# Copyright (c) 2015 Clinton Knight.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
NetApp CIFS protocol helper class.
"""

import re

from oslo_log import log

from manila.common import constants
from manila import exception
from manila.i18n import _, _LE
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.protocols import base
from manila.share.drivers.netapp import utils as na_utils


LOG = log.getLogger(__name__)


class NetAppCmodeCIFSHelper(base.NetAppBaseHelper):
    """Netapp specific cluster-mode CIFS sharing driver."""

    @na_utils.trace
    def create_share(self, share, share_name, export_addresses):
        """Creates CIFS share on Data ONTAP Vserver."""
        self._client.create_cifs_share(share_name)
        self._client.remove_cifs_share_access(share_name, 'Everyone')
        return [r'\\%s\%s' % (export_address, share_name)
                for export_address in export_addresses]

    @na_utils.trace
    def delete_share(self, share, share_name):
        """Deletes CIFS share on Data ONTAP Vserver."""
        host_ip, share_name = self._get_export_location(share)
        self._client.remove_cifs_share(share_name)

    @na_utils.trace
    def allow_access(self, context, share, share_name, access):
        """Allows access to the CIFS share for a given user."""
        if access['access_type'] != 'user':
            msg = _("Cluster Mode supports only 'user' type for share access"
                    " rules with CIFS protocol.")
            raise exception.InvalidShareAccess(reason=msg)

        user_name = access['access_to']

        if access['access_level'] == constants.ACCESS_LEVEL_RW:
            readonly = False
        elif access['access_level'] == constants.ACCESS_LEVEL_RO:
            readonly = True
        else:
            raise exception.InvalidShareAccessLevel(
                level=access['access_level'])

        target, share_name = self._get_export_location(share)
        try:
            self._client.add_cifs_share_access(share_name,
                                               user_name,
                                               readonly)
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EDUPLICATEENTRY:
                # Duplicate entry, so use specific exception.
                raise exception.ShareAccessExists(
                    access_type=access['access_type'], access=access)
            raise e

    @na_utils.trace
    def deny_access(self, context, share, share_name, access):
        """Denies access to the CIFS share for a given user."""
        host_ip, share_name = self._get_export_location(share)
        user_name = access['access_to']
        try:
            self._client.remove_cifs_share_access(share_name, user_name)
        except netapp_api.NaApiError as e:
            if e.code == netapp_api.EONTAPI_EINVAL:
                LOG.error(_LE("User %s does not exist."), user_name)
            elif e.code == netapp_api.EOBJECTNOTFOUND:
                LOG.error(_LE("Rule %s does not exist."), user_name)
            else:
                raise e

    @na_utils.trace
    def get_target(self, share):
        """Returns OnTap target IP based on share export location."""
        return self._get_export_location(share)[0]

    @na_utils.trace
    def get_share_name_for_share(self, share):
        """Returns the flexvol name that hosts a share."""
        _, share_name = self._get_export_location(share)
        return share_name

    @staticmethod
    def _get_export_location(share):
        """Returns host ip and share name for a given CIFS share."""
        export_location = share['export_location'] or '\\\\\\'
        regex = r'^(?:\\\\|//)(?P<host_ip>.*)(?:\\|/)(?P<share_name>.*)$'
        match = re.match(regex, export_location)
        if match:
            return match.group('host_ip'), match.group('share_name')
        else:
            return '', ''
