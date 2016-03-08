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
NetApp Data ONTAP cDOT single-SVM storage driver library.

This library extends the abstract base library and completes the single-SVM
functionality needed by the cDOT single-SVM Manila driver.  This library
variant uses a single Data ONTAP storage virtual machine (i.e. 'vserver')
as defined in manila.conf to provision shares.
"""

import re

from oslo_log import log

from manila import exception
from manila.i18n import _, _LI
from manila.share.drivers.netapp.dataontap.cluster_mode import lib_base
from manila.share.drivers.netapp import utils as na_utils


LOG = log.getLogger(__name__)


class NetAppCmodeSingleSVMFileStorageLibrary(
        lib_base.NetAppCmodeFileStorageLibrary):

    def __init__(self, driver_name, **kwargs):
        super(NetAppCmodeSingleSVMFileStorageLibrary, self).__init__(
            driver_name, **kwargs)

        self._vserver = self.configuration.netapp_vserver

    @na_utils.trace
    def check_for_setup_error(self):

        # Ensure vserver is specified in configuration.
        if not self._vserver:
            msg = _('Vserver must be specified in the configuration '
                    'when the driver is not managing share servers.')
            raise exception.InvalidInput(reason=msg)

        # Ensure vserver exists.
        if not self._client.vserver_exists(self._vserver):
            raise exception.VserverNotFound(vserver=self._vserver)

        # If we have vserver credentials, ensure the vserver they connect
        # to matches the vserver specified in the configuration.
        if not self._have_cluster_creds:
            if self._vserver not in self._client.list_vservers():
                msg = _('Vserver specified in the configuration does not '
                        'match supplied credentials.')
                raise exception.InvalidInput(reason=msg)

        # Ensure one or more aggregates are available to the vserver.
        if not self._find_matching_aggregates():
            msg = _('No aggregates are available to Vserver %s for '
                    'provisioning shares. Ensure that one or more aggregates '
                    'are assigned to the Vserver and that the configuration '
                    'option netapp_aggregate_name_search_pattern is set '
                    'correctly.') % self._vserver
            raise exception.NetAppException(msg)

        msg = _LI('Using Vserver %(vserver)s for backend %(backend)s with '
                  '%(creds)s credentials.')
        msg_args = {'vserver': self._vserver, 'backend': self._backend_name}
        msg_args['creds'] = ('cluster' if self._have_cluster_creds
                             else 'Vserver')
        LOG.info(msg % msg_args)

        super(NetAppCmodeSingleSVMFileStorageLibrary, self).\
            check_for_setup_error()

    @na_utils.trace
    def _get_vserver(self, share_server=None):

        if share_server is not None:
            msg = _('Share server must not be passed to the driver '
                    'when the driver is not managing share servers.')
            raise exception.InvalidParameterValue(err=msg)

        if not self._vserver:
            msg = _('Vserver not specified in configuration.')
            raise exception.InvalidInput(reason=msg)

        if not self._client.vserver_exists(self._vserver):
            raise exception.VserverNotFound(vserver=self._vserver)

        vserver_client = self._get_api_client(self._vserver)
        return self._vserver, vserver_client

    @na_utils.trace
    def _handle_housekeeping_tasks(self):
        """Handle various cleanup activities."""
        vserver_client = self._get_api_client(vserver=self._vserver)
        vserver_client.prune_deleted_nfs_export_policies()
        vserver_client.prune_deleted_snapshots()

        super(NetAppCmodeSingleSVMFileStorageLibrary, self).\
            _handle_housekeeping_tasks()

    @na_utils.trace
    def _find_matching_aggregates(self):
        """Find all aggregates match pattern."""
        vserver_client = self._get_api_client(vserver=self._vserver)
        aggregate_names = vserver_client.list_vserver_aggregates()
        pattern = self.configuration.netapp_aggregate_name_search_pattern
        return [aggr_name for aggr_name in aggregate_names
                if re.match(pattern, aggr_name)]

    @na_utils.trace
    def get_network_allocations_number(self):
        """Get number of network interfaces to be created."""
        return 0

    @na_utils.trace
    def get_admin_network_allocations_number(self):
        """Get number of network allocations for creating admin LIFs."""
        return 0
