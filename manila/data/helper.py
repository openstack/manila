# Copyright (c) 2015 Hitachi Data Systems.
# All Rights Reserved.
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
"""Helper class for Data Service operations."""

import os

from oslo_config import cfg
from oslo_log import log

from manila.common import constants
from manila import exception
from manila.i18n import _, _LW
from manila.share import rpcapi as share_rpc
from manila import utils

LOG = log.getLogger(__name__)

data_helper_opts = [
    cfg.IntOpt(
        'data_access_wait_access_rules_timeout',
        default=180,
        help="Time to wait for access rules to be allowed/denied on backends "
             "when migrating a share (seconds)."),
    cfg.StrOpt(
        'data_node_access_ip',
        default=None,
        help="The IP of the node interface connected to the admin network. "
             "Used for allowing access to the mounting shares."),
    cfg.StrOpt(
        'data_node_access_cert',
        default=None,
        help="The certificate installed in the data node in order to "
             "allow access to certificate authentication-based shares."),

]

CONF = cfg.CONF
CONF.register_opts(data_helper_opts)


class DataServiceHelper(object):

    def __init__(self, context, db, share):

        self.db = db
        self.share = share
        self.context = context
        self.share_rpc = share_rpc.ShareAPI()
        self.wait_access_rules_timeout = (
            CONF.data_access_wait_access_rules_timeout)

    def _allow_data_access(self, access, share_instance_id,
                           dest_share_instance_id=None):

        values = {
            'share_id': self.share['id'],
            'access_type': access['access_type'],
            'access_level': access['access_level'],
            'access_to': access['access_to']
        }

        share_access_list = self.db.share_access_get_all_by_type_and_access(
            self.context, self.share['id'], access['access_type'],
            access['access_to'])

        for access in share_access_list:
            self._change_data_access_to_instance(
                share_instance_id, access, allow=False)

        access_ref = self.db.share_access_create(self.context, values)

        self._change_data_access_to_instance(
            share_instance_id, access_ref, allow=True)
        if dest_share_instance_id:
            self._change_data_access_to_instance(
                dest_share_instance_id, access_ref, allow=True)

        return access_ref

    def deny_access_to_data_service(self, access_ref, share_instance_id):

        self._change_data_access_to_instance(
            share_instance_id, access_ref, allow=False)

    # NOTE(ganso): Cleanup methods do not throw exceptions, since the
    # exceptions that should be thrown are the ones that call the cleanup

    def cleanup_data_access(self, access_ref, share_instance_id):

        try:
            self.deny_access_to_data_service(access_ref, share_instance_id)
        except Exception:
            LOG.warning(_LW("Could not cleanup access rule of share %s."),
                        self.share['id'])

    def cleanup_temp_folder(self, instance_id, mount_path):

        try:
            path = os.path.join(mount_path, instance_id)
            if os.path.exists(path):
                os.rmdir(path)
            self._check_dir_not_exists(path)
        except Exception:
            LOG.warning(_LW("Could not cleanup instance %(instance_id)s "
                            "temporary folders for data copy of "
                            "share %(share_id)s."), {
                                'instance_id': instance_id,
                                'share_id': self.share['id']})

    def cleanup_unmount_temp_folder(self, unmount_template, mount_path,
                                    share_instance_id):

        try:
            self.unmount_share_instance(unmount_template, mount_path,
                                        share_instance_id)
        except Exception:
            LOG.warning(_LW("Could not unmount folder of instance"
                            " %(instance_id)s for data copy of "
                            "share %(share_id)s."), {
                                'instance_id': share_instance_id,
                                'share_id': self.share['id']})

    def _change_data_access_to_instance(
            self, instance_id, access_ref, allow=False):

        self.db.share_instance_update_access_status(
            self.context, instance_id, constants.STATUS_OUT_OF_SYNC)

        instance = self.db.share_instance_get(
            self.context, instance_id, with_share_data=True)

        if allow:
            self.share_rpc.allow_access(self.context, instance, access_ref)
        else:
            self.share_rpc.deny_access(self.context, instance, access_ref)

        utils.wait_for_access_update(
            self.context, self.db, instance, self.wait_access_rules_timeout)

    def allow_access_to_data_service(self, share, share_instance_id,
                                     dest_share_instance_id):

        if share['share_proto'].upper() == 'GLUSTERFS':

            access_to = CONF.data_node_access_cert
            access_type = 'cert'

            if not access_to:
                msg = _("Data Node Certificate not specified. Cannot mount "
                        "instances for data copy of share %(share_id)s. "
                        "Aborting.") % {'share_id': share['id']}
                raise exception.ShareDataCopyFailed(reason=msg)

        else:

            access_to = CONF.data_node_access_ip
            access_type = 'ip'

            if not access_to:
                msg = _("Data Node Admin Network IP not specified. Cannot "
                        "mount instances for data copy of share %(share_id)s. "
                        "Aborting.") % {'share_id': share['id']}
                raise exception.ShareDataCopyFailed(reason=msg)

        access = {'access_type': access_type,
                  'access_level': constants.ACCESS_LEVEL_RW,
                  'access_to': access_to}

        access_ref = self._allow_data_access(access, share_instance_id,
                                             dest_share_instance_id)

        return access_ref

    @utils.retry(exception.NotFound, 0.1, 10, 0.1)
    def _check_dir_exists(self, path):
        if not os.path.exists(path):
            raise exception.NotFound("Folder %s could not be found." % path)

    @utils.retry(exception.Found, 0.1, 10, 0.1)
    def _check_dir_not_exists(self, path):
        if os.path.exists(path):
            raise exception.Found("Folder %s was found." % path)

    def mount_share_instance(self, mount_template, mount_path,
                             share_instance_id):

        path = os.path.join(mount_path, share_instance_id)

        if not os.path.exists(path):
            os.makedirs(path)
        self._check_dir_exists(path)

        mount_command = mount_template % {'path': path}

        utils.execute(*(mount_command.split()), run_as_root=True)

    def unmount_share_instance(self, unmount_template, mount_path,
                               share_instance_id):

        path = os.path.join(mount_path, share_instance_id)

        unmount_command = unmount_template % {'path': path}

        utils.execute(*(unmount_command.split()), run_as_root=True)

        try:
            if os.path.exists(path):
                os.rmdir(path)
            self._check_dir_not_exists(path)
        except Exception:
            LOG.warning(_LW("Folder %s could not be removed."), path)
