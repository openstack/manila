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
from manila.i18n import _
from manila.share import access as access_manager
from manila.share import rpcapi as share_rpc
from manila import utils

LOG = log.getLogger(__name__)

data_helper_opts = [
    cfg.IntOpt(
        'data_access_wait_access_rules_timeout',
        default=180,
        help="Time to wait for access rules to be allowed/denied on backends "
             "when migrating a share (seconds)."),
    cfg.ListOpt('data_node_access_ips',
                default=[],
                help="A list of the IPs of the node interface connected to "
                     "the admin network. Used for allowing access to the "
                     "mounting shares. Default is []."),
    cfg.StrOpt(
        'data_node_access_ip',
        help="The IP of the node interface connected to the admin network. "
             "Used for allowing access to the mounting shares.",
        deprecated_for_removal=True,
        deprecated_reason="New config option 'data_node_access_ips' added "
                          "to support multiple IPs, including IPv6 addresses "
                          "alongside IPv4."),
    cfg.StrOpt(
        'data_node_access_cert',
        help="The certificate installed in the data node in order to "
             "allow access to certificate authentication-based shares."),
    cfg.StrOpt(
        'data_node_access_admin_user',
        help="The admin user name registered in the security service in order "
             "to allow access to user authentication-based shares."),
    cfg.DictOpt(
        'data_node_mount_options',
        default={},
        help="Mount options to be included in the mount command for share "
             "protocols. Use dictionary format, example: "
             "{'nfs': '-o nfsvers=3', 'cifs': '-o user=foo,pass=bar'}"),

]

CONF = cfg.CONF
CONF.register_opts(data_helper_opts)


class DataServiceHelper(object):

    def __init__(self, context, db, share):

        self.db = db
        self.share = share
        self.context = context
        self.share_rpc = share_rpc.ShareAPI()
        self.access_helper = access_manager.ShareInstanceAccess(self.db, None)
        self.wait_access_rules_timeout = (
            CONF.data_access_wait_access_rules_timeout)

    def deny_access_to_data_service(self, access_ref_list, share_instance):
        self._change_data_access_to_instance(
            share_instance, access_ref_list, deny=True)

    # NOTE(ganso): Cleanup methods do not throw exceptions, since the
    # exceptions that should be thrown are the ones that call the cleanup

    def cleanup_data_access(self, access_ref_list, share_instance_id):

        try:
            self.deny_access_to_data_service(
                access_ref_list, share_instance_id)
        except Exception:
            LOG.warning("Could not cleanup access rule of share %s.",
                        self.share['id'])

    def cleanup_temp_folder(self, instance_id, mount_path):

        try:
            path = os.path.join(mount_path, instance_id)
            if os.path.exists(path):
                os.rmdir(path)
            self._check_dir_not_exists(path)
        except Exception:
            LOG.warning("Could not cleanup instance %(instance_id)s "
                        "temporary folders for data copy of "
                        "share %(share_id)s.", {
                            'instance_id': instance_id,
                            'share_id': self.share['id']})

    def cleanup_unmount_temp_folder(self, unmount_template, mount_path,
                                    share_instance_id):

        try:
            self.unmount_share_instance(unmount_template, mount_path,
                                        share_instance_id)
        except Exception:
            LOG.warning("Could not unmount folder of instance"
                        " %(instance_id)s for data copy of "
                        "share %(share_id)s.", {
                            'instance_id': share_instance_id,
                            'share_id': self.share['id']})

    def _change_data_access_to_instance(
            self, instance, accesses=None, deny=False):

        self.access_helper.get_and_update_share_instance_access_rules_status(
            self.context, status=constants.SHARE_INSTANCE_RULES_SYNCING,
            share_instance_id=instance['id'])

        if deny:
            if accesses is None:
                accesses = []
            else:
                if not isinstance(accesses, list):
                    accesses = [accesses]

            access_filters = {'access_id': [a['id'] for a in accesses]}
            updates = {'state': constants.ACCESS_STATE_QUEUED_TO_DENY}
            self.access_helper.get_and_update_share_instance_access_rules(
                self.context, filters=access_filters, updates=updates,
                share_instance_id=instance['id'])

        self.share_rpc.update_access(self.context, instance)

        utils.wait_for_access_update(
            self.context, self.db, instance, self.wait_access_rules_timeout)

    def allow_access_to_data_service(
            self, share_instance, connection_info_src,
            dest_share_instance=None, connection_info_dest=None):

        allow_access_to_destination_instance = (dest_share_instance and
                                                connection_info_dest)

        # NOTE(ganso): intersect the access type compatible with both instances
        if allow_access_to_destination_instance:
            access_mapping = {}
            for a_type, protocols in (
                    connection_info_src['access_mapping'].items()):
                for proto in protocols:
                    if (a_type in connection_info_dest['access_mapping'] and
                            proto in
                            connection_info_dest['access_mapping'][a_type]):
                        access_mapping[a_type] = access_mapping.get(a_type, [])
                        access_mapping[a_type].append(proto)
        else:
            access_mapping = connection_info_src['access_mapping']

        access_list = self._get_access_entries_according_to_mapping(
            access_mapping)
        access_ref_list = []

        for access in access_list:

            values = {
                'share_id': self.share['id'],
                'access_type': access['access_type'],
                'access_level': access['access_level'],
                'access_to': access['access_to'],
            }

            # Check if the rule being added already exists. If so, we will
            # remove it to prevent conflicts
            old_access_list = self.db.share_access_get_all_by_type_and_access(
                self.context, self.share['id'], access['access_type'],
                access['access_to'])
            if old_access_list:
                self._change_data_access_to_instance(
                    share_instance, old_access_list, deny=True)

            access_ref = self.db.share_instance_access_create(
                self.context, values, share_instance['id'])
            self._change_data_access_to_instance(share_instance)

            if allow_access_to_destination_instance:
                access_ref = self.db.share_instance_access_create(
                    self.context, values, dest_share_instance['id'])
                self._change_data_access_to_instance(dest_share_instance)

            # The access rule ref used here is a regular Share Access Map,
            # instead of a Share Instance Access Map.
            access_ref_list.append(access_ref)

        return access_ref_list

    def _get_access_entries_according_to_mapping(self, access_mapping):

        access_list = []

        # NOTE(ganso): protocol is not relevant here because we previously
        # used it to filter the access types we are interested in
        for access_type, protocols in access_mapping.items():
            access_to_list = []
            if access_type.lower() == 'cert' and CONF.data_node_access_cert:
                access_to_list.append(CONF.data_node_access_cert)
            elif access_type.lower() == 'ip':
                ips = CONF.data_node_access_ips or CONF.data_node_access_ip
                if ips:
                    if not isinstance(ips, list):
                        ips = [ips]
                    access_to_list.extend(ips)
            elif (access_type.lower() == 'user' and
                    CONF.data_node_access_admin_user):
                access_to_list.append(CONF.data_node_access_admin_user)
            else:
                msg = _("Unsupported access type provided: %s.") % access_type
                raise exception.ShareDataCopyFailed(reason=msg)
            if not access_to_list:
                msg = _("Configuration for Data node mounting access type %s "
                        "has not been set.") % access_type
                raise exception.ShareDataCopyFailed(reason=msg)

            for access_to in access_to_list:
                access = {
                    'access_type': access_type,
                    'access_level': constants.ACCESS_LEVEL_RW,
                    'access_to': access_to,
                }
                access_list.append(access)

        return access_list

    @utils.retry(exception.NotFound, 0.1, 10, 0.1)
    def _check_dir_exists(self, path):
        if not os.path.exists(path):
            raise exception.NotFound("Folder %s could not be found." % path)

    @utils.retry(exception.Found, 0.1, 10, 0.1)
    def _check_dir_not_exists(self, path):
        if os.path.exists(path):
            raise exception.Found("Folder %s was found." % path)

    def mount_share_instance(self, mount_template, mount_path,
                             share_instance):

        path = os.path.join(mount_path, share_instance['id'])

        options = CONF.data_node_mount_options
        options = {k.lower(): v for k, v in options.items()}
        proto_options = options.get(share_instance['share_proto'].lower())

        if not proto_options:
            proto_options = ''

        if not os.path.exists(path):
            os.makedirs(path)
        self._check_dir_exists(path)

        mount_command = mount_template % {'path': path,
                                          'options': proto_options}

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
            LOG.warning("Folder %s could not be removed.", path)
