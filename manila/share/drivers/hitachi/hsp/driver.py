# Copyright (c) 2016 Hitachi Data Systems, Inc.
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

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import units

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share.drivers.hitachi.hsp import rest

LOG = log.getLogger(__name__)

hitachi_hsp_opts = [
    cfg.HostAddressOpt('hitachi_hsp_host',
                       required=True,
                       help="HSP management host for communication between "
                            "Manila controller and HSP."),
    cfg.StrOpt('hitachi_hsp_username',
               required=True,
               help="HSP username to perform tasks such as create filesystems"
                    " and shares."),
    cfg.StrOpt('hitachi_hsp_password',
               required=True,
               secret=True,
               help="HSP password for the username provided."),
]


class HitachiHSPDriver(driver.ShareDriver):
    """Manila HSP Driver implementation.

    1.0.0 - Initial Version.
    """

    def __init__(self, *args, **kwargs):
        super(self.__class__, self).__init__(
            [False], *args, config_opts=[hitachi_hsp_opts], **kwargs)

        self.private_storage = kwargs.get('private_storage')

        self.backend_name = self.configuration.safe_get('share_backend_name')
        self.hsp_host = self.configuration.safe_get('hitachi_hsp_host')

        self.hsp = rest.HSPRestBackend(
            self.hsp_host,
            self.configuration.safe_get('hitachi_hsp_username'),
            self.configuration.safe_get('hitachi_hsp_password')
        )

    def _update_share_stats(self, data=None):
        LOG.debug("Updating Backend Capability Information - Hitachi HSP.")

        reserved = self.configuration.safe_get('reserved_share_percentage')
        max_over_subscription_ratio = self.configuration.safe_get(
            'max_over_subscription_ratio')
        hsp_cluster = self.hsp.get_cluster()

        total_space = hsp_cluster['properties']['total-storage-capacity']
        free_space = hsp_cluster['properties']['total-storage-available']

        data = {
            'share_backend_name': self.backend_name,
            'vendor_name': 'Hitachi',
            'driver_version': '1.0.0',
            'storage_protocol': 'NFS',
            'pools': [{
                'reserved_percentage': reserved,
                'pool_name': 'HSP',
                'thin_provisioning': True,
                'total_capacity_gb': total_space / units.Gi,
                'free_capacity_gb': free_space / units.Gi,
                'max_over_subscription_ratio': max_over_subscription_ratio,
                'qos': False,
                'dedupe': False,
                'compression': False,
            }],
        }

        LOG.info("Hitachi HSP Capabilities: %(data)s.",
                 {'data': data})
        super(HitachiHSPDriver, self)._update_share_stats(data)

    def create_share(self, context, share, share_server=None):
        LOG.debug("Creating share in HSP: %(shr)s", {'shr': share['id']})

        if share['share_proto'].lower() != 'nfs':
            msg = _("Only NFS protocol is currently supported.")
            raise exception.InvalidShare(reason=msg)

        self.hsp.add_file_system(share['id'], share['size'] * units.Gi)
        filesystem_id = self.hsp.get_file_system(share['id'])['id']

        try:
            self.hsp.add_share(share['id'], filesystem_id)
        except exception.HSPBackendException:
            with excutils.save_and_reraise_exception():
                self.hsp.delete_file_system(filesystem_id)
                msg = ("Could not create share %s on HSP.")
                LOG.exception(msg, share['id'])

        uri = self.hsp_host + ':/' + share['id']

        LOG.debug("Share created successfully on path: %(uri)s.",
                  {'uri': uri})
        return [{
            "path": uri,
            "metadata": {},
            "is_admin_only": False,
        }]

    def delete_share(self, context, share, share_server=None):
        LOG.debug("Deleting share in HSP: %(shr)s.", {'shr': share['id']})

        filesystem_id = hsp_share_id = None

        try:
            filesystem_id = self.hsp.get_file_system(share['id'])['id']
            hsp_share_id = self.hsp.get_share(filesystem_id)['id']
        except exception.HSPItemNotFoundException:
            LOG.info("Share %(shr)s already removed from backend.",
                     {'shr': share['id']})

        if hsp_share_id:
            # Clean all rules from share before deleting it
            current_rules = self.hsp.get_access_rules(hsp_share_id)
            for rule in current_rules:
                try:
                    self.hsp.delete_access_rule(hsp_share_id,
                                                rule['name'])
                except exception.HSPBackendException as e:
                    if 'No matching access rule found.' in e.msg:
                        LOG.debug("Rule %(rule)s already deleted in "
                                  "backend.", {'rule': rule['name']})
                    else:
                        raise

            self.hsp.delete_share(hsp_share_id)

        if filesystem_id:
            self.hsp.delete_file_system(filesystem_id)

        LOG.debug("Export and share successfully deleted: %(shr)s.",
                  {'shr': share['id']})

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):

        LOG.debug("Updating access rules for share: %(shr)s.",
                  {'shr': share['id']})

        try:
            filesystem_id = self.hsp.get_file_system(share['id'])['id']
            hsp_share_id = self.hsp.get_share(filesystem_id)['id']
        except exception.HSPItemNotFoundException:
            raise exception.ShareResourceNotFound(share_id=share['id'])

        if not (add_rules or delete_rules):
            # Recovery mode
            current_rules = self.hsp.get_access_rules(hsp_share_id)

            # Indexing the rules for faster searching
            hsp_rules_dict = {
                rule['host-specification']: rule['read-write']
                for rule in current_rules
            }

            manila_rules_dict = {}

            for rule in access_rules:
                if rule['access_type'].lower() != 'ip':
                    msg = _("Only IP access type currently supported.")
                    raise exception.InvalidShareAccess(reason=msg)

                access_to = rule['access_to']
                is_rw = rule['access_level'] == constants.ACCESS_LEVEL_RW
                manila_rules_dict[access_to] = is_rw

            # Remove the rules that exist on HSP but not on manila
            remove_rules = self._get_complement(hsp_rules_dict,
                                                manila_rules_dict)

            # Add the rules that exist on manila but not on HSP
            add_rules = self._get_complement(manila_rules_dict, hsp_rules_dict)

            for rule in remove_rules:
                rule_name = self._get_hsp_rule_name(hsp_share_id, rule[0])
                self.hsp.delete_access_rule(hsp_share_id, rule_name)

            for rule in add_rules:
                self.hsp.add_access_rule(hsp_share_id, rule[0], rule[1])
        else:
            for rule in delete_rules:
                if rule['access_type'].lower() != 'ip':
                    continue

                # get the real rule name in HSP
                rule_name = self._get_hsp_rule_name(hsp_share_id,
                                                    rule['access_to'])
                try:
                    self.hsp.delete_access_rule(hsp_share_id,
                                                rule_name)
                except exception.HSPBackendException as e:
                    if 'No matching access rule found.' in e.msg:
                        LOG.debug("Rule %(rule)s already deleted in "
                                  "backend.", {'rule': rule['access_to']})
                    else:
                        raise

            for rule in add_rules:
                if rule['access_type'].lower() != 'ip':
                    msg = _("Only IP access type currently supported.")
                    raise exception.InvalidShareAccess(reason=msg)

                try:
                    self.hsp.add_access_rule(
                        hsp_share_id, rule['access_to'],
                        (rule['access_level'] == constants.ACCESS_LEVEL_RW))
                except exception.HSPBackendException as e:
                    if 'Duplicate NFS access rule exists' in e.msg:
                        LOG.debug("Rule %(rule)s already exists in "
                                  "backend.", {'rule': rule['access_to']})
                    else:
                        raise

        LOG.debug("Successfully updated share %(shr)s rules.",
                  {'shr': share['id']})

    def _get_hsp_rule_name(self, share_id, host_to):
        rule_name = share_id + host_to
        all_rules = self.hsp.get_access_rules(share_id)
        for rule in all_rules:
            # check if this rule has other name in HSP
            if rule['host-specification'] == host_to:
                rule_name = rule['name']
                break

        return rule_name

    def _get_complement(self, rules_a, rules_b):
        """Returns the rules of list A that are not on list B"""
        complement = []
        for rule, is_rw in rules_a.items():
            if rule not in rules_b or rules_b[rule] != is_rw:
                complement.append((rule, is_rw))

        return complement

    def extend_share(self, share, new_size, share_server=None):
        LOG.debug("Extending share in HSP: %(shr_id)s.",
                  {'shr_id': share['id']})

        old_size = share['size']
        hsp_cluster = self.hsp.get_cluster()
        free_space = hsp_cluster['properties']['total-storage-available']
        free_space = free_space / units.Gi

        if (new_size - old_size) < free_space:
            filesystem_id = self.hsp.get_file_system(share['id'])['id']
            self.hsp.resize_file_system(filesystem_id, new_size * units.Gi)
        else:
            msg = (_("Share %s cannot be extended due to insufficient space.")
                   % share['id'])
            raise exception.HSPBackendException(msg=msg)

        LOG.info("Share %(shr_id)s successfully extended to "
                 "%(shr_size)sG.",
                 {'shr_id': share['id'],
                  'shr_size': new_size})

    def shrink_share(self, share, new_size, share_server=None):
        LOG.debug("Shrinking share in HSP: %(shr_id)s.",
                  {'shr_id': share['id']})

        file_system = self.hsp.get_file_system(share['id'])
        usage = file_system['properties']['used-capacity'] / units.Gi

        LOG.debug("Usage for share %(shr_id)s in HSP: %(usage)sG.",
                  {'shr_id': share['id'], 'usage': usage})

        if new_size > usage:
            self.hsp.resize_file_system(file_system['id'], new_size * units.Gi)
        else:
            raise exception.ShareShrinkingPossibleDataLoss(
                share_id=share['id'])

        LOG.info("Share %(shr_id)s successfully shrunk to "
                 "%(shr_size)sG.",
                 {'shr_id': share['id'],
                  'shr_size': new_size})

    def manage_existing(self, share, driver_options):
        LOG.debug("Managing share in HSP: %(shr_id)s.",
                  {'shr_id': share['id']})

        ip, share_name = share['export_locations'][0]['path'].split(':')

        try:
            hsp_share = self.hsp.get_share(name=share_name.strip('/'))
        except exception.HSPItemNotFoundException:
            msg = _("The share %s trying to be managed was not found on "
                    "backend.") % share['id']
            raise exception.ManageInvalidShare(reason=msg)

        self.hsp.rename_file_system(hsp_share['properties']['file-system-id'],
                                    share['id'])

        original_name = hsp_share['properties']['file-system-name']
        private_storage_content = {
            'old_name': original_name,
            'new_name': share['id'],
        }
        self.private_storage.update(share['id'], private_storage_content)

        LOG.debug("Filesystem %(original_name)s was renamed to %(name)s.",
                  {'original_name': original_name,
                   'name': share['id']})

        file_system = self.hsp.get_file_system(share['id'])

        LOG.info("Share %(shr_path)s was successfully managed with ID "
                 "%(shr_id)s.",
                 {'shr_path': share['export_locations'][0]['path'],
                  'shr_id': share['id']})

        export_locations = [{
            "path": share['export_locations'][0]['path'],
            "metadata": {},
            "is_admin_only": False,
        }]

        return {'size': file_system['properties']['quota'] / units.Gi,
                'export_locations': export_locations}

    def unmanage(self, share):
        original_name = self.private_storage.get(share['id'], 'old_name')

        LOG.debug("Filesystem %(name)s that was originally named "
                  "%(original_name)s will no longer be managed.",
                  {'original_name': original_name,
                   'name': share['id']})

        self.private_storage.delete(share['id'])

        LOG.info("The share with current path %(shr_path)s and ID "
                 "%(shr_id)s is no longer being managed.",
                 {'shr_path': share['export_locations'][0]['path'],
                  'shr_id': share['id']})

    def get_default_filter_function(self):
        return "share.size >= 128"
