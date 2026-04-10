# Copyright (c) 2026 Dell Inc. or its subsidiaries.
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

"""
PowerStore specific NAS backend plugin.
"""
import math

from oslo_config import cfg
from oslo_log import log
from oslo_utils import units

from manila.common import constants as const
from manila import coordination
from manila import exception
from manila.i18n import _
from manila.share.drivers.dell_emc.plugins import base as driver
from manila.share.drivers.dell_emc.plugins.powerstore import client
from manila.share import qos_types

"""Version history:
    1.0 - Initial version
    1.1 - Add support for manage/unmanage share
    1.2 - Add support for manage/unmanage snapshot
    2.0 - Added QoS support
"""
VERSION = "2.0"

CONF = cfg.CONF

LOG = log.getLogger(__name__)

QOS_RULE_NAME_PREFIX = "manila_qos_rule"
QOS_POLICY_NAME_PREFIX = "manila_qos_policy"
QOS_MAX_BW_MIN = 1
QOS_MAX_BW_MAX = 1000000

POWERSTORE_OPTS = [
    cfg.StrOpt('dell_nas_backend_host',
               help='Dell NAS backend hostname or IP address.'),
    cfg.StrOpt('dell_nas_server',
               help='Root directory or NAS server which owns the shares.'),
    cfg.StrOpt('dell_ad_domain',
               help='Domain name of the active directory '
               'joined by the NAS server.'),
    cfg.StrOpt('dell_nas_login',
               help='User name for the Dell NAS backend.'),
    cfg.StrOpt('dell_nas_password',
               secret=True,
               help='Password for the Dell NAS backend.'),
    cfg.BoolOpt('dell_ssl_cert_verify',
                default=False,
                help='If set to False the https client will not validate the '
                     'SSL certificate of the backend endpoint.'),
    cfg.StrOpt('dell_ssl_cert_path',
               help='Can be used to specify a non default path to a '
                    'CA_BUNDLE file or directory with certificates of trusted '
                    'CAs, which will be used to validate the backend.')
]


class PowerStoreStorageConnection(driver.StorageConnection):
    """Implements PowerStore specific functionality for Dell Manila driver."""

    def __init__(self, *args, **kwargs):
        """Do initialization"""

        LOG.debug('Invoking base constructor for Manila'
                  ' Dell PowerStore Driver.')
        super(PowerStoreStorageConnection,
              self).__init__(*args, **kwargs)

        LOG.debug('Setting up attributes for Manila'
                  ' Dell PowerStore Driver.')
        if 'configuration' in kwargs:
            kwargs['configuration'].append_config_values(POWERSTORE_OPTS)

        self.client = None
        self.verify_certificate = None
        self.certificate_path = None
        self.ipv6_implemented = True
        self.revert_to_snap_support = True
        self.shrink_share_support = True
        self.manage_existing_support = True
        self.manage_existing_snapshot_support = True
        self.qos_type_support = True

        # props from super class
        self.driver_handles_share_servers = False
        # props for share status update
        self.reserved_percentage = None
        self.reserved_snapshot_percentage = None
        self.reserved_share_extend_percentage = None
        self.max_over_subscription_ratio = None

    def connect(self, dell_share_driver, context):
        """Connects to Dell PowerStore"""
        LOG.debug('Reading configuration parameters for Manila'
                  ' Dell PowerStore Driver.')
        config = dell_share_driver.configuration
        get_config_value = config.safe_get
        self.rest_ip = get_config_value("dell_nas_backend_host")
        self.rest_username = get_config_value("dell_nas_login")
        self.rest_password = get_config_value("dell_nas_password")
        # validate IP, username and password
        if not all([self.rest_ip,
                    self.rest_username,
                    self.rest_password]):
            message = _("REST server IP, username and password"
                        " must be specified.")
            raise exception.BadConfigurationException(reason=message)
        self.nas_server = get_config_value("dell_nas_server")
        self.ad_domain = get_config_value("dell_ad_domain")
        self.verify_certificate = (get_config_value("dell_ssl_cert_verify") or
                                   False)
        if self.verify_certificate:
            self.certificate_path = get_config_value(
                "dell_ssl_cert_path")

        LOG.debug('Initializing Dell PowerStore REST Client.')
        LOG.info("REST server IP: %(ip)s, username: %(user)s. "
                 "Verify server's certificate: %(verify_cert)s.",
                 {
                     "ip": self.rest_ip,
                     "user": self.rest_username,
                     "verify_cert": self.verify_certificate,
                 })

        self.client = client.PowerStoreClient(self.rest_ip,
                                              self.rest_username,
                                              self.rest_password,
                                              self.verify_certificate,
                                              self.certificate_path)

        # configuration for share status update
        self.reserved_percentage = config.safe_get(
            'reserved_share_percentage')
        if self.reserved_percentage is None:
            self.reserved_percentage = 0

        self.reserved_snapshot_percentage = config.safe_get(
            'reserved_share_from_snapshot_percentage')
        if self.reserved_snapshot_percentage is None:
            self.reserved_snapshot_percentage = self.reserved_percentage

        self.reserved_share_extend_percentage = config.safe_get(
            'reserved_share_extend_percentage')
        if self.reserved_share_extend_percentage is None:
            self.reserved_share_extend_percentage = self.reserved_percentage

        self.max_over_subscription_ratio = config.safe_get(
            'max_over_subscription_ratio')

    def create_share(self, context, share, share_server):
        """Is called to create a share."""
        LOG.debug(f'Creating {share["share_proto"]} share.')
        locations = self._create_share(share)
        return locations

    def _create_share(self, share):
        """Creates a NFS or SMB share.

        In PowerStore, an export (share) belongs to a filesystem.
        This function creates a filesystem and an export.
        If the share has a QoS type, a QoS policy is applied to the
        filesystem.
        """
        share_name = share['name']
        size_in_bytes = share['size'] * units.Gi
        # create a filesystem
        nas_server_id = self.client.get_nas_server_id(self.nas_server)
        LOG.debug(f"Creating filesystem {share_name}")
        filesystem_id = self.client.create_filesystem(nas_server_id,
                                                      share_name,
                                                      size_in_bytes)
        if not filesystem_id:
            message = (
                _('The filesystem "%(export)s" was not created.') %
                {'export': share_name})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        # apply QoS policy if defined
        try:
            self._apply_qos_to_filesystem(share, filesystem_id)
        except Exception:
            LOG.error("Failed to apply QoS policy to filesystem "
                      "for share '%s'. Cleaning up filesystem.",
                      share_name)
            self.client.delete_filesystem(filesystem_id)
            raise
        # create a share
        locations = self._create_share_NFS_CIFS(nas_server_id, filesystem_id,
                                                share_name,
                                                share['share_proto'].upper())
        return locations

    def _create_share_NFS_CIFS(self, nas_server_id, filesystem_id, share_name,
                               protocol):
        LOG.debug(f"Get file interfaces of {nas_server_id}")
        file_interfaces = self.client.get_nas_server_interfaces(
            nas_server_id)
        LOG.debug(f"Creating {protocol} export {share_name}")
        if protocol == 'NFS':
            export_id = self.client.create_nfs_export(filesystem_id,
                                                      share_name)
            if not export_id:
                message = (
                    _('The requested NFS export "%(export)s"'
                        ' was not created.') %
                    {'export': share_name})
                LOG.error(message)
                raise exception.ShareBackendException(msg=message)
            locations = self._get_nfs_location(file_interfaces, share_name)
        elif protocol == 'CIFS':
            export_id = self.client.create_smb_share(filesystem_id,
                                                     share_name)
            if not export_id:
                message = (
                    _('The requested SMB share "%(export)s"'
                        ' was not created.') %
                    {'export': share_name})
                LOG.error(message)
                raise exception.ShareBackendException(msg=message)
            locations = self._get_cifs_location(file_interfaces,
                                                share_name)
        return locations

    def _get_nfs_location(self, file_interfaces, share_name):
        export_locations = []
        for interface in file_interfaces:
            export_locations.append(
                {'path': f"{interface['ip']}:/{share_name}",
                 'metadata': {
                     'preferred': interface['preferred']
                     }
                 })
        return export_locations

    def _get_cifs_location(self, file_interfaces, share_name):
        export_locations = []
        for interface in file_interfaces:
            export_locations.append(
                {'path': f"\\\\{interface['ip']}\\{share_name}",
                 'metadata': {
                     'preferred': interface['preferred']
                     }
                 })
        return export_locations

    @staticmethod
    def _parse_share_name_from_path(path, protocol):
        """Parse the backend share name from an export path string."""
        if protocol == 'NFS' and ':/' in path:
            return path.rsplit(':/', 1)[-1].strip('/')
        elif protocol == 'CIFS' and '\\' in path:
            return path.split('\\')[-1]
        return ''

    def _get_export_path(self, share):
        """Extract the export path string from a share."""
        export_locations = share.get('export_locations')
        if export_locations:
            el = export_locations[0]
            if isinstance(el, dict):
                return el.get('path', '')
            elif hasattr(el, 'path'):
                return el['path']
            else:
                return str(el)
        return share.get('export_location', '')

    def _get_backend_share_name(self, share):
        """Get the backend resource name for a share."""
        try:
            path = self._get_export_path(share)
            if path:
                protocol = share.get('share_proto', '').upper()
                name = self._parse_share_name_from_path(path, protocol)
                if name:
                    return name
        except Exception:
            LOG.debug("Failed to parse backend share name from export "
                      "locations for share '%(name)s', falling back "
                      "to share name.",
                      {'name': share.get('name', '')})
        return share.get('name', '')

    def _get_filesystem_id(self, share):
        """Resolve the PowerStore filesystem ID for a share."""
        backend_name = self._get_backend_share_name(share)
        protocol = share.get('share_proto', '').upper()

        filesystem_id = self.client.get_filesystem_id(backend_name)
        if filesystem_id:
            return filesystem_id

        LOG.debug("Filesystem not found by name '%(name)s', trying "
                  "%(proto)s export/share lookup.",
                  {'name': backend_name, 'proto': protocol})
        if protocol == 'NFS':
            filesystem_id = self.client.get_fsid_from_export_name(
                backend_name)
        elif protocol == 'CIFS':
            filesystem_id = self.client.get_fsid_from_share_name(
                backend_name)

        return filesystem_id

    def delete_share(self, context, share, share_server):
        """Is called to delete a share."""
        LOG.debug(f'Deleting {share["share_proto"]} share.')
        self._delete_share(share)

    def _delete_share(self, share):
        """Deletes a filesystem and its associated export."""
        backend_name = self._get_backend_share_name(share)
        LOG.debug(f"Retrieving filesystem ID for filesystem {backend_name}")
        filesystem_id = self._get_filesystem_id(share)
        if not filesystem_id:
            LOG.warning(
                f'Filesystem with share name {share["name"]} is not found.')
        else:
            LOG.debug(f"Deleting filesystem ID {filesystem_id}")
            share_deleted = self.client.delete_filesystem(filesystem_id)
            if not share_deleted:
                message = (
                    _('Failed to delete share "%(export)s".') %
                    {'export': share['name']})
                LOG.error(message)
                raise exception.ShareBackendException(msg=message)
            # Clean up QoS policy and rule if no longer used
            self._cleanup_qos_on_delete(share)

    def extend_share(self, share, new_size, share_server):
        """Is called to extend a share."""
        LOG.debug(f"Extending {share['name']} to {new_size}GiB")
        self._resize_filesystem(share, new_size)

    def shrink_share(self, share, new_size, share_server):
        """Is called to shrink a share."""
        LOG.debug(f"Shrinking {share['name']} to {new_size}GiB")
        self._resize_filesystem(share, new_size)

    def _resize_filesystem(self, share, new_size):
        """Is called to resize a filesystem"""

        # Converts the size from GiB to Bytes
        new_size_in_bytes = new_size * units.Gi
        filesystem_id = self._get_filesystem_id(share)
        if not filesystem_id:
            message = (_('Failed to find filesystem for share "%(share)s".') %
                       {'share': share['name']})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        is_success, detail = self.client.resize_filesystem(filesystem_id,
                                                           new_size_in_bytes)
        if not is_success:
            message = (_('Failed to resize share "%(export)s".') %
                       {'export': share['name']})
            LOG.error(message)
            if detail:
                raise exception.ShareShrinkingPossibleDataLoss(
                    share_id=share['id'])
            raise exception.ShareBackendException(msg=message)

    def manage_existing(self, share, driver_options):
        """Brings an existing share under Manila management."""
        export_path = self._get_export_path(share)
        if not export_path:
            raise exception.ManageInvalidShare(
                reason=_("Export path is empty. Cannot manage share "
                         "without an export path."))

        protocol = share['share_proto'].upper()
        LOG.info("Managing existing %(proto)s share with export path: "
                 "%(path)s.",
                 {'proto': protocol, 'path': export_path})

        original_name = self._parse_share_name_from_path(
            export_path, protocol)
        if not original_name:
            raise exception.ManageInvalidShare(
                reason=(_("Unable to parse share name from export "
                          "path '%(path)s'.") %
                        {'path': export_path}))

        if protocol == 'NFS':
            export_id = self.client.get_nfs_export_id(original_name)
            if not export_id:
                raise exception.ManageInvalidShare(
                    reason=(_("NFS export '%(name)s' was not found on "
                              "the PowerStore backend.") %
                            {'name': original_name}))
            filesystem_id = self.client.get_fsid_from_export_name(
                original_name)
        elif protocol == 'CIFS':
            smb_share_id = self.client.get_smb_share_id(original_name)
            if not smb_share_id:
                raise exception.ManageInvalidShare(
                    reason=(_("SMB share '%(name)s' was not found on "
                              "the PowerStore backend.") %
                            {'name': original_name}))
            filesystem_id = self.client.get_fsid_from_share_name(
                original_name)
        else:
            raise exception.ManageInvalidShare(
                reason=(_("Unsupported share protocol: %s.") % protocol))

        if not filesystem_id:
            raise exception.ManageInvalidShare(
                reason=(_("Filesystem for export '%(name)s' was not "
                          "found on the PowerStore backend.") %
                        {'name': original_name}))

        # Get filesystem size
        size_bytes = self.client.get_filesystem_size(filesystem_id)
        if not size_bytes:
            raise exception.ManageInvalidShare(
                reason=(_("Unable to determine the size of the filesystem "
                          "for export '%(name)s'.") %
                        {'name': original_name}))
        size_gb = math.ceil(size_bytes / units.Gi)

        nas_server_id = self.client.get_nas_server_id(self.nas_server)
        file_interfaces = self.client.get_nas_server_interfaces(
            nas_server_id)
        if protocol == 'NFS':
            locations = self._get_nfs_location(file_interfaces,
                                               original_name)
        else:
            locations = self._get_cifs_location(file_interfaces,
                                                original_name)

        return {'size': size_gb, 'export_locations': locations}

    def _get_snapshot_filesystem_id(self, snapshot):
        """Resolve the PowerStore filesystem ID for a snapshot."""
        provider_location = snapshot.get('provider_location')
        if provider_location:
            filesystem_id = self.client.get_filesystem_id(provider_location)
            if filesystem_id:
                return filesystem_id
        return self.client.get_filesystem_id(snapshot['name'])

    def manage_existing_snapshot(self, snapshot, driver_options):
        """Brings an existing snapshot under Manila management."""
        provider_location = snapshot.get('provider_location')
        if not provider_location:
            raise exception.ManageInvalidShareSnapshot(
                reason=_("provider_location is required to manage a "
                         "snapshot."))

        LOG.info("Managing existing snapshot with provider_location: "
                 "%(provider_location)s.",
                 {'provider_location': provider_location})

        snap_details = self.client.get_snapshot_filesystem(provider_location)
        if not snap_details:
            raise exception.ManageInvalidShareSnapshot(
                reason=(_("Snapshot '%(name)s' was not found on the "
                          "PowerStore backend.") %
                        {'name': provider_location}))

        parent_id = snap_details.get('parent_id')
        if not parent_id:
            raise exception.ManageInvalidShareSnapshot(
                reason=(_("'%(name)s' is not a snapshot on the "
                          "PowerStore backend.") %
                        {'name': provider_location}))

        share = snapshot.get('share')
        if share:
            share_filesystem_id = self._get_filesystem_id(share)
            if share_filesystem_id and parent_id != share_filesystem_id:
                raise exception.ManageInvalidShareSnapshot(
                    reason=(_("Snapshot '%(snap)s' does not belong to "
                              "share '%(share)s'.") %
                            {'snap': provider_location,
                             'share': share.get('name', '')}))

        backend_size_bytes = snap_details.get('size_total')
        if backend_size_bytes is not None:
            snapshot_size = backend_size_bytes // units.Gi
        else:
            try:
                snapshot_size = int(driver_options.get("size", 0))
            except (ValueError, TypeError):
                msg = _("The size in driver options to manage snapshot "
                        "%(snap_id)s should be an integer, in format "
                        "driver-options size=<SIZE>. Value passed: "
                        "%(size)s.") % {'snap_id': snapshot['id'],
                                        'size': driver_options.get("size")}
                raise exception.ManageInvalidShareSnapshot(reason=msg)

        LOG.info("Snapshot %(provider_location)s in PowerStore will be "
                 "managed with ID %(snapshot_id)s.",
                 {'provider_location': provider_location,
                  'snapshot_id': snapshot['id']})

        return {"size": snapshot_size, "provider_location": provider_location}

    # QoS methods

    @staticmethod
    def _generate_qos_rule_name(qos_type_id):
        """Generates the name for a file_io_limit_rule on PowerStore."""
        return "%s_%s" % (QOS_RULE_NAME_PREFIX, qos_type_id)

    @staticmethod
    def _generate_qos_policy_name(qos_type_id):
        """Generates the name for a File_Performance policy on PowerStore."""
        return "%s_%s" % (QOS_POLICY_NAME_PREFIX, qos_type_id)

    def _validate_qos_specs(self, qos_specs):
        """Validates that QoS specs contain valid max_bw value.

        :param qos_specs: dict of QoS specs from the QoS type
        :raises: InvalidQosTypeSpec if specs are invalid
        """
        if not qos_specs:
            return

        max_bw = qos_specs.get('max_bw')
        if max_bw is None:
            message = _("QoS spec 'max_bw' is required for "
                        "PowerStore driver.")
            raise exception.InvalidQosTypeSpec(reason=message)

        try:
            max_bw = int(max_bw)
        except (ValueError, TypeError):
            message = _("QoS spec 'max_bw' must be a valid integer. "
                        "Got: %s.") % max_bw
            raise exception.InvalidQosTypeSpec(reason=message)

        if max_bw < QOS_MAX_BW_MIN or max_bw > QOS_MAX_BW_MAX:
            message = (_("QoS spec 'max_bw' must be between "
                         "%(min)s and %(max)s MB/s. Got: %(val)s.") %
                       {'min': QOS_MAX_BW_MIN,
                        'max': QOS_MAX_BW_MAX,
                        'val': max_bw})
            raise exception.InvalidQosTypeSpec(reason=message)

        unsupported_keys = set(qos_specs.keys()) - {'max_bw'}
        if unsupported_keys:
            message = (_("Unsupported QoS spec key(s) for PowerStore "
                         "driver: %s. Only 'max_bw' is supported.") %
                       ', '.join(unsupported_keys))
            raise exception.InvalidQosTypeSpec(reason=message)

    def _get_or_create_qos_policy(self, qos_type_id, max_bw):
        """Gets or creates the QoS rule and policy on PowerStore.

        Uses idempotent find-or-create pattern protected by a distributed
        lock keyed on qos_type_id. Multiple shares with the same QoS type
        share the same rule and policy; the lock serialises concurrent
        share-create requests for the same type.

        :param qos_type_id: ID of the Manila QoS type
        :param max_bw: maximum bandwidth in MB/s
        :return: ID of the File_Performance policy
        """
        rule_name = self._generate_qos_rule_name(qos_type_id)
        policy_name = self._generate_qos_policy_name(qos_type_id)

        @coordination.synchronized('powerstore-qos-{qos_type_id}')
        def _locked_get_or_create(qos_type_id):
            # Step 1: Find or create the file_io_limit_rule
            existing_rule = (
                self.client.get_file_io_limit_rule_by_name(rule_name))
            if existing_rule:
                _rule_id = existing_rule['id']
                # Update max_bw if it changed
                if existing_rule.get('max_bw') != max_bw:
                    LOG.debug("Updating file_io_limit_rule %s with "
                              "max_bw=%s.", rule_name, max_bw)
                    if not self.client.modify_file_io_limit_rule(
                            _rule_id, max_bw):
                        message = (_("Failed to update file_io_limit_rule "
                                     "'%(name)s'.") % {'name': rule_name})
                        raise exception.ShareBackendException(msg=message)
            else:
                LOG.debug("Creating file_io_limit_rule %s with "
                          "max_bw=%s.", rule_name, max_bw)
                _rule_id = self.client.create_file_io_limit_rule(
                    rule_name, max_bw)
                if not _rule_id:
                    message = (_("Failed to create file_io_limit_rule "
                                 "'%(name)s'.") % {'name': rule_name})
                    raise exception.ShareBackendException(msg=message)

            # Step 2: Find or create the File_Performance policy
            existing_policy = self.client.get_policy_by_name(policy_name)
            if existing_policy:
                _policy_id = existing_policy['id']
            else:
                LOG.debug("Creating File_Performance policy %s.",
                          policy_name)
                _policy_id = self.client.create_file_performance_policy(
                    policy_name, _rule_id)
                if not _policy_id:
                    message = (_("Failed to create File_Performance "
                                 "policy '%(name)s'.") %
                               {'name': policy_name})
                    raise exception.ShareBackendException(msg=message)

            return _policy_id

        return _locked_get_or_create(qos_type_id)

    def _apply_qos_to_filesystem(self, share, filesystem_id):
        """Applies QoS policy to a filesystem if QoS specs are defined.

        :param share: share dict containing qos_type_id
        :param filesystem_id: ID of the PowerStore filesystem
        """
        qos_specs = qos_types.get_specs_from_share(share)
        if not qos_specs:
            return

        self._validate_qos_specs(qos_specs)
        max_bw = int(qos_specs['max_bw'])
        qos_type_id = share['qos_type_id']

        LOG.info("Applying QoS policy for QoS type '%(qos_type_id)s' "
                 "(max_bw=%(max_bw)s MB/s) to filesystem for "
                 "share '%(share)s'.",
                 {'qos_type_id': qos_type_id,
                  'max_bw': max_bw,
                  'share': share['name']})

        policy_id = self._get_or_create_qos_policy(qos_type_id, max_bw)

        is_success = self.client.set_filesystem_performance_policy(
            filesystem_id, policy_id)
        if not is_success:
            message = (_("Failed to apply QoS policy to filesystem "
                         "for share '%(share)s'.") %
                       {'share': share['name']})
            raise exception.ShareBackendException(msg=message)

    def _cleanup_qos_on_delete(self, share):
        """Cleans up QoS policy and rule if no longer used by any filesystem.

        The check-then-delete sequence is protected by the same distributed
        lock used in _get_or_create_qos_policy, preventing a concurrent
        share-create from observing a partially-deleted policy mid-cleanup.

        :param share: share dict containing qos_type_id
        """
        try:
            qos_specs = qos_types.get_specs_from_share(share)
        except Exception:
            LOG.warning("Failed to retrieve QoS specs for share '%s'. "
                        "Skipping QoS cleanup.", share.get('name'))
            return

        if not qos_specs:
            return

        qos_type_id = share.get('qos_type_id')
        if not qos_type_id:
            return

        policy_name = self._generate_qos_policy_name(qos_type_id)
        rule_name = self._generate_qos_rule_name(qos_type_id)

        @coordination.synchronized('powerstore-qos-{qos_type_id}')
        def _locked_cleanup(qos_type_id):
            existing_policy = self.client.get_policy_by_name(policy_name)
            if not existing_policy:
                return

            _policy_id = existing_policy['id']

            # Check if any other filesystems are still using this policy
            associated_fs = self.client.get_policy_filesystems(_policy_id)
            if associated_fs:
                LOG.debug("QoS policy '%s' still in use by %d "
                          "filesystem(s). Skipping cleanup.",
                          policy_name, len(associated_fs))
                return

            # No filesystems using this policy; safe to delete
            LOG.info("Cleaning up unused QoS policy '%s' and rule '%s'.",
                     policy_name, rule_name)

            if not self.client.delete_policy(_policy_id):
                LOG.warning("Failed to delete QoS policy '%s'.",
                            policy_name)
                return

            existing_rule = (
                self.client.get_file_io_limit_rule_by_name(rule_name))
            if existing_rule:
                if not self.client.delete_file_io_limit_rule(
                        existing_rule['id']):
                    LOG.warning("Failed to delete file_io_limit_rule "
                                "'%s'.", rule_name)

        try:
            _locked_cleanup(qos_type_id)
        except Exception:
            LOG.warning("Error during QoS cleanup for share '%s'. "
                        "Manual cleanup of policy '%s' and rule '%s' "
                        "may be required.",
                        share.get('name'), policy_name, rule_name)

    def allow_access(self, context, share, access, share_server):
        """Allow access to the share."""
        raise NotImplementedError()

    def deny_access(self, context, share, access, share_server):
        """Deny access to the share."""
        raise NotImplementedError()

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Is called to update share access."""
        protocol = share['share_proto'].upper()
        LOG.debug(f'Updating access to {protocol} share.')
        if protocol == 'NFS':
            return self._update_nfs_access(share, access_rules)
        elif protocol == 'CIFS':
            return self._update_cifs_access(share, access_rules)

    def _update_nfs_access(self, share, access_rules):
        """Updates access rules for NFS share type."""
        nfs_rw_ips = set()
        nfs_ro_ips = set()
        access_updates = {}

        for rule in access_rules:
            if rule['access_type'].lower() != 'ip':
                message = (_("Only IP access type currently supported for "
                             "NFS. Share provided %(share)s with rule type "
                             "%(type)s") % {'share': share['display_name'],
                                            'type': rule['access_type']})
                LOG.error(message)
                access_updates.update({rule['access_id']: {'state': 'error'}})

            else:
                if rule['access_level'] == const.ACCESS_LEVEL_RW:
                    nfs_rw_ips.add(rule['access_to'])
                elif rule['access_level'] == const.ACCESS_LEVEL_RO:
                    nfs_ro_ips.add(rule['access_to'])
                access_updates.update({rule['access_id']: {'state': 'active'}})

        backend_name = self._get_backend_share_name(share)
        share_id = self.client.get_nfs_export_id(backend_name)
        share_updated = self.client.set_export_access(share_id,
                                                      nfs_rw_ips,
                                                      nfs_ro_ips)
        if not share_updated:
            message = (
                _('Failed to update NFS access rules for "%(export)s".') %
                {'export': share['display_name']})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        return access_updates

    def _update_cifs_access(self, share, access_rules):
        """Updates access rules for CIFS share type."""
        cifs_rw_users = set()
        cifs_ro_users = set()
        access_updates = {}

        for rule in access_rules:
            if rule['access_type'].lower() != 'user':
                message = (_("Only user access type currently supported for "
                             "CIFS. Share provided %(share)s with rule type "
                             "%(type)s") % {'share': share['display_name'],
                                            'type': rule['access_type']})
                LOG.error(message)
                access_updates.update({rule['access_id']: {'state': 'error'}})

            else:
                prefix = (
                    self.ad_domain or
                    self.client.get_nas_server_smb_netbios(self.nas_server)
                )
                if not prefix:
                    message = (
                        _('Failed to get daomain/netbios name of '
                          '"%(nas_server)s".'
                          ) % {'nas_server': self.nas_server})
                    LOG.error(message)
                    access_updates.update({rule['access_id']:
                                           {'state': 'error'}})
                    continue

                prefix = prefix + '\\'
                if rule['access_level'] == const.ACCESS_LEVEL_RW:
                    cifs_rw_users.add(prefix + rule['access_to'])
                elif rule['access_level'] == const.ACCESS_LEVEL_RO:
                    cifs_ro_users.add(prefix + rule['access_to'])
                access_updates.update({rule['access_id']: {'state': 'active'}})

        backend_name = self._get_backend_share_name(share)
        share_id = self.client.get_smb_share_id(backend_name)
        share_updated = self.client.set_acl(share_id,
                                            cifs_rw_users,
                                            cifs_ro_users)
        if not share_updated:
            message = (
                _('Failed to update NFS access rules for "%(export)s".') %
                {'export': share['display_name']})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        return access_updates

    def update_share_stats(self, stats_dict):
        """Retrieve stats info from share."""
        stats_dict['driver_version'] = VERSION
        stats_dict['storage_protocol'] = 'NFS_CIFS'
        stats_dict['reserved_percentage'] = self.reserved_percentage
        stats_dict['reserved_snapshot_percentage'] = (
            self.reserved_snapshot_percentage)
        stats_dict['reserved_share_extend_percentage'] = (
            self.reserved_share_extend_percentage)
        stats_dict['max_over_subscription_ratio'] = (
            self.max_over_subscription_ratio)
        stats_dict['qos_type_support'] = True

        cluster_id = self.client.get_cluster_id()
        total, used = self.client.retreive_cluster_capacity_metrics(cluster_id)
        if total and used:
            free = total - used
            stats_dict['total_capacity_gb'] = total // units.Gi
            stats_dict['free_capacity_gb'] = free // units.Gi

    def create_snapshot(self, context, snapshot, share_server):
        """Is called to create snapshot."""
        share = snapshot.get('share')
        if not share:
            share = {'name': snapshot['share_name'],
                     'share_proto': ''}
        export_name = self._get_backend_share_name(share)
        LOG.debug(f'Retrieving filesystem ID for share {export_name}')
        filesystem_id = self._get_filesystem_id(share)
        if not filesystem_id:
            message = (
                _('Failed to get filesystem id for export "%(export)s".') %
                {'export': export_name})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        snapshot_name = snapshot['name']
        LOG.debug(
            f'Creating snapshot {snapshot_name} for filesystem {filesystem_id}'
            )
        snapshot_id = self.client.create_snapshot(filesystem_id,
                                                  snapshot_name)
        if not snapshot_id:
            message = (
                _('Failed to create snapshot "%(snapshot)s".') %
                {'snapshot': snapshot_name})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

        LOG.info("Snapshot %(snapshot)s successfully created.",
                 {'snapshot': snapshot_name})
        return {'provider_location': snapshot_name}

    def delete_snapshot(self, context, snapshot, share_server):
        """Is called to delete snapshot."""
        snapshot_name = snapshot.get('provider_location') or snapshot['name']
        LOG.debug(f'Retrieving filesystem ID for snapshot {snapshot_name}')
        filesystem_id = self._get_snapshot_filesystem_id(snapshot)
        if not filesystem_id:
            LOG.warning("Snapshot '%(snapshot)s' was not found on the "
                        "PowerStore backend. Skipping deletion.",
                        {'snapshot': snapshot_name})
            return
        LOG.debug(f'Deleting filesystem ID {filesystem_id}')
        snapshot_deleted = self.client.delete_filesystem(filesystem_id)
        if not snapshot_deleted:
            message = (
                _('Failed to delete snapshot "%(snapshot)s".') %
                {'snapshot': snapshot_name})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        else:
            LOG.info("Snapshot %(snapshot)s successfully deleted.",
                     {'snapshot': snapshot_name})

    def revert_to_snapshot(self, context, snapshot, share_access_rules,
                           snapshot_access_rules, share_server=None):
        """Reverts a share (in place) to the specified snapshot."""
        snapshot_name = snapshot.get('provider_location') or snapshot['name']
        snapshot_id = self._get_snapshot_filesystem_id(snapshot)
        if not snapshot_id:
            message = (
                _('Snapshot "%(snapshot)s" was not found on the '
                  'PowerStore backend.') %
                {'snapshot': snapshot_name})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        snapshot_restored = self.client.restore_snapshot(snapshot_id)
        if not snapshot_restored:
            message = (
                _('Failed to restore snapshot "%(snapshot)s".') %
                {'snapshot': snapshot_name})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        else:
            LOG.info("Snapshot %(snapshot)s successfully restored.",
                     {'snapshot': snapshot_name})

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None, parent_share=None):
        """Create a share from a snapshot - clone a snapshot."""
        LOG.debug(f'Creating {share["share_proto"]} share.')
        locations = self._create_share_from_snapshot(share, snapshot)

        if share['size'] != snapshot['size']:
            LOG.debug(f"Resizing {share['name']} to {share['size']}GiB")
            self._resize_filesystem(share, share['size'])

        return locations

    def _create_share_from_snapshot(self, share, snapshot):
        snap_name = snapshot.get('provider_location') or snapshot['name']
        LOG.debug(f"Retrieving snapshot id of snapshot {snap_name}")
        snapshot_id = self._get_snapshot_filesystem_id(snapshot)
        if not snapshot_id:
            message = (
                _('Snapshot "%(snapshot)s" was not found on the '
                  'PowerStore backend.') %
                {'snapshot': snap_name})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        share_name = share['name']
        LOG.debug(
            f"Cloning filesystem {share_name} from snapshot {snapshot_id}"
            )
        filesystem_id = self.client.clone_snapshot(snapshot_id,
                                                   share_name)
        if not filesystem_id:
            message = (
                _('The filesystem "%(export)s" was not created.') %
                {'export': share_name})
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)
        # apply QoS policy if defined
        try:
            self._apply_qos_to_filesystem(share, filesystem_id)
        except Exception:
            LOG.error("Failed to apply QoS policy to cloned filesystem "
                      "for share '%s'. Cleaning up filesystem.",
                      share_name)
            self.client.delete_filesystem(filesystem_id)
            raise
        # create a share
        nas_server_id = self.client.get_nas_server_id(self.nas_server)
        locations = self._create_share_NFS_CIFS(nas_server_id, filesystem_id,
                                                share_name,
                                                share['share_proto'].upper())
        return locations

    def ensure_share(self, context, share, share_server):
        """Invoked to ensure that share is exported."""

    def setup_server(self, network_info, metadata=None):
        """Set up and configures share server with given network parameters."""

    def teardown_server(self, server_details, security_services=None):
        """Teardown share server."""

    def check_for_setup_error(self):
        """Is called to check for setup error."""

    def get_default_filter_function(self):
        # NOTE(PowerStore): The Manila API layer hardcodes size=0 in the
        # scheduler request_spec during manage operations (see
        # manila/share/api.py, method manage(), ``size=0`` in the call to
        # _get_request_spec_dict).  The scheduler's DriverFilter
        # (manila/scheduler/filters/driver.py) evaluates this filter
        # function against that zero-sized share *before*
        # manage_existing() has a chance to discover the real size from
        # the backend.  Because no request attribute distinguishes a
        # manage call from an ordinary create at the filter stage, we
        # must let size 0 through explicitly.  This is an OpenStack
        # Manila framework constraint, not a PowerStore-specific issue.
        return 'share.size >= 3 or share.size == 0'
