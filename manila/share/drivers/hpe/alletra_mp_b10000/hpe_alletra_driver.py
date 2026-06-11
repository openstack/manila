# Copyright (c) 2025 Hewlett Packard Enterprise Development LP
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

import math

from oslo_config import cfg
from oslo_log import log

from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share.drivers.hpe.alletra_mp_b10000.fileshare import (
    filesetup_handler)
from manila.share.drivers.hpe.alletra_mp_b10000.fileshare import (
    fileshare_handler)
from manila.share.drivers.hpe.alletra_mp_b10000.fileshare import (
    filesystem_handler)
from manila.share.drivers.hpe.alletra_mp_b10000.fileshare import (
    snapshot_handler)
from manila.share.drivers.hpe.alletra_mp_b10000.rest_client import rest_client
from manila.share import share_types

LOG = log.getLogger(__name__)

OPTS = [
    cfg.StrOpt('hpealletra_wsapi_url',
               default='',
               help="Alletra WSAPI V3 Server Url like "
                    "https://<alletra ip>:8080/api/v3"),
    cfg.StrOpt('hpealletra_username',
               default='',
               help="Alletra username with the 'edit' role"),
    cfg.StrOpt('hpealletra_password',
               default='',
               help="Alletra password for the user specified "
               "in hpealletra_username",
               secret=True),
    cfg.BoolOpt('hpealletra_debug',
                default=False,
                help="Enable HTTP debugging to Alletra"),
]


class HPEAlletraMPB10000ShareDriver(driver.ShareDriver):
    """Driver for the HPE Alletra MP B10000 File

    Version history::

        1.0.0 - Initial version
        1.1.0 - Support snapshot functionalities
    """

    # Driver Version
    VERSION = "1.1.0"

    # Other Constants
    ALLETRA_REST_API_TIMEOUT = 120

    def __init__(self, *args, **kwargs):
        super().__init__(False, *args, config_opts=[OPTS], **kwargs)
        self.driver_helper = None
        self.rest_client = None
        self.filesetup_handler = None
        self.fileshare_handler = None
        self.filesystem_handler = None
        self.snapshot_handler = None
        self.privatestorage_handler = HPEAlletraPrivateStorageHandler(
            kwargs.get('private_storage'))
        self.feature_support_handler = None

        # Driver capability support
        self.snapshot_support = False
        self.create_share_from_snapshot_support = False
        self.revert_to_snapshot_support = False
        self.mount_snapshot_support = False
        self.snapshot_inherit_share_access_support = False
        self.qos = False

    def do_setup(self, context):
        """Driver initialization"""

        LOG.info("Starting share driver %(driver_name)s (%(version)s)", {
                 'driver_name': self.__class__.__name__,
                 'version': self.VERSION})

        # Read configuration values
        wsapi_url = self.configuration.safe_get("hpealletra_wsapi_url")
        username = self.configuration.safe_get("hpealletra_username")
        password = self.configuration.safe_get("hpealletra_password")
        debug = self.configuration.safe_get("hpealletra_debug")

        if not wsapi_url:
            msg = _("hpealletra_wsapi_url is required and cannot be empty.")
            LOG.error(msg)
            raise exception.InvalidParameterValue(err=msg)
        if not username:
            msg = _("hpealletra_username is required and cannot be empty.")
            LOG.error(msg)
            raise exception.InvalidParameterValue(err=msg)
        if not password:
            msg = _("hpealletra_password is required and cannot be empty.")
            LOG.error(msg)
            raise exception.InvalidParameterValue(err=msg)

        # If rest client from prior failed do_setup has access key, try to
        # reuse it
        existing_session_key = None
        if (self.rest_client is not None and
                self.rest_client.session_key is not None):
            existing_session_key = self.rest_client.session_key

        # Initialize rest client
        self.rest_client = rest_client.HpeAlletraRestClient(
            wsapi_url, username, password, debug=debug,
            timeout=self.ALLETRA_REST_API_TIMEOUT)
        if existing_session_key is not None:
            self.rest_client.session_key = existing_session_key
        else:
            auth_success, resp_status = self.rest_client.authenticate()
            if not auth_success:
                msg = _("WSAPI V3 authentication during do_setup failed with "
                        "response code %(status)s") % {'status': resp_status}
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(reason=msg)

        # Initialize handlers
        device_version = filesetup_handler.FileSetupHandler.get_device_version(
            self.rest_client)
        self.feature_support_handler = HPEAlletraFeatureSupportHandler(
            device_version)
        self.driver_helper = HPEAlletraMPB10000ShareDriverHelper(
            self.rest_client)

        self.filesetup_handler = filesetup_handler.FileSetupHandler(
            self.rest_client, self.feature_support_handler)
        self.fileshare_handler = fileshare_handler.FileShareHandler(
            self.rest_client, self.feature_support_handler)
        self.filesystem_handler = filesystem_handler.FileSystemHandler(
            self.rest_client, self.feature_support_handler)
        self.snapshot_handler = snapshot_handler.SnapshotHandler(
            self.rest_client, self.feature_support_handler)

        # 1. Check for R5 version from systems API
        self.feature_support_handler.validate_min_driver_version()

        # 2. Check for isFileServiceSupported and File Ports Enabled
        fe_osinfo = self.filesetup_handler.get_osinfo()
        self.driver_helper._validate_is_file_service_supported(fe_osinfo)

        # 3. Check fileservice enabled status
        fe_fileservice = self.filesetup_handler.get_fileservice()
        self.driver_helper._validate_is_fileservice_enabled(fe_fileservice)

        # 4. Feature support checks
        if self.feature_support_handler.check_min_r6_device_version():
            self.snapshot_support = True
            self.revert_to_snapshot_support = True
            self.mount_snapshot_support = True
            self.snapshot_inherit_share_access_support = True

    def create_share(self, context, share, share_server=None):
        """Create a new manila managed share on backend."""

        extra_specs = share_types.get_extra_specs_from_share(share)

        be_fileshare_name, be_filesystem_name, be_sharesetting_name = (
            self.fileshare_handler.create_fileshare(share, extra_specs)
        )

        # Get backend fileshare uid using get fileshares response
        try:
            fe_fileshare = self.fileshare_handler._get_fileshare_by_name(
                be_fileshare_name, be_filesystem_name, be_sharesetting_name)
        except Exception as e:
            msg = _("Create fileshare failed for id %(share_id)s. "
                    "Error: %(error)s") % {'share_id': share['id'],
                                           'error': str(e)}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        export_path = self.driver_helper._build_create_share_resp(
            fe_fileshare['host_ip'], fe_fileshare['mount_path'])

        # Store backend fileshare details in private storage
        self.privatestorage_handler.update_share_by_id(
            share['id'],
            fe_fileshare['be_uid'],
            fe_fileshare['be_fileshare_name'],
            fe_fileshare['be_filesystem_name'],
            fe_fileshare['be_sharesetting_name'])

        return export_path

    def delete_share(self, context, share, share_server=None):
        """Remove a share from manila and backend"""

        try:
            (be_share_id, be_share_name, be_filesystem_name,
             be_sharesetting_name) = (
                self.privatestorage_handler.get_share_by_id(share['id'])
            )
        except Exception as e:
            LOG.error(
                "Failed to retrieve share %(share_id)s from private "
                "storage: %(error)s. Cannot perform automated backend "
                "cleanup without share metadata. Operators should check "
                "HPE Alletra backend for orphaned share resources and "
                "remove them manually if present.",
                {'share_id': share['id'], 'error': str(e)})

            try:
                self.privatestorage_handler.delete_share_by_id(share['id'])
            except Exception:
                LOG.debug("Failed to clear private storage for share "
                          "%(share_id)s during error cleanup.",
                          {'share_id': share['id']})
            return

        try:
            self.fileshare_handler._compare_values_with_be_share(
                be_share_id, be_share_name, be_filesystem_name,
                be_sharesetting_name)
        except Exception as e:
            LOG.warning(
                "Failed to find share %(share_id)s in BE: %(error)s. "
                "Clearing data from private storage and proceeding with"
                " delete.", {'share_id': share['id'], 'error': str(e)})
            self.privatestorage_handler.delete_share_by_id(share['id'])
            return

        try:
            self.fileshare_handler.delete_fileshare_by_id(
                share['id'], be_share_id
            )
        except exception.HPEAlletraB10000DriverException as e:
            if 'snapshots fileshare exist' in str(e):
                msg = (_('Cannot delete share %(share_id)s. '
                         'Backend filesystem has one or more snapshots. '
                         'Please manage all snapshots of this share '
                         'into Manila, delete them, then retry deleting '
                         'the share. Alternatively, unmanage the share '
                         'to remove it from Manila without deleting the '
                         'backend resource.') %
                       {'share_id': share['id']})
                LOG.error(msg)
                raise exception.HPEAlletraB10000DriverException(reason=msg)
            raise

        self.privatestorage_handler.delete_share_by_id(share['id'])

    def extend_share(self, share, new_size, share_server=None):
        """Expand share size"""

        extra_specs = share_types.get_extra_specs_from_share(share)

        (be_share_id, be_share_name, be_filesystem_name,
         be_sharesetting_name) = (
            self.privatestorage_handler.get_share_by_id(share['id'])
        )

        self.fileshare_handler._compare_values_with_be_share(
            be_share_id, be_share_name,
            be_filesystem_name, be_sharesetting_name)

        self.fileshare_handler.edit_fileshare_by_id(
            share['id'],
            be_share_id,
            be_filesystem_name,
            extra_specs,
            True,
            share['size'],
            new_size,
            False,
            None)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, update_rules, share_server=None):
        """Modify share access rules"""

        extra_specs = share_types.get_extra_specs_from_share(share)

        (be_share_id, be_share_name, be_filesystem_name,
         be_sharesetting_name) = (
            self.privatestorage_handler.get_share_by_id(share['id'])
        )

        try:
            self.fileshare_handler._compare_values_with_be_share(
                be_share_id, be_share_name,
                be_filesystem_name, be_sharesetting_name)
        except Exception as e:
            # If access_rules is empty, this is a deletion/cleanup scenario
            # where we're clearing access before deleting the share.
            # Suppress errors in this case to allow deletion to proceed.
            if not access_rules:
                LOG.warning(
                    "Failed to clear share %(share_id)s access rules "
                    "during deletion: %(error)s. Continuing with deletion.",
                    {'share_id': share['id'], 'error': str(e)})
                return
            # For normal access updates, propagate the exception
            raise

        self.fileshare_handler.edit_fileshare_by_id(
            share['id'],
            be_share_id,
            be_filesystem_name,
            extra_specs,
            False,
            None,
            None,
            True,
            access_rules)

    def manage_existing(self, share, driver_options):
        """Bring an existing backend share into manila management"""

        extra_specs = share_types.get_extra_specs_from_share(share)

        fe_fileshare, be_filesystem_size = (
            self.fileshare_handler.manage_fileshare(share, extra_specs)
        )

        manage_existing_resp = (
            self.driver_helper._build_manage_share_resp(
                fe_fileshare['host_ip'],
                fe_fileshare['mount_path'],
                be_filesystem_size)
        )

        # Store backend fileshare details in private storage
        self.privatestorage_handler.update_share_by_id(
            share['id'],
            fe_fileshare['be_uid'],
            fe_fileshare['be_fileshare_name'],
            fe_fileshare['be_filesystem_name'],
            fe_fileshare['be_sharesetting_name'])

        return manage_existing_resp

    def unmanage(self, share):
        """Remove from manila management without deleting backend share"""

        try:
            (be_share_id, be_share_name, be_filesystem_name,
             be_sharesetting_name) = (
                self.privatestorage_handler.get_share_by_id(share['id'])
            )
        except Exception as e:
            LOG.warning(
                "Failed to retrieve share %(share_id)s "
                "from private storage: %(error)s. "
                "Skipping remaining unmanage operations.", {
                    'share_id': share['id'], 'error': str(e)})
            return

        try:
            self.fileshare_handler._compare_values_with_be_share(
                be_share_id, be_share_name, be_filesystem_name,
                be_sharesetting_name)
        except Exception as e:
            LOG.warning(
                "Failed to find share %(share_id)s in BE: %(error)s. "
                "Clearing data from private storage and proceeding with"
                " unmanage.", {'share_id': share['id'], 'error': str(e)})

        self.privatestorage_handler.delete_share_by_id(share['id'])

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot of a share"""

        # Get and validate parent share from private storage
        share_id = snapshot['share']['id']
        (be_share_id, be_share_name, be_filesystem_name,
         be_sharesetting_name) = (
            self.privatestorage_handler.get_share_by_id(share_id))
        self.fileshare_handler._compare_values_with_be_share(
            be_share_id, be_share_name,
            be_filesystem_name, be_sharesetting_name)

        # Create snapshot
        (fe_snap_fileshare,
         fe_snap_filesystem) = (
            self.snapshot_handler.create_snapshot(
                snapshot,
                be_share_name,
                be_filesystem_name,
                be_sharesetting_name))

        self.privatestorage_handler.update_snapshot_by_id(
            snapshot['id'],
            fe_snap_fileshare['be_uid'],
            fe_snap_filesystem['be_uid'],
            fe_snap_fileshare['be_fileshare_name'],
            fe_snap_fileshare['be_filesystem_name'],
            fe_snap_fileshare['be_sharesetting_name'])

        create_snapshot_resp = (
            self.driver_helper._build_create_snapshot_resp(
                fe_snap_fileshare['host_ip'],
                fe_snap_fileshare['mount_path'],
                fe_snap_fileshare['be_filesystem_name'],
                snapshot['share'].get('mount_snapshot_support')))

        return create_snapshot_resp

    def delete_snapshot(self, context, snapshot, share_server=None):

        try:
            (be_snap_share_id, be_snap_filesystem_id, be_snap_share_name,
             be_snap_filesystem_name, be_snap_sharesetting_name) = (
                self.privatestorage_handler.get_snapshot_by_id(snapshot['id'])
            )
        except Exception as e:
            LOG.error(
                "Failed to retrieve snapshot %(snapshot_id)s from private "
                "storage: %(error)s. Cannot perform automated backend "
                "cleanup without snapshot metadata. Operators should check "
                "HPE Alletra backend for orphaned snapshot resources and "
                "remove them manually if present.",
                {'snapshot_id': snapshot['id'], 'error': str(e)})

            try:
                self.privatestorage_handler.delete_snapshot_by_id(
                    snapshot['id'])
            except Exception:
                LOG.debug("Failed to clear private storage for snapshot "
                          "%(snapshot_id)s during error cleanup.",
                          {'snapshot_id': snapshot['id']})
            return

        try:
            self.snapshot_handler._compare_values_with_be_snap(
                be_snap_share_id, be_snap_share_name, be_snap_filesystem_name,
                be_snap_sharesetting_name)
        except Exception as e:
            LOG.warning(
                "Failed to find snap fileshare for %(snapshot_id)s "
                "in BE: %(error)s. "
                "Clearing data from private storage and proceeding with"
                " delete.", {'snapshot_id': snapshot['id'], 'error': str(e)})
            self.privatestorage_handler.delete_snapshot_by_id(snapshot['id'])
            return

        self.snapshot_handler.delete_snapshot(snapshot, be_snap_share_id)

        self.privatestorage_handler.delete_snapshot_by_id(snapshot['id'])

    def revert_to_snapshot(self, context, snapshot, share_access_rules,
                           snapshot_access_rules, share_server=None):

        (be_snap_share_id, be_snap_filesystem_id, be_snap_share_name,
         be_snap_filesystem_name, be_snap_sharesetting_name) = (
            self.privatestorage_handler.get_snapshot_by_id(snapshot['id'])
        )
        share_id = snapshot['share']['id']
        (be_share_id, be_share_name, be_filesystem_name,
         be_sharesetting_name) = (
            self.privatestorage_handler.get_share_by_id(share_id))

        be_filesystem_size = self.snapshot_handler.revert_to_snapshot(
            snapshot, be_filesystem_name, be_snap_filesystem_name
        )

        return math.ceil(be_filesystem_size / 1024)

    def snapshot_update_access(self, context, snapshot, access_rules,
                               add_rules=None, delete_rules=None,
                               share_server=None):
        """Update access rules for a mountable snapshot.

        Alletra snapshots always inherit the parent share's access rules,
        so the driver reports snapshot_inherit_share_access_support and the
        backend offers no way to set independent snapshot rules. Nothing is
        applied here.
        """
        pass

    def manage_existing_snapshot(self, snapshot, driver_options):

        # Get and validate parent share from private storage
        share_id = snapshot['share']['id']
        (be_share_id, be_share_name, be_filesystem_name,
         be_sharesetting_name) = (
            self.privatestorage_handler.get_share_by_id(share_id))
        self.fileshare_handler._compare_values_with_be_share(
            be_share_id, be_share_name,
            be_filesystem_name, be_sharesetting_name)

        (fe_snap_fileshare,
         fe_snap_filesystem) = self.snapshot_handler.manage_snapshot(
            snapshot, be_filesystem_name)

        self.privatestorage_handler.update_snapshot_by_id(
            snapshot['id'],
            fe_snap_fileshare['be_uid'],
            fe_snap_filesystem['be_uid'],
            fe_snap_fileshare['be_fileshare_name'],
            fe_snap_fileshare['be_filesystem_name'],
            fe_snap_fileshare['be_sharesetting_name'])

        manage_snapshot_resp = self.driver_helper._build_manage_snapshot_resp(
            fe_snap_fileshare['host_ip'],
            fe_snap_fileshare['mount_path'],
            fe_snap_filesystem['be_filesystem_size'],
            fe_snap_fileshare['be_filesystem_name'],
            snapshot['share'].get('mount_snapshot_support'))

        return manage_snapshot_resp

    def unmanage_snapshot(self, snapshot):
        """Remove snapshot from manila management without deleting backend"""

        try:
            (be_snap_share_id, be_snap_filesystem_id, be_snap_share_name,
             be_snap_filesystem_name, be_snap_sharesetting_name) = (
                self.privatestorage_handler.get_snapshot_by_id(snapshot['id'])
            )
        except Exception as e:
            LOG.warning(
                "Failed to retrieve snapshot %(snapshot_id)s "
                "from private storage: %(error)s. "
                "Skipping remaining unmanage operations.", {
                    'snapshot_id': snapshot['id'], 'error': str(e)})
            return

        try:
            self.snapshot_handler._compare_values_with_be_snap(
                be_snap_share_id, be_snap_share_name,
                be_snap_filesystem_name, be_snap_sharesetting_name)
        except Exception as e:
            LOG.warning(
                "Failed to find snapshot %(snapshot_id)s in BE: %(error)s. "
                "Clearing data from private storage and proceeding with"
                " unmanage.", {
                    'snapshot_id': snapshot['id'], 'error': str(e)})

        self.privatestorage_handler.delete_snapshot_by_id(snapshot['id'])

    def get_backend_info(self, context):
        """Return backend configuration info for ensure_shares validation."""
        return {
            'driver_version': self.VERSION,
            'wsapi_url': self.configuration.safe_get("hpealletra_wsapi_url"),
            'username': self.configuration.safe_get("hpealletra_username"),
            'password': self.configuration.safe_get("hpealletra_password"),
            'debug': self.configuration.safe_get("hpealletra_debug"),
        }

    def ensure_shares(self, context, shares):
        """Ensure shares exist on backend and return their current state.

        Only returns updates for shares that need status changes. Shares that
        are already available on the backend are not included in the response,
        preserving their current state.
        """
        ensure_updates = {}

        try:
            fe_fileshares = self.fileshare_handler.get_fileshares()
            # Build lookup dictionary: be_share_id -> fe_fileshare
            fe_fileshares_map = {}
            for fileshare in fe_fileshares:
                fe_fileshares_map[fileshare['be_uid']] = fileshare
        except Exception as e:
            LOG.warning(
                "Failed to retrieve fileshare details from backend: %s. "
                "Shares will retain their current state.", str(e))
            # Don't return updates - leave shares in their current state
            return ensure_updates

        # Process each share
        for share in shares:
            try:
                (ps_be_share_id, ps_be_share_name, ps_be_filesystem_name,
                 ps_be_sharesetting_name) = (
                    self.privatestorage_handler.get_share_by_id(share['id'])
                )

                # Lookup share in the retrieved fileshares
                fe_fileshare = fe_fileshares_map.get(ps_be_share_id)
                if not fe_fileshare:
                    # Share exists in Manila DB but not on backend - mark as
                    # error
                    LOG.error(
                        "Share %(share_id)s with backend ID %(be_id)s"
                        " not found on backend. Share may have been "
                        "deleted externally.", {'share_id': share['id'],
                                                'be_id': ps_be_share_id})
                    ensure_updates[share['id']] = {
                        'status': 'error',
                        'reapply_access_rules': False,
                    }
                    continue

                # Validate backend share names to match private storage
                try:
                    self.fileshare_handler.validator._validate_be_share_values(
                        fe_fileshare['be_uid'],
                        fe_fileshare['be_fileshare_name'],
                        fe_fileshare['be_filesystem_name'],
                        fe_fileshare['be_sharesetting_name'],
                        ps_be_share_id, ps_be_share_name,
                        ps_be_filesystem_name, ps_be_sharesetting_name)
                except Exception as e:
                    LOG.error(
                        "Backend share validation failed "
                        "for %(share_id)s: %(error)s. "
                        "Share metadata mismatch detected.", {
                            'share_id': share['id'], 'error': str(e)})
                    ensure_updates[share['id']] = {
                        'status': 'error',
                        'reapply_access_rules': False,
                    }
                    continue

                # Share exists and is valid - only update if export locations
                # changed
                export_path = self.driver_helper._build_create_share_resp(
                    fe_fileshare['host_ip'], fe_fileshare['mount_path'])

                ensure_updates[share['id']] = {
                    'export_locations': export_path,
                    'status': 'available',
                    'reapply_access_rules': True,
                }

            except Exception as e:
                # Private storage read failure - don't update share status
                LOG.warning(
                    "Failed to verify share %(share_id)s "
                    "from private storage: %(error)s. "
                    "Share will retain its current state.", {
                        'share_id': share['id'], 'error': str(e)})
                # Don't include in updates - leave share in current state

        return ensure_updates

    def _update_share_stats(self):
        """Retrieve stats info from backend for file"""

        backend_name = self.configuration.safe_get(
            'share_backend_name') or self.__class__.__name__

        fe_fileservice = self.filesetup_handler.get_fileservice()

        # Convert from MiB to GB
        total_capacity_gb = float(fe_fileservice['be_total_capacity']) / 1024
        provisioned_capacity_gb = float(
            fe_fileservice['be_used_capacity']) / 1024
        free_capacity_gb = float(
            fe_fileservice['be_available_capacity']) / 1024

        # We are setting max_over_subscription_ratio to 1,
        # we cannot overprovision filesystems beyond the
        # available capacity in backend
        max_over_subscription_ratio = 1

        reserved_percentage = self.configuration.safe_get(
            'reserved_share_percentage')
        reserved_extend_percentage = (
            self.configuration.safe_get('reserved_share_extend_percentage') or
            reserved_percentage)

        data = {
            'share_backend_name': backend_name,
            'vendor_name': 'HPE',
            'driver_version': self.VERSION,
            'storage_protocol': 'NFS',
            'total_capacity_gb': total_capacity_gb,
            'free_capacity_gb': free_capacity_gb,
            'provisioned_capacity_gb': provisioned_capacity_gb,
            'max_over_subscription_ratio': max_over_subscription_ratio,
            'reserved_percentage': reserved_percentage,
            'reserved_share_extend_percentage': reserved_extend_percentage,
            'qos': self.qos,
            'thin_provisioning': True,
            'dedupe': [True, False],
            'compression': [True, False],
            'pools': None,
            'snapshot_support': self.snapshot_support,
            'create_share_from_snapshot_support':
                self.create_share_from_snapshot_support,
            'revert_to_snapshot_support': self.revert_to_snapshot_support,
            'mount_snapshot_support': self.mount_snapshot_support,
            'snapshot_inherit_share_access_support': (
                self.snapshot_inherit_share_access_support),
        }
        # Update the stats
        super(HPEAlletraMPB10000ShareDriver, self)._update_share_stats(data)

    def get_network_allocations_number(self):
        return 0


class HPEAlletraMPB10000ShareDriverHelper(object):
    """Driver helper for the HPE Alletra MP B10000 File"""

    def __init__(self, rest_client, **kwargs):
        self.rest_client = rest_client

    def _validate_is_file_service_supported(self, fe_osinfo):
        is_file_service_supported = fe_osinfo['be_is_fileservice_supported']
        LOG.info("isFileServiceSupported status on %(api_url)s is "
                 "%(is_file_service_supported)s",
                 {'api_url': self.rest_client.api_url,
                  'is_file_service_supported': is_file_service_supported})
        if not is_file_service_supported:
            msg = _(
                "File service is not supported on %(api_url)s. "
                "Please verify that the Alletra system is properly "
                "configured to support file services and retry driver setup."
            ) % {'api_url': self.rest_client.api_url}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

    def _validate_is_fileservice_enabled(self, fe_fileservice):
        is_fileservice_enabled = fe_fileservice['be_is_fileservice_enabled']
        LOG.info("Fileservice enabled status on %(api_url)s is "
                 "%(be_is_fileservice_enabled)s",
                 {'api_url': self.rest_client.api_url,
                  'be_is_fileservice_enabled': is_fileservice_enabled})
        if not is_fileservice_enabled:
            msg = _("Fileservice is not enabled on %(api_url)s. Enable and "
                    "retry driver setup") % {
                        'api_url': self.rest_client.api_url}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

    # create_share()
    def _build_create_share_resp(self, hostip, mountpath):
        return self._build_export_data_resp(hostip, mountpath)

    # manage_share()
    def _build_manage_share_resp(
            self,
            hostip,
            mountpath,
            existing_share_size_mib):
        export_data = self._build_export_data_resp(hostip, mountpath)

        existing_share_size_gb = math.ceil(existing_share_size_mib / 1024)
        manage_share_resp = {
            'size': existing_share_size_gb,
            'export_locations': export_data}
        return manage_share_resp

    # create_snapshot()
    def _build_create_snapshot_resp(
            self,
            hostip,
            mountpath,
            provider_location,
            mount_snapshot_support):

        create_snapshot_resp = {
            'provider_location': provider_location,
        }
        if mount_snapshot_support:
            create_snapshot_resp['export_locations'] = (
                self._build_export_data_resp(hostip, mountpath))
        return create_snapshot_resp

    # manage_snapshot()
    def _build_manage_snapshot_resp(
            self,
            hostip,
            mountpath,
            be_filesystem_size,
            provider_location,
            mount_snapshot_support):

        be_filesystem_size_gb = math.ceil(be_filesystem_size / 1024)
        manage_snapshot_resp = {
            'size': be_filesystem_size_gb,
            'provider_location': provider_location,
        }
        if mount_snapshot_support:
            export_data = self._build_export_data_resp(hostip, mountpath)
            manage_snapshot_resp['export_locations'] = export_data
        return manage_snapshot_resp

    def _build_export_data_resp(self, hostip, mountpath):
        share_path = hostip + ':' + mountpath
        export_location = {"path": share_path, "is_admin_only": False,
                           "metadata": {}}
        export_data = []
        export_data.append(export_location)
        return export_data


class HPEAlletraPrivateStorageHandler(object):
    def __init__(self, private_storage):
        self.private_storage = private_storage

    # Fileshare
    PS_BE_SHARE_ID = 'alletra_be_share_id'
    PS_BE_SHARE_NAME = 'alletra_be_share_name'
    PS_BE_FILESYSTEM_NAME = 'alletra_be_filesystem_name'
    PS_BE_SHARESETTING_NAME = 'alletra_be_sharesetting_name'

    def update_share_by_id(self, fe_share_id, be_share_id, be_share_name,
                           be_filesystem_name, be_sharesetting_name):
        """Update private storage with backend share details."""
        self.private_storage.update(fe_share_id, {
            self.PS_BE_SHARE_ID: be_share_id,
            self.PS_BE_SHARE_NAME: be_share_name,
            self.PS_BE_FILESYSTEM_NAME: be_filesystem_name,
            self.PS_BE_SHARESETTING_NAME: be_sharesetting_name
        })

    def get_share_by_id(self, fe_share_id):
        if fe_share_id is None:
            msg = _("Invalid fe_share_id received from manila API "
                    "%(fe_share_id)s.") % {'fe_share_id': fe_share_id}
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        ps_share_data = self.private_storage.get(fe_share_id)

        if ps_share_data is None:
            msg = _("Share %(share_id)s not found in private storage. "
                    "Share may have been deleted or private storage "
                    "is corrupted.") % {'share_id': fe_share_id}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        self._validate_get_values_from_private_storage(
            fe_share_id, ps_share_data)

        be_share_id = ps_share_data.get(self.PS_BE_SHARE_ID)
        be_share_name = ps_share_data.get(self.PS_BE_SHARE_NAME)
        be_filesystem_name = ps_share_data.get(self.PS_BE_FILESYSTEM_NAME)
        be_sharesetting_name = ps_share_data.get(
            self.PS_BE_SHARESETTING_NAME)
        return (be_share_id, be_share_name,
                be_filesystem_name, be_sharesetting_name)

    def delete_share_by_id(self, fe_share_id):
        if fe_share_id is None:
            msg = _("Invalid fe_share_id received from manila API "
                    "%(fe_share_id)s.") % {'fe_share_id': fe_share_id}
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        self.private_storage.delete(fe_share_id)

    def _validate_get_values_from_private_storage(
            self, fe_share_id, ps_share_data):
        be_share_id = ps_share_data.get(self.PS_BE_SHARE_ID)
        be_share_name = ps_share_data.get(self.PS_BE_SHARE_NAME)
        be_filesystem_name = ps_share_data.get(self.PS_BE_FILESYSTEM_NAME)
        be_sharesetting_name = ps_share_data.get(
            self.PS_BE_SHARESETTING_NAME)

        if be_share_id is None:
            msg = _("Unable to read alletra_be_share_id "
                    "from manila private storage "
                    "for %(fe_share_id)s.") % {'fe_share_id': fe_share_id}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if be_share_name is None:
            msg = _("Unable to read alletra_be_share_name "
                    "from manila private storage for "
                    "%(fe_share_id)s.") % {'fe_share_id': fe_share_id}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if be_filesystem_name is None:
            msg = _("Unable to read alletra_be_filesystem_name"
                    " from manila private storage for "
                    "%(fe_share_id)s.") % {'fe_share_id': fe_share_id}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if be_sharesetting_name is None:
            msg = _("Unable to read alletra_be_sharesetting_name"
                    " from manila private storage for "
                    "%(fe_share_id)s.") % {'fe_share_id': fe_share_id}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

    # Snapshot
    PS_BE_SNAP_SHARE_ID = 'alletra_be_snap_share_id'
    PS_BE_SNAP_FILESYSTEM_ID = 'alletra_be_snap_filesystem_id'
    PS_BE_SNAP_SHARE_NAME = 'alletra_be_snap_share_name'
    PS_BE_SNAP_FILESYSTEM_NAME = 'alletra_be_snap_filesystem_name'
    PS_BE_SNAP_SHARESETTING_NAME = 'alletra_be_snap_sharesetting_name'

    def update_snapshot_by_id(self, fe_snapshot_id, be_share_id,
                              be_filesystem_id, be_share_name,
                              be_filesystem_name, be_sharesetting_name):
        """Update private storage with backend snapshot details."""
        self.private_storage.update(fe_snapshot_id, {
            self.PS_BE_SNAP_SHARE_ID: be_share_id,
            self.PS_BE_SNAP_FILESYSTEM_ID: be_filesystem_id,
            self.PS_BE_SNAP_SHARE_NAME: be_share_name,
            self.PS_BE_SNAP_FILESYSTEM_NAME: be_filesystem_name,
            self.PS_BE_SNAP_SHARESETTING_NAME: be_sharesetting_name
        })

    def get_snapshot_by_id(self, fe_snapshot_id):
        if fe_snapshot_id is None:
            msg = _("Invalid fe_snapshot_id received from manila API "
                    "%(fe_snapshot_id)s.") % {'fe_snapshot_id': fe_snapshot_id}
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        ps_share_data = self.private_storage.get(fe_snapshot_id)

        if ps_share_data is None:
            msg = _("Snapshot %(snapshot_id)s not found in private storage. "
                    "Snapshot may have been deleted or private storage "
                    "is corrupted.") % {'snapshot_id': fe_snapshot_id}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        self._validate_get_snapshot_values_from_private_storage(
            fe_snapshot_id, ps_share_data)

        be_snap_share_id = ps_share_data.get(self.PS_BE_SNAP_SHARE_ID)
        be_snap_filesystem_id = ps_share_data.get(
            self.PS_BE_SNAP_FILESYSTEM_ID)
        be_snap_share_name = ps_share_data.get(self.PS_BE_SNAP_SHARE_NAME)
        be_snap_filesystem_name = ps_share_data.get(
            self.PS_BE_SNAP_FILESYSTEM_NAME)
        be_snap_sharesetting_name = ps_share_data.get(
            self.PS_BE_SNAP_SHARESETTING_NAME)
        return (be_snap_share_id, be_snap_filesystem_id, be_snap_share_name,
                be_snap_filesystem_name, be_snap_sharesetting_name)

    def delete_snapshot_by_id(self, fe_snapshot_id):
        if fe_snapshot_id is None:
            msg = _("Invalid fe_snapshot_id received from manila API "
                    "%(fe_snapshot_id)s.") % {'fe_snapshot_id': fe_snapshot_id}
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        self.private_storage.delete(fe_snapshot_id)

    def _validate_get_snapshot_values_from_private_storage(
            self, fe_snapshot_id, ps_share_data):
        be_snap_share_id = ps_share_data.get(self.PS_BE_SNAP_SHARE_ID)
        be_snap_filesystem_id = ps_share_data.get(
            self.PS_BE_SNAP_FILESYSTEM_ID)
        be_snap_share_name = ps_share_data.get(self.PS_BE_SNAP_SHARE_NAME)
        be_snap_filesystem_name = ps_share_data.get(
            self.PS_BE_SNAP_FILESYSTEM_NAME)
        be_snap_sharesetting_name = ps_share_data.get(
            self.PS_BE_SNAP_SHARESETTING_NAME)

        if be_snap_share_id is None:
            msg = _("Unable to read alletra_be_snap_share_id "
                    "from manila private storage "
                    "for %(fe_snapshot_id)s.") % {
                        'fe_snapshot_id': fe_snapshot_id}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if be_snap_filesystem_id is None:
            msg = _("Unable to read alletra_be_snap_filesystem_id "
                    "from manila private storage "
                    "for %(fe_snapshot_id)s.") % {
                        'fe_snapshot_id': fe_snapshot_id}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if be_snap_share_name is None:
            msg = _("Unable to read alletra_be_snap_share_name "
                    "from manila private storage for "
                    "%(fe_snapshot_id)s.") % {'fe_snapshot_id': fe_snapshot_id}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if be_snap_filesystem_name is None:
            msg = _("Unable to read alletra_be_snap_filesystem_name"
                    " from manila private storage for "
                    "%(fe_snapshot_id)s.") % {'fe_snapshot_id': fe_snapshot_id}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        if be_snap_sharesetting_name is None:
            msg = _("Unable to read alletra_be_snap_sharesetting_name"
                    " from manila private storage for "
                    "%(fe_snapshot_id)s.") % {'fe_snapshot_id': fe_snapshot_id}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)


class HPEAlletraFeatureSupportHandler(object):
    R5_MIN_DEVICE_VERSION = "10.5.0"
    R6_MIN_DEVICE_VERSION = "10.6.0"

    def __init__(self, device_version):
        self.device_version = device_version

    def validate_min_driver_version(self):
        """Validate that device version meets minimum requirements."""
        if not self.check_min_r5_device_version():
            msg = _(
                "File on Alletra MP B10000 is not supported "
                "for device version %(version)s. "
                "Minimum required version is %(min_version)s") % {
                'version': self.device_version,
                'min_version': self.R5_MIN_DEVICE_VERSION}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

    def check_min_r5_device_version(self):
        return self._check_device_version(self.R5_MIN_DEVICE_VERSION)

    def check_min_r6_device_version(self):
        return self._check_device_version(self.R6_MIN_DEVICE_VERSION)

    # Helpers
    def _check_device_version(self, feature_min_version):
        """Check that device version meets minimum requirements."""
        device_version = self.device_version

        version_parts = device_version.split('.')
        major = int(version_parts[0])
        minor = int(version_parts[1])

        min_version_parts = feature_min_version.split('.')
        min_major = int(min_version_parts[0])
        min_minor = int(min_version_parts[1])

        if major < min_major or (major == min_major and minor < min_minor):
            return False

        return True
