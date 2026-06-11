# Copyright (c) 2026 Hewlett Packard Enterprise Development LP
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

from oslo_log import log

from manila import exception
from manila.i18n import _
from manila.share.drivers.hpe.alletra_mp_b10000.fileshare import (
    fileshare_handler)
from manila.share.drivers.hpe.alletra_mp_b10000.fileshare import (
    filesystem_handler)
from manila.share.drivers.hpe.alletra_mp_b10000.fileshare import (
    helpers)

LOG = log.getLogger(__name__)


class SnapshotHandler(object):
    def __init__(self, rest_client, feature_support_handler, **kwargs):
        self.rest_client = rest_client
        self.feature_support_handler = feature_support_handler
        self.validator = SnapshotValidator(self.feature_support_handler)

        self.fileshare_handler = fileshare_handler.FileShareHandler(
            rest_client, self.feature_support_handler)
        self.filesystem_handler = filesystem_handler.FileSystemHandler(
            rest_client, self.feature_support_handler)

    def create_snapshot(self, fe_create_snapshot, be_share_name,
                        be_filesystem_name, be_sharesetting_name):

        self.validator.validate_create_snapshot_fe_req(fe_create_snapshot)
        fe_filesystem = self.filesystem_handler._get_filesystem_by_name(
            be_filesystem_name)

        # Create snapshot on base filesystem
        self.filesystem_handler.snapshot_create(
            fe_filesystem['be_uid'],
            fe_create_snapshot['name'],
            fe_create_snapshot['id'])

        fe_snap_filesystem = (helpers.poll_for_resource(
            lambda: self.filesystem_handler._get_filesystem_by_name(
                fe_create_snapshot['name']),
            "snapshot filesystem '%s'" % fe_create_snapshot['name']))

        fe_snap_fileshare = (helpers.poll_for_resource(
            lambda: self.fileshare_handler._get_fileshare_by_name(
                be_share_name, fe_create_snapshot['name'],
                be_sharesetting_name),
            "snapshot fileshare '%s'" % be_share_name))

        # Mountable snapshot support
        if fe_create_snapshot['share'].get('mount_snapshot_support'):
            try:
                self.filesystem_handler.snapshot_online(
                    fe_snap_filesystem['be_uid'])
            except Exception as e:
                # We were unable to bring the snapshot online.
                # Clean up the snapshot fileshare and filesystem
                msg = _("Failed to bring snapshot '%(snap)s' online. "
                        "Cleaning up the snapshot share and filesystem. "
                        "Error: %(error)s") % {
                    'snap': fe_create_snapshot['name'], 'error': str(e)}
                LOG.error(msg)
                try:
                    self.fileshare_handler.delete_fileshare_by_id(
                        fe_create_snapshot['id'],
                        fe_snap_fileshare['be_uid'])
                except Exception as cleanup_error:
                    LOG.error(
                        "Failed to clean up snapshot share '%(snap)s' "
                        "after snapshot online failure. Manual cleanup may "
                        "be required. Error: %(error)s",
                        {'snap': fe_create_snapshot['name'],
                         'error': str(cleanup_error)})
                raise exception.HPEAlletraB10000DriverException(reason=msg)

        return fe_snap_fileshare, fe_snap_filesystem

    def delete_snapshot(self, fe_delete_snapshot, be_snap_share_id):
        self.validator.validate_delete_snapshot_fe_req(fe_delete_snapshot)

        self.fileshare_handler.delete_fileshare_by_id(
            fe_delete_snapshot['id'], be_snap_share_id)

    def revert_to_snapshot(self, fe_revert_snapshot, be_filesystem_name,
                           be_snap_filesystem_name):

        fe_filesystem = (
            self.filesystem_handler._get_filesystem_by_name(
                be_filesystem_name))

        self.filesystem_handler.snapshot_restore(
            fe_filesystem['be_uid'], be_snap_filesystem_name)

        # A restore takes the snapshot offline on the backend, so a mountable
        # snapshot has to be re-exported to stay usable.
        if fe_revert_snapshot['share'].get('mount_snapshot_support'):
            try:
                fe_snap_filesystem = (
                    self.filesystem_handler._get_filesystem_by_name(
                        be_snap_filesystem_name))
                self.filesystem_handler.snapshot_online(
                    fe_snap_filesystem['be_uid'])
            except Exception as e:
                LOG.error(
                    "Revert succeeded but failed to bring snapshot "
                    "'%(snap)s' back online. The snapshot will not be "
                    "mountable until it is exported manually on the backend."
                    " Error: %(error)s",
                    {'snap': be_snap_filesystem_name, 'error': str(e)})

        # Reading back filesystem size afer restore
        fe_reverted_filesystem = (
            self.filesystem_handler._get_filesystem_by_name(
                be_filesystem_name))

        return fe_reverted_filesystem['be_filesystem_size']

    def manage_snapshot(self, fe_manage_snapshot, be_filesystem_name):
        self.validator.validate_manage_snapshot_fe_req(fe_manage_snapshot)

        # Get snapshot fileshare and filesystem
        be_snap_filesystem_name = fe_manage_snapshot['provider_location']
        fe_snap_filesystem = self.filesystem_handler._get_filesystem_by_name(
            be_snap_filesystem_name)
        fe_snap_fileshare = (
            self.fileshare_handler._get_fileshare_by_filesystem_name(
                be_snap_filesystem_name))

        # Validate snapshot belongs to parent filesystem
        if 'be_parent_filesystem_name' not in fe_snap_filesystem:
            msg = _("be_parent_filesystem_name not found in get filesystem "
                    "response for '%(snap)s'. This may not be a snapshot "
                    "filesystem.") % {'snap': be_snap_filesystem_name}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)
        if (fe_snap_filesystem['be_parent_filesystem_name']
                != be_filesystem_name):
            msg = (_("Filesystem '%(fs)s' is not the parent filesystem of "
                     "snapshot '%(snap)s'.") %
                   {'fs': be_filesystem_name,
                    'snap': be_snap_filesystem_name})
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        # Validate snapshot export state matches share type mount option
        mount_support = fe_manage_snapshot['share'].get(
            'mount_snapshot_support')
        be_state = fe_snap_fileshare['be_detailed_state']
        if ((mount_support and be_state != "STATE_NORMAL") or
                (not mount_support and be_state != "STATE_UNEXPORTED")):
            if mount_support:
                msg = (_("Manage snapshot failed. Backend snapshot must be "
                         "in exported state (expected: STATE_NORMAL) for "
                         "mount_snapshot_support=True. "
                         "Current backend snapshot state: '%(state)s'. "
                         "Please bring the backend snapshot online and try "
                         "again.") % {'state': be_state})
            else:
                msg = (_("Manage snapshot failed. Backend snapshot must be "
                         "in unexported state (expected: STATE_UNEXPORTED) "
                         "for mount_snapshot_support=False. "
                         "Current backend snapshot state: '%(state)s'. "
                         "Please bring the backend snapshot offline and try "
                         "again.") % {'state': be_state})
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        # Validate that BE snap filesystem size is a multiple of 1024 MiB
        be_filesystem_size_mib = fe_snap_filesystem['be_filesystem_size']
        if be_filesystem_size_mib % 1024 != 0:
            msg = (_("Manage snapshot failed for snapshot '%(snap_name)s'. "
                     "Backend snapshot filesystem size %(current_size)s MiB "
                     "must be a multiple of 1024 MiB (1 GiB).") % {
                'snap_name': be_snap_filesystem_name,
                'current_size': be_filesystem_size_mib})
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        return fe_snap_fileshare, fe_snap_filesystem

    def _compare_values_with_be_snap(
            self, be_snap_share_id, be_snap_share_name,
            be_snap_filesystem_name, be_snap_sharesetting_name):

        return self.fileshare_handler._compare_values_with_be_share(
            be_snap_share_id, be_snap_share_name, be_snap_filesystem_name,
            be_snap_sharesetting_name)


class SnapshotValidator(object):
    def __init__(self, feature_support_handler, **kwargs):
        self.feature_support_handler = feature_support_handler

    def validate_create_snapshot_fe_req(self, fe_create_snapshot):
        if 'name' not in fe_create_snapshot:
            msg = _("Did not receive name parameter "
                    "from create_snapshot fe request")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if 'share' not in fe_create_snapshot:
            msg = _("Did not receive share parameter "
                    "from create_snapshot fe request")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

    def validate_delete_snapshot_fe_req(self, fe_delete_snapshot):
        if 'id' not in fe_delete_snapshot:
            msg = _("Did not receive id parameter "
                    "from delete_snapshot fe request")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

    def validate_manage_snapshot_fe_req(self, fe_manage_snapshot):
        if 'provider_location' not in fe_manage_snapshot:
            msg = _("The backend snap filesystem name must be provided as the "
                    "'provider_location' while managing snapshots.")
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if 'share' not in fe_manage_snapshot:
            msg = _("Did not receive share parameter "
                    "from manage_snapshot fe request")
            LOG.error(msg)
            raise exception.InvalidInput(msg)
