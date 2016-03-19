# Copyright 2016 Yogesh Kshirsagar
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

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest import test
import testtools

from manila_tempest_tests import clients_share as clients
from manila_tempest_tests.common import constants
from manila_tempest_tests import share_exceptions
from manila_tempest_tests.tests.api import base

CONF = config.CONF
_MIN_SUPPORTED_MICROVERSION = '2.11'


@testtools.skipUnless(CONF.share.run_replication_tests,
                      'Replication tests are disabled.')
@testtools.skipUnless(CONF.share.run_snapshot_tests,
                      'Snapshot tests disabled.')
@base.skip_if_microversion_lt(_MIN_SUPPORTED_MICROVERSION)
class ReplicationSnapshotTest(base.BaseSharesTest):

    @classmethod
    def resource_setup(cls):
        super(ReplicationSnapshotTest, cls).resource_setup()
        # Create share_type
        name = data_utils.rand_name(constants.TEMPEST_MANILA_PREFIX)
        cls.admin_client = clients.AdminManager().shares_v2_client
        cls.replication_type = CONF.share.backend_replication_type

        if cls.replication_type not in constants.REPLICATION_TYPE_CHOICES:
            raise share_exceptions.ShareReplicationTypeException(
                replication_type=cls.replication_type
            )
        cls.zones = cls.get_availability_zones(client=cls.admin_client)
        cls.share_zone = cls.zones[0]
        cls.replica_zone = cls.zones[-1]

        cls.extra_specs = cls.add_required_extra_specs_to_dict(
            {"replication_type": cls.replication_type})
        share_type = cls.create_share_type(
            name,
            extra_specs=cls.extra_specs,
            client=cls.admin_client)
        cls.share_type = share_type["share_type"]
        # Create share with above share_type
        cls.creation_data = {'kwargs': {
            'share_type_id': cls.share_type['id'],
            'availability_zone': cls.share_zone,
        }}

    @test.attr(type=["gate", ])
    def test_snapshot_after_share_replica(self):
        """Test the snapshot for replicated share.

        Create replica first and then create a snapshot.
        Verify that the snapshot is properly created under replica by
        creating a share from that snapshot.
        """
        share = self.create_share(share_type_id=self.share_type['id'],
                                  availability_zone=self.share_zone)
        original_replica = self.shares_v2_client.list_share_replicas(
            share["id"])[0]

        share_replica = self.create_share_replica(share["id"],
                                                  self.replica_zone,
                                                  cleanup=False)
        self.addCleanup(self.delete_share_replica, original_replica['id'])
        self.shares_v2_client.wait_for_share_replica_status(
            share_replica['id'], constants.REPLICATION_STATE_IN_SYNC,
            status_attr='replica_state')

        snapshot = self.create_snapshot_wait_for_active(share["id"])
        self.promote_share_replica(share_replica['id'])
        self.delete_share_replica(original_replica['id'])
        self.create_share(snapshot_id=snapshot['id'])

    @test.attr(type=["gate", ])
    def test_snapshot_before_share_replica(self):
        """Test the snapshot for replicated share.

        Create snapshot before creating share replica for the same
        share.
        Verify snapshot by creating share from the snapshot.
        """
        share = self.create_share(share_type_id=self.share_type['id'],
                                  availability_zone=self.share_zone)
        snapshot = self.create_snapshot_wait_for_active(share["id"])

        original_replica = self.shares_v2_client.list_share_replicas(
            share["id"])[0]
        share_replica = self.create_share_replica(share["id"],
                                                  self.replica_zone,
                                                  cleanup=False)
        self.addCleanup(self.delete_share_replica, original_replica['id'])
        self.shares_v2_client.wait_for_share_replica_status(
            share_replica['id'], constants.REPLICATION_STATE_IN_SYNC,
            status_attr='replica_state')

        # Wait for snapshot1 to become available
        self.shares_v2_client.wait_for_snapshot_status(
            snapshot['id'], "available")

        self.promote_share_replica(share_replica['id'])
        self.delete_share_replica(original_replica['id'])
        self.create_share(snapshot_id=snapshot['id'])

    @test.attr(type=["gate", ])
    def test_snapshot_before_and_after_share_replica(self):
        """Test the snapshot for replicated share.

        Verify that snapshot can be created before and after share replica
        being created.
        Verify snapshots by creating share from the snapshots.
        """
        share = self.create_share(share_type_id=self.share_type['id'],
                                  availability_zone=self.share_zone)
        snapshot1 = self.create_snapshot_wait_for_active(share["id"])

        original_replica = self.shares_v2_client.list_share_replicas(
            share["id"])[0]

        share_replica = self.create_share_replica(share["id"],
                                                  self.replica_zone,
                                                  cleanup=False)
        self.addCleanup(self.delete_share_replica, original_replica['id'])
        self.shares_v2_client.wait_for_share_replica_status(
            share_replica['id'], constants.REPLICATION_STATE_IN_SYNC,
            status_attr='replica_state')

        snapshot2 = self.create_snapshot_wait_for_active(share["id"])

        # Wait for snapshot1 to become available
        self.shares_v2_client.wait_for_snapshot_status(
            snapshot1['id'], "available")

        self.promote_share_replica(share_replica['id'])
        # Remove the original active replica to ensure that snapshot is
        # still being created successfully.
        self.delete_share_replica(original_replica['id'])

        self.create_share(snapshot_id=snapshot1['id'])
        self.create_share(snapshot_id=snapshot2['id'])

    @test.attr(type=["gate", ])
    def test_delete_snapshot_after_adding_replica(self):
        """Verify the snapshot delete.

        Ensure that deleting the original snapshot also deletes the
        snapshot from replica.
        """

        share = self.create_share(share_type_id=self.share_type['id'],
                                  availability_zone=self.share_zone)
        share_replica = self.create_share_replica(share["id"],
                                                  self.replica_zone)
        self.shares_v2_client.wait_for_share_replica_status(
            share_replica['id'], constants.REPLICATION_STATE_IN_SYNC,
            status_attr='replica_state')
        snapshot = self.create_snapshot_wait_for_active(share["id"])
        self.shares_v2_client.delete_snapshot(snapshot['id'])
        self.shares_v2_client.wait_for_resource_deletion(
            snapshot_id=snapshot["id"])

    @test.attr(type=["gate", ])
    def test_create_replica_from_snapshot_share(self):
        """Test replica for a share that was created from snapshot."""

        share = self.create_share(share_type_id=self.share_type['id'],
                                  availability_zone=self.share_zone)
        orig_snapshot = self.create_snapshot_wait_for_active(share["id"])
        snap_share = self.create_share(snapshot_id=orig_snapshot['id'])
        original_replica = self.shares_v2_client.list_share_replicas(
            snap_share["id"])[0]
        share_replica = self.create_share_replica(snap_share["id"],
                                                  self.replica_zone,
                                                  cleanup=False)
        self.addCleanup(self.delete_share_replica, original_replica['id'])
        self.shares_v2_client.wait_for_share_replica_status(
            share_replica['id'], constants.REPLICATION_STATE_IN_SYNC,
            status_attr='replica_state')
        self.promote_share_replica(share_replica['id'])
        # Delete the demoted replica so promoted replica can be cleaned
        # during the cleanup
        self.delete_share_replica(original_replica['id'])
