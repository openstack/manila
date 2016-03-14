# Copyright 2015 Yogesh Kshirsagar
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
@base.skip_if_microversion_lt(_MIN_SUPPORTED_MICROVERSION)
class ReplicationAdminTest(base.BaseSharesAdminTest):

    @classmethod
    def resource_setup(cls):
        super(ReplicationAdminTest, cls).resource_setup()
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
        cls.share = cls.create_share(share_type_id=cls.share_type["id"],
                                     availability_zone=cls.share_zone,)
        cls.replica = cls.shares_v2_client.list_share_replicas(
            share_id=cls.share['id'])[0]

    @staticmethod
    def _filter_share_replica_list(replica_list, r_state):
        # Iterate through replica list to filter based on replica_state
        return [replica['id'] for replica in replica_list
                if replica['replica_state'] == r_state]

    @test.attr(type=["gate", ])
    def test_promote_out_of_sync_share_replica(self):
        """Test promote 'out_of_sync' share replica to active state."""
        if (self.replication_type
                not in constants.REPLICATION_PROMOTION_CHOICES):
            msg = "Option backend_replication_type should be one of (%s)!"
            raise self.skipException(
                msg % ','.join(constants.REPLICATION_PROMOTION_CHOICES))
        share = self.create_share(share_type_id=self.share_type['id'])
        original_replica = self.shares_v2_client.list_share_replicas(
            share_id=share['id'])[0]

        # NOTE(Yogi1): Cleanup needs to be disabled for replica that is
        # being promoted since it will become the 'primary'/'active' replica.
        replica = self.create_share_replica(share["id"], self.replica_zone,
                                            cleanup=False)

        # List replicas
        replica_list = self.admin_client.list_share_replicas(
            share_id=share['id'])

        # Check if there is only 1 'active' replica before promotion.
        active_replicas = self._filter_share_replica_list(
            replica_list, constants.REPLICATION_STATE_ACTIVE)
        self.assertEqual(1, len(active_replicas))

        # Set replica_state to 'out_of_sync'
        self.admin_client.reset_share_replica_state(
            replica['id'], constants.REPLICATION_STATE_OUT_OF_SYNC)
        self.shares_v2_client.wait_for_share_replica_status(
            replica['id'], constants.REPLICATION_STATE_OUT_OF_SYNC,
            status_attr='replica_state')

        # Promote 'out_of_sync' replica to 'active' state.
        self.promote_share_replica(replica['id'], self.admin_client)
        # Original replica will need to be cleaned up before the promoted
        # replica can be deleted.
        self.addCleanup(self.delete_share_replica, original_replica['id'])

        # Check if there is still only 1 'active' replica after promotion.
        replica_list = self.shares_v2_client.list_share_replicas(
            share_id=self.share["id"])
        new_active_replicas = self._filter_share_replica_list(
            replica_list, constants.REPLICATION_STATE_ACTIVE)
        self.assertEqual(1, len(new_active_replicas))

    @test.attr(type=["gate", ])
    def test_force_delete_share_replica(self):
        """Test force deleting a replica that is in 'error_deleting' status."""
        replica = self.create_share_replica(self.share['id'],
                                            self.replica_zone,
                                            cleanup_in_class=False)
        self.admin_client.reset_share_replica_status(
            replica['id'], constants.STATUS_ERROR_DELETING)
        self.shares_v2_client.wait_for_share_replica_status(
            replica['id'], constants.STATUS_ERROR_DELETING)
        self.admin_client.force_delete_share_replica(replica['id'])
        self.shares_v2_client.wait_for_resource_deletion(
            replica_id=replica['id'])

    @test.attr(type=["gate", ])
    def test_reset_share_replica_status(self):
        """Test resetting a replica's 'status' attribute."""
        replica = self.create_share_replica(self.share['id'],
                                            self.replica_zone,
                                            cleanup_in_class=False)
        self.admin_client.reset_share_replica_status(replica['id'],
                                                     constants.STATUS_ERROR)
        self.shares_v2_client.wait_for_share_replica_status(
            replica['id'], constants.STATUS_ERROR)

    @test.attr(type=["gate", ])
    def test_reset_share_replica_state(self):
        """Test resetting a replica's 'replica_state' attribute."""
        replica = self.create_share_replica(self.share['id'],
                                            self.replica_zone,
                                            cleanup_in_class=False)
        self.admin_client.reset_share_replica_state(replica['id'],
                                                    constants.STATUS_ERROR)
        self.shares_v2_client.wait_for_share_replica_status(
            replica['id'], constants.STATUS_ERROR, status_attr='replica_state')

    @test.attr(type=["gate", ])
    def test_resync_share_replica(self):
        """Test resyncing a replica."""
        replica = self.create_share_replica(self.share['id'],
                                            self.replica_zone,
                                            cleanup_in_class=False)
        self.shares_v2_client.wait_for_share_replica_status(
            replica['id'], constants.REPLICATION_STATE_IN_SYNC,
            status_attr='replica_state')

        # Set replica_state to 'out_of_sync'.
        self.admin_client.reset_share_replica_state(
            replica['id'], constants.REPLICATION_STATE_OUT_OF_SYNC)
        self.shares_v2_client.wait_for_share_replica_status(
            replica['id'], constants.REPLICATION_STATE_OUT_OF_SYNC,
            status_attr='replica_state')

        # Attempt resync
        self.admin_client.resync_share_replica(replica['id'])
        self.shares_v2_client.wait_for_share_replica_status(
            replica['id'], constants.REPLICATION_STATE_IN_SYNC,
            status_attr='replica_state')
