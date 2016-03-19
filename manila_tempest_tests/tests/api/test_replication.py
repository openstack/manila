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
from manila_tempest_tests import utils

CONF = config.CONF
_MIN_SUPPORTED_MICROVERSION = '2.11'
SUMMARY_KEYS = ['share_id', 'id', 'replica_state', 'status']
DETAIL_KEYS = SUMMARY_KEYS + ['availability_zone', 'host', 'updated_at',
                              'share_network_id', 'created_at']


@testtools.skipUnless(CONF.share.run_replication_tests,
                      'Replication tests are disabled.')
@base.skip_if_microversion_lt(_MIN_SUPPORTED_MICROVERSION)
class ReplicationTest(base.BaseSharesTest):

    @classmethod
    def resource_setup(cls):
        super(ReplicationTest, cls).resource_setup()
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

        # Data for creating shares in parallel
        data = [cls.creation_data, cls.creation_data]
        cls.shares = cls.create_shares(data)
        cls.shares = [cls.shares_v2_client.get_share(s['id']) for s in
                      cls.shares]
        cls.instance_id1 = cls._get_instance(cls.shares[0])
        cls.instance_id2 = cls._get_instance(cls.shares[1])

        cls.access_type = "ip"
        cls.access_to = utils.rand_ip()

    @classmethod
    def _get_instance(cls, share):
        share_instances = cls.admin_client.get_instances_of_share(share["id"])
        return share_instances[0]["id"]

    def _verify_create_replica(self):
        # Create the replica
        share_replica = self.create_share_replica(self.shares[0]["id"],
                                                  self.replica_zone,
                                                  cleanup_in_class=False)
        share_replicas = self.shares_v2_client.list_share_replicas(
            share_id=self.shares[0]["id"])
        # Ensure replica is created successfully.
        replica_ids = [replica["id"] for replica in share_replicas]
        self.assertIn(share_replica["id"], replica_ids)
        return share_replica

    def _verify_active_replica_count(self, share_id):
        # List replicas
        replica_list = self.shares_v2_client.list_share_replicas(
            share_id=share_id)

        # Check if there is only 1 'active' replica before promotion.
        active_replicas = self._filter_replica_list(
            replica_list, constants.REPLICATION_STATE_ACTIVE)
        self.assertEqual(1, len(active_replicas))

    def _filter_replica_list(self, replica_list, r_state):
        # Iterate through replica list to filter based on replica_state
        return [replica for replica in replica_list
                if replica['replica_state'] == r_state]

    def _verify_config_and_set_access_rule_data(self):
        """Verify the access rule configuration is enabled for NFS.

        Set the data after verification.
        """
        protocol = self.shares_v2_client.share_protocol

        # TODO(Yogi1): Add access rules for other protocols.
        if not ((protocol.lower() == 'nfs') and
                (protocol in CONF.share.enable_ip_rules_for_protocols) and
                CONF.share.enable_ip_rules_for_protocols):
            message = "IP access rules are not supported for this protocol."
            raise self.skipException(message)

        access_type = "ip"
        access_to = utils.rand_ip()

        return access_type, access_to

    @test.attr(type=["gate", ])
    def test_add_delete_share_replica(self):
        # Create the replica
        share_replica = self._verify_create_replica()

        # Delete the replica
        self.delete_share_replica(share_replica["id"])

    @test.attr(type=["gate", ])
    def test_add_access_rule_create_replica_delete_rule(self):
        # Add access rule to the share
        access_type, access_to = self._verify_config_and_set_access_rule_data()
        rule = self.shares_v2_client.create_access_rule(
            self.shares[0]["id"], access_type, access_to, 'ro')
        self.shares_v2_client.wait_for_access_rule_status(
            self.shares[0]["id"], rule["id"], constants.RULE_STATE_ACTIVE)

        # Create the replica
        self._verify_create_replica()

        # Verify access_rules_status transitions to 'active' state.
        self.shares_v2_client.wait_for_share_status(
            self.shares[0]["id"], constants.RULE_STATE_ACTIVE,
            status_attr='access_rules_status')

        # Delete rule and wait for deletion
        self.shares_v2_client.delete_access_rule(self.shares[0]["id"],
                                                 rule["id"])
        self.shares_v2_client.wait_for_resource_deletion(
            rule_id=rule["id"], share_id=self.shares[0]['id'])

    @test.attr(type=["gate", ])
    def test_create_replica_add_access_rule_delete_replica(self):
        access_type, access_to = self._verify_config_and_set_access_rule_data()
        # Create the replica
        share_replica = self._verify_create_replica()

        # Add access rule
        self.shares_v2_client.create_access_rule(
            self.shares[0]["id"], access_type, access_to, 'ro')

        self.shares_v2_client.wait_for_share_status(
            self.shares[0]["id"], constants.RULE_STATE_ACTIVE,
            status_attr='access_rules_status')

        # Delete the replica
        self.delete_share_replica(share_replica["id"])

    @test.attr(type=["gate", ])
    def test_add_multiple_share_replicas(self):
        rep_domain, pools = self.get_pools_for_replication_domain()
        if len(pools) < 3:
            msg = ("Replication domain %(domain)s has only %(count)s pools. "
                   "Need at least 3 pools to run this test." %
                   {"domain": rep_domain, "count": len(pools)})
            raise self.skipException(msg)
        # Add the replicas
        share_replica1 = self.create_share_replica(self.shares[0]["id"],
                                                   self.replica_zone,
                                                   cleanup_in_class=False)
        share_replica2 = self.create_share_replica(self.shares[0]["id"],
                                                   self.replica_zone,
                                                   cleanup_in_class=False)
        self.shares_v2_client.get_share_replica(share_replica2['id'])

        share_replicas = self.shares_v2_client.list_share_replicas(
            share_id=self.shares[0]["id"])
        replica_host_set = {r['host'] for r in share_replicas}

        # Assert that replicas are created on different pools.
        msg = "More than one replica is created on the same pool."
        self.assertEqual(3, len(replica_host_set), msg)
        # Verify replicas are in the replica list
        replica_ids = [replica["id"] for replica in share_replicas]
        self.assertIn(share_replica1["id"], replica_ids)
        self.assertIn(share_replica2["id"], replica_ids)

    @test.attr(type=["gate", ])
    def test_promote_in_sync_share_replica(self):
        # Test promote 'in_sync' share_replica to 'active' state
        if (self.replication_type
                not in constants.REPLICATION_PROMOTION_CHOICES):
            msg = "Option backend_replication_type should be one of (%s)!"
            raise self.skipException(
                msg % ','.join(constants.REPLICATION_PROMOTION_CHOICES))
        share = self.create_shares([self.creation_data])[0]
        original_replica = self.shares_v2_client.list_share_replicas(
            share["id"])[0]
        # NOTE(Yogi1): Cleanup needs to be disabled for replica that is
        # being promoted since it will become the 'primary'/'active' replica.
        replica = self.create_share_replica(share["id"], self.replica_zone,
                                            cleanup=False)
        # Wait for replica state to update after creation
        self.shares_v2_client.wait_for_share_replica_status(
            replica['id'], constants.REPLICATION_STATE_IN_SYNC,
            status_attr='replica_state')
        # Promote the first in_sync replica to active state
        promoted_replica = self.promote_share_replica(replica['id'])
        # Delete the demoted replica so promoted replica can be cleaned
        # during the cleanup of the share.
        self.addCleanup(self.delete_share_replica, original_replica['id'])
        self._verify_active_replica_count(share["id"])
        # Verify the replica_state for promoted replica
        promoted_replica = self.shares_v2_client.get_share_replica(
            promoted_replica["id"])
        self.assertEqual(constants.REPLICATION_STATE_ACTIVE,
                         promoted_replica["replica_state"])

    @test.attr(type=["gate", ])
    def test_promote_and_promote_back(self):
        # Test promote back and forth between 2 share replicas
        if (self.replication_type
                not in constants.REPLICATION_PROMOTION_CHOICES):
            msg = "Option backend_replication_type should be one of (%s)!"
            raise self.skipException(
                msg % ','.join(constants.REPLICATION_PROMOTION_CHOICES))

        # Create a new share
        share = self.create_shares([self.creation_data])[0]

        # Discover the original replica
        initial_replicas = self.shares_v2_client.list_share_replicas(
            share_id=share['id'])
        self.assertEqual(1, len(initial_replicas),
                         '%s replicas initially created for share %s' %
                         (len(initial_replicas), share['id']))
        original_replica = initial_replicas[0]

        # Create a new replica
        new_replica = self.create_share_replica(share["id"],
                                                self.replica_zone,
                                                cleanup_in_class=False)
        self.shares_v2_client.wait_for_share_replica_status(
            new_replica['id'], constants.REPLICATION_STATE_IN_SYNC,
            status_attr='replica_state')

        # Promote the new replica to active and verify the replica states
        self.promote_share_replica(new_replica['id'])
        self._verify_active_replica_count(share["id"])
        self.shares_v2_client.wait_for_share_replica_status(
            original_replica['id'], constants.REPLICATION_STATE_IN_SYNC,
            status_attr='replica_state')

        # Promote the original replica back to active
        self.promote_share_replica(original_replica['id'])
        self._verify_active_replica_count(share["id"])
        self.shares_v2_client.wait_for_share_replica_status(
            new_replica['id'], constants.REPLICATION_STATE_IN_SYNC,
            status_attr='replica_state')

    @test.attr(type=["gate", ])
    def test_active_replication_state(self):
        # Verify the replica_state of first instance is set to active.
        replica = self.shares_v2_client.get_share_replica(self.instance_id1)
        self.assertEqual(
            constants.REPLICATION_STATE_ACTIVE, replica['replica_state'])


@testtools.skipUnless(CONF.share.run_replication_tests,
                      'Replication tests are disabled.')
@base.skip_if_microversion_lt(_MIN_SUPPORTED_MICROVERSION)
class ReplicationActionsTest(base.BaseSharesTest):

    @classmethod
    def resource_setup(cls):
        super(ReplicationActionsTest, cls).resource_setup()
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

        # Data for creating shares in parallel
        data = [cls.creation_data, cls.creation_data]
        cls.shares = cls.create_shares(data)
        cls.shares = [cls.shares_v2_client.get_share(s['id']) for s in
                      cls.shares]
        cls.instance_id1 = cls._get_instance(cls.shares[0])
        cls.instance_id2 = cls._get_instance(cls.shares[1])

        # Create replicas to 2 shares
        cls.replica1 = cls.create_share_replica(cls.shares[0]["id"],
                                                cls.replica_zone,
                                                cleanup_in_class=True)
        cls.replica2 = cls.create_share_replica(cls.shares[1]["id"],
                                                cls.replica_zone,
                                                cleanup_in_class=True)

    @classmethod
    def _get_instance(cls, share):
        share_instances = cls.admin_client.get_instances_of_share(share["id"])
        return share_instances[0]["id"]

    def _validate_replica_list(self, replica_list, detail=True):
        # Verify keys
        if detail:
            keys = DETAIL_KEYS
        else:
            keys = SUMMARY_KEYS
        for replica in replica_list:
            self.assertEqual(sorted(keys), sorted(replica.keys()))
            # Check for duplicates
            replica_id_list = [sr["id"] for sr in replica_list
                               if sr["id"] == replica["id"]]
            msg = "Replica %s appears %s times in replica list." % (
                replica['id'], len(replica_id_list))
            self.assertEqual(1, len(replica_id_list), msg)

    @test.attr(type=["gate", ])
    def test_show_share_replica(self):
        replica = self.shares_v2_client.get_share_replica(self.replica1["id"])

        actual_keys = sorted(list(replica.keys()))
        detail_keys = sorted(DETAIL_KEYS)
        self.assertEqual(detail_keys, actual_keys,
                         'Share Replica %s has incorrect keys; '
                         'expected %s, got %s.' % (replica["id"],
                                                   detail_keys, actual_keys))

    @test.attr(type=["gate", ])
    def test_detail_list_share_replicas_for_share(self):
        # List replicas for share
        replica_list = self.shares_v2_client.list_share_replicas(
            share_id=self.shares[0]["id"])
        replica_ids_list = [rep['id'] for rep in replica_list]
        self.assertIn(self.replica1['id'], replica_ids_list,
                      'Replica %s was not returned in the list of replicas: %s'
                      % (self.replica1['id'], replica_list))
        # Verify keys
        self._validate_replica_list(replica_list)

    @test.attr(type=["gate", ])
    def test_detail_list_share_replicas_for_all_shares(self):
        # List replicas for all available shares
        replica_list = self.shares_v2_client.list_share_replicas()
        replica_ids_list = [rep['id'] for rep in replica_list]
        for replica in [self.replica1, self.replica2]:
            self.assertIn(replica['id'], replica_ids_list,
                          'Replica %s was not returned in the list of '
                          'replicas: %s' % (replica['id'], replica_list))
        # Verify keys
        self._validate_replica_list(replica_list)

    @test.attr(type=["gate", ])
    def test_summary_list_share_replicas_for_all_shares(self):
        # List replicas
        replica_list = self.shares_v2_client.list_share_replicas_summary()

        # Verify keys
        self._validate_replica_list(replica_list, detail=False)
