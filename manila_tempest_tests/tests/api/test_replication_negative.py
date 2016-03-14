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
from tempest.lib import exceptions as lib_exc
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
class ReplicationNegativeTest(base.BaseSharesTest):

    @classmethod
    def resource_setup(cls):
        super(ReplicationNegativeTest, cls).resource_setup()
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
        cls.share1, cls.instance_id1 = cls._create_share_get_instance()

    @classmethod
    def _create_share_get_instance(cls):
        share = cls.create_share(share_type_id=cls.share_type["id"],
                                 availability_zone=cls.share_zone,)
        share_instances = cls.admin_client.get_instances_of_share(
            share["id"], version=_MIN_SUPPORTED_MICROVERSION
        )
        instance_id = share_instances[0]["id"]
        return share, instance_id

    def _is_replication_type_promotable(self):
        if (self.replication_type
                not in constants.REPLICATION_PROMOTION_CHOICES):
            msg = "Option backend_replication_type should be one of (%s)!"
            raise self.skipException(
                msg % ','.join(constants.REPLICATION_PROMOTION_CHOICES))

    @test.attr(type=["gate", "negative", ])
    def test_try_add_replica_to_share_with_no_replication_share_type(self):
        # Create share without replication type
        share = self.create_share()
        self.assertRaises(lib_exc.BadRequest,
                          self.create_share_replica,
                          share['id'],
                          self.replica_zone)

    @test.attr(type=["gate", "negative", ])
    def test_add_replica_to_share_with_error_state(self):
        # Set "error" state
        self.admin_client.reset_state(
            self.share1['id'], constants.STATUS_ERROR)
        self.addCleanup(self.admin_client.reset_state,
                        self.share1['id'],
                        constants.STATUS_AVAILABLE)
        self.assertRaises(lib_exc.BadRequest,
                          self.create_share_replica,
                          self.share1['id'],
                          self.replica_zone)

    @test.attr(type=["gate", "negative", ])
    def test_get_replica_by_nonexistent_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.get_share_replica,
                          data_utils.rand_uuid())

    @test.attr(type=["gate", "negative", ])
    def test_try_delete_replica_by_nonexistent_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.shares_v2_client.delete_share_replica,
                          data_utils.rand_uuid())

    @test.attr(type=["gate", "negative", ])
    def test_try_delete_last_active_replica(self):
        self.assertRaises(lib_exc.BadRequest,
                          self.shares_v2_client.delete_share_replica,
                          self.instance_id1)

    @test.attr(type=["gate", "negative", ])
    def test_try_delete_share_having_replica(self):
        self.create_share_replica(self.share1["id"], self.replica_zone,
                                  cleanup_in_class=False)
        self.assertRaises(lib_exc.Conflict,
                          self.shares_v2_client.delete_share,
                          self.share1["id"])

    @test.attr(type=["negative", "gate", ])
    def test_promote_out_of_sync_share_replica(self):
        # Test promoting an out_of_sync share_replica to active state
        self._is_replication_type_promotable()
        share, instance_id = self._create_share_get_instance()
        replica = self.create_share_replica(share["id"], self.replica_zone,
                                            cleanup_in_class=False)
        # Set replica state to out of sync
        self.admin_client.reset_share_replica_state(
            replica['id'], constants.REPLICATION_STATE_OUT_OF_SYNC)
        self.shares_v2_client.wait_for_share_replica_status(
            replica['id'], constants.REPLICATION_STATE_OUT_OF_SYNC,
            status_attr='replica_state')
        # Try promoting the first out_of_sync replica to active state
        self.assertRaises(lib_exc.Forbidden,
                          self.shares_v2_client.promote_share_replica,
                          replica['id'])

    @test.attr(type=["negative", "gate", ])
    def test_promote_active_share_replica(self):
        # Test promote active share_replica
        self._is_replication_type_promotable()

        # Try promoting the active replica
        self.shares_v2_client.promote_share_replica(self.instance_id1,
                                                    expected_status=200)

    @test.attr(type=["negative", "gate", ])
    def test_promote_share_replica_for_writable_share_type(self):
        # Test promote active share_replica for writable share
        if self.replication_type != "writable":
            raise self.skipException("Option backend_replication_type "
                                     "should be writable!")
        share, instance_id = self._create_share_get_instance()
        replica = self.create_share_replica(share["id"], self.replica_zone,
                                            cleanup_in_class=False)
        # By default, 'writable' replica is expected to be in active state
        self.shares_v2_client.wait_for_share_replica_status(
            replica["id"], constants.REPLICATION_STATE_ACTIVE,
            status_attr='replica_state')

        # Try promoting the replica
        self.shares_v2_client.promote_share_replica(replica['id'])
