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
"""Testing of SQLAlchemy model classes."""

import ddt

from manila.common import constants
from manila import context
from manila.db.sqlalchemy import api as db_api
from manila import test
from manila.tests import db_utils


@ddt.ddt
class ShareTestCase(test.TestCase):
    """Testing of SQLAlchemy Share model class."""

    @ddt.data(constants.STATUS_MANAGE_ERROR, constants.STATUS_CREATING,
              constants.STATUS_EXTENDING, constants.STATUS_DELETING,
              constants.STATUS_EXTENDING_ERROR,
              constants.STATUS_ERROR_DELETING, constants.STATUS_MANAGING,
              constants.STATUS_MANAGE_ERROR)
    def test_share_instance_available(self, status):

        instance_list = [
            db_utils.create_share_instance(status=constants.STATUS_AVAILABLE,
                                           share_id='fake_id'),
            db_utils.create_share_instance(status=status,
                                           share_id='fake_id')
        ]

        share1 = db_utils.create_share(instances=instance_list)
        share2 = db_utils.create_share(instances=list(reversed(instance_list)))

        self.assertEqual(constants.STATUS_AVAILABLE, share1.instance['status'])
        self.assertEqual(constants.STATUS_AVAILABLE, share2.instance['status'])

    @ddt.data([constants.STATUS_MANAGE_ERROR, constants.STATUS_CREATING],
              [constants.STATUS_ERROR_DELETING, constants.STATUS_DELETING],
              [constants.STATUS_ERROR, constants.STATUS_MANAGING],
              [constants.STATUS_UNMANAGE_ERROR, constants.STATUS_UNMANAGING],
              [constants.STATUS_INACTIVE, constants.STATUS_EXTENDING],
              [constants.STATUS_SHRINKING_ERROR, constants.STATUS_SHRINKING])
    @ddt.unpack
    def test_share_instance_not_transitional(self, status, trans_status):

        instance_list = [
            db_utils.create_share_instance(status=status,
                                           share_id='fake_id'),
            db_utils.create_share_instance(status=trans_status,
                                           share_id='fake_id')
        ]

        share1 = db_utils.create_share(instances=instance_list)
        share2 = db_utils.create_share(instances=list(reversed(instance_list)))

        self.assertEqual(status, share1.instance['status'])
        self.assertEqual(status, share2.instance['status'])

    def test_share_instance_creating(self):

        share = db_utils.create_share(status=constants.STATUS_CREATING)

        self.assertEqual(constants.STATUS_CREATING, share.instance['status'])

    @ddt.data(constants.STATUS_REPLICATION_CHANGE, constants.STATUS_AVAILABLE,
              constants.STATUS_ERROR, constants.STATUS_CREATING)
    def test_share_instance_reverting(self, status):

        instance_list = [
            db_utils.create_share_instance(
                status=constants.STATUS_REVERTING,
                share_id='fake_id'),
            db_utils.create_share_instance(
                status=status, share_id='fake_id'),
            db_utils.create_share_instance(
                status=constants.STATUS_ERROR_DELETING, share_id='fake_id'),
        ]

        share1 = db_utils.create_share(instances=instance_list)
        share2 = db_utils.create_share(instances=list(reversed(instance_list)))

        self.assertEqual(
            constants.STATUS_REVERTING, share1.instance['status'])
        self.assertEqual(
            constants.STATUS_REVERTING, share2.instance['status'])

    @ddt.data(constants.STATUS_AVAILABLE, constants.STATUS_ERROR,
              constants.STATUS_CREATING)
    def test_share_instance_replication_change(self, status):

        instance_list = [
            db_utils.create_share_instance(
                status=constants.STATUS_REPLICATION_CHANGE,
                share_id='fake_id'),
            db_utils.create_share_instance(
                status=status, share_id='fake_id'),
            db_utils.create_share_instance(
                status=constants.STATUS_ERROR_DELETING, share_id='fake_id')
        ]

        share1 = db_utils.create_share(instances=instance_list)
        share2 = db_utils.create_share(instances=list(reversed(instance_list)))

        self.assertEqual(
            constants.STATUS_REPLICATION_CHANGE, share1.instance['status'])
        self.assertEqual(
            constants.STATUS_REPLICATION_CHANGE, share2.instance['status'])

    def test_share_instance_prefer_active_instance(self):

        instance_list = [
            db_utils.create_share_instance(
                status=constants.STATUS_AVAILABLE,
                share_id='fake_id',
                replica_state=constants.REPLICA_STATE_IN_SYNC),
            db_utils.create_share_instance(
                status=constants.STATUS_CREATING,
                share_id='fake_id',
                replica_state=constants.REPLICA_STATE_OUT_OF_SYNC),
            db_utils.create_share_instance(
                status=constants.STATUS_ERROR, share_id='fake_id',
                replica_state=constants.REPLICA_STATE_ACTIVE),
            db_utils.create_share_instance(
                status=constants.STATUS_MANAGING, share_id='fake_id',
                replica_state=constants.REPLICA_STATE_ACTIVE),
        ]

        share1 = db_utils.create_share(instances=instance_list)
        share2 = db_utils.create_share(instances=list(reversed(instance_list)))

        self.assertEqual(
            constants.STATUS_ERROR, share1.instance['status'])
        self.assertEqual(
            constants.STATUS_ERROR, share2.instance['status'])

    def test_access_rules_status_no_instances(self):
        share = db_utils.create_share(instances=[])

        self.assertEqual(constants.STATUS_ACTIVE, share.access_rules_status)

    @ddt.data(constants.STATUS_ACTIVE, constants.SHARE_INSTANCE_RULES_SYNCING,
              constants.SHARE_INSTANCE_RULES_ERROR)
    def test_access_rules_status(self, access_status):
        instances = [
            db_utils.create_share_instance(
                share_id='fake_id', status=constants.STATUS_ERROR,
                access_rules_status=constants.STATUS_ACTIVE),
            db_utils.create_share_instance(
                share_id='fake_id', status=constants.STATUS_AVAILABLE,
                access_rules_status=constants.STATUS_ACTIVE),
            db_utils.create_share_instance(
                share_id='fake_id', status=constants.STATUS_AVAILABLE,
                access_rules_status=access_status),
        ]

        share = db_utils.create_share(instances=instances)

        self.assertEqual(access_status, share.access_rules_status)


@ddt.ddt
class ShareAccessTestCase(test.TestCase):
    """Testing of SQLAlchemy Share Access related model classes."""

    @ddt.data(constants.ACCESS_STATE_QUEUED_TO_APPLY,
              constants.ACCESS_STATE_ACTIVE, constants.ACCESS_STATE_ERROR,
              constants.ACCESS_STATE_APPLYING)
    def test_share_access_mapping_state(self, expected_status):
        ctxt = context.get_admin_context()

        share = db_utils.create_share()
        share_instances = [
            share.instance,
            db_utils.create_share_instance(share_id=share['id']),
            db_utils.create_share_instance(share_id=share['id']),
            db_utils.create_share_instance(share_id=share['id']),
        ]
        access_rule = db_utils.create_access(share_id=share['id'])

        # Update the access mapping states
        db_api.share_instance_access_update(
            ctxt, access_rule['id'], share_instances[0]['id'],
            {'state': constants.ACCESS_STATE_ACTIVE})
        db_api.share_instance_access_update(
            ctxt, access_rule['id'], share_instances[1]['id'],
            {'state': expected_status})
        db_api.share_instance_access_update(
            ctxt, access_rule['id'], share_instances[2]['id'],
            {'state': constants.ACCESS_STATE_ACTIVE})
        db_api.share_instance_access_update(
            ctxt, access_rule['id'], share_instances[3]['id'],
            {'deleted': 'True', 'state': constants.STATUS_DELETED})

        access_rule = db_api.share_access_get(ctxt, access_rule['id'])

        self.assertEqual(expected_status, access_rule['state'])


class ShareSnapshotTestCase(test.TestCase):
    """Testing of SQLAlchemy ShareSnapshot model class."""

    def test_instance_and_proxified_properties(self):

        in_sync_replica_instance = db_utils.create_share_instance(
            status=constants.STATUS_AVAILABLE, share_id='fake_id',
            replica_state=constants.REPLICA_STATE_IN_SYNC)
        active_replica_instance = db_utils.create_share_instance(
            status=constants.STATUS_AVAILABLE, share_id='fake_id',
            replica_state=constants.REPLICA_STATE_ACTIVE)
        out_of_sync_replica_instance = db_utils.create_share_instance(
            status=constants.STATUS_ERROR, share_id='fake_id',
            replica_state=constants.REPLICA_STATE_OUT_OF_SYNC)
        non_replica_instance = db_utils.create_share_instance(
            status=constants.STATUS_CREATING, share_id='fake_id')
        share_instances = [
            in_sync_replica_instance, active_replica_instance,
            out_of_sync_replica_instance, non_replica_instance,
        ]
        share = db_utils.create_share(instances=share_instances)
        snapshot_instance_list = [
            db_utils.create_snapshot_instance(
                'fake_snapshot_id',
                status=constants.STATUS_CREATING,
                share_instance_id=out_of_sync_replica_instance['id']),
            db_utils.create_snapshot_instance(
                'fake_snapshot_id',
                status=constants.STATUS_ERROR,
                share_instance_id=in_sync_replica_instance['id']),
            db_utils.create_snapshot_instance(
                'fake_snapshot_id',
                status=constants.STATUS_AVAILABLE,
                provider_location='hogsmeade:snapshot1',
                progress='87%',
                share_instance_id=active_replica_instance['id']),
            db_utils.create_snapshot_instance(
                'fake_snapshot_id',
                status=constants.STATUS_MANAGING,
                share_instance_id=non_replica_instance['id']),
        ]
        snapshot = db_utils.create_snapshot(
            id='fake_snapshot_id', share_id=share['id'],
            instances=snapshot_instance_list)

        # Proxified properties
        self.assertEqual(constants.STATUS_AVAILABLE, snapshot['status'])
        self.assertEqual(constants.STATUS_ERROR, snapshot['aggregate_status'])
        self.assertEqual('hogsmeade:snapshot1', snapshot['provider_location'])
        self.assertEqual('87%', snapshot['progress'])

        # Snapshot properties
        expected_share_name = '-'.join(['share', share['id']])
        self.assertEqual(expected_share_name, snapshot['share_name'])
        self.assertEqual(active_replica_instance['id'],
                         snapshot['instance']['share_instance_id'])
