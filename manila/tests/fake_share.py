# Copyright 2013 OpenStack Foundation
# Copyright 2015 Intel, Inc.
# All Rights Reserved
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
import datetime
import uuid

from manila.common import constants
from manila.db.sqlalchemy import models
from manila.tests.db import fakes as db_fakes


def fake_share(**kwargs):

    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'fake_proto',
        'share_network_id': 'fake share network id',
        'share_server_id': 'fake share server id',
        'share_type_id': 'fake share type id',
        'export_location': 'fake_location:/fake_share',
        'project_id': 'fake_project_uuid',
        'availability_zone': 'fake_az',
        'snapshot_support': 'True',
        'replication_type': None,
        'is_busy': False,
        'consistency_group_id': 'fakecgid',
        'instance': {'host': 'fakehost'},
    }
    share.update(kwargs)
    return db_fakes.FakeModel(share)


def fake_share_instance(base_share=None, **kwargs):
    if base_share is None:
        share = fake_share()
    else:
        share = base_share

    share_instance = {
        'share_id': share['id'],
        'id': "fakeinstanceid",
        'status': "active",
    }

    for attr in models.ShareInstance._proxified_properties:
        share_instance[attr] = getattr(share, attr, None)

    return db_fakes.FakeModel(share_instance)


def fake_share_type(**kwargs):

    share_type = {
        'id': "fakesharetype",
        'name': "fakesharetypename",
        'is_public': False,
        'extra_specs': {
            'driver_handles_share_servers': 'False',
            'snapshot_support': 'True',
        }
    }

    extra_specs = kwargs.pop('extra_specs', {})

    for key, value in extra_specs.items():
        share_type['extra_specs'][key] = value

    share_type.update(kwargs)

    return db_fakes.FakeModel(share_type)


def fake_snapshot(create_instance=False, **kwargs):

    instance_keys = ('instance_id', 'snapshot_id', 'share_instance_id',
                     'status', 'progress', 'provider_location')
    snapshot_keys = ('id', 'share_name', 'share_id', 'name', 'share_size',
                     'share_proto', 'instance', 'aggregate_status')

    instance_kwargs = {k: kwargs.get(k) for k in instance_keys if k in kwargs}
    snapshot_kwargs = {k: kwargs.get(k) for k in snapshot_keys if k in kwargs}

    aggregate_status = snapshot_kwargs.get(
        'aggregate_status', instance_kwargs.get(
            'status', constants.STATUS_CREATING))

    snapshot = {
        'id': 'fakesnapshotid',
        'share_name': 'fakename',
        'share_id': 'fakeid',
        'name': 'fakesnapshotname',
        'share_size': 1,
        'share_proto': 'fake_proto',
        'instance': None,
        'share': 'fake_share',
        'aggregate_status': aggregate_status,
    }
    snapshot.update(snapshot_kwargs)
    if create_instance:
        if 'instance_id' in instance_kwargs:
            instance_kwargs['id'] = instance_kwargs.pop('instance_id')
        snapshot['instance'] = fake_snapshot_instance(
            base_snapshot=snapshot, **instance_kwargs)
        snapshot['status'] = snapshot['instance']['status']
        snapshot['provider_location'] = (
            snapshot['instance']['provider_location']
        )
        snapshot['progress'] = snapshot['instance']['progress']
    else:
        snapshot['status'] = constants.STATUS_AVAILABLE
        snapshot['progress'] = '0%'
        snapshot['provider_location'] = 'fake'
        snapshot.update(instance_kwargs)

    return db_fakes.FakeModel(snapshot)


def fake_snapshot_instance(base_snapshot=None, **kwargs):
    if base_snapshot is None:
        base_snapshot = fake_snapshot()
    snapshot_instance = {
        'id': 'fakesnapshotinstanceid',
        'snapshot_id': base_snapshot['id'],
        'status': constants.STATUS_CREATING,
        'progress': '0%',
        'provider_location': 'i_live_here_actually',
        'share_name': 'fakename',
        'share_id': 'fakeshareinstanceid',
        'share_instance_id': 'fakeshareinstanceid',
    }
    snapshot_instance.update(kwargs)
    return db_fakes.FakeModel(snapshot_instance)


def expected_snapshot(id='fake_snapshot_id', **kwargs):
    self_link = 'http://localhost/v1/fake/snapshots/%s' % id
    bookmark_link = 'http://localhost/fake/snapshots/%s' % id
    snapshot = {
        'id': id,
        'share_id': 'fakeshareid',
        'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
        'status': 'fakesnapstatus',
        'name': 'displaysnapname',
        'description': 'displaysnapdesc',
        'share_size': 1,
        'size': 1,
        'share_proto': 'fakesnapproto',
        'links': [
            {
                'href': self_link,
                'rel': 'self',
            },
            {
                'href': bookmark_link,
                'rel': 'bookmark',
            },
        ],
    }
    snapshot.update(kwargs)
    return {'snapshot': snapshot}


def search_opts(**kwargs):
    search_opts = {
        'name': 'fake_name',
        'status': 'fake_status',
        'share_id': 'fake_share_id',
        'sort_key': 'fake_sort_key',
        'sort_dir': 'fake_sort_dir',
        'offset': '1',
        'limit': '1',
    }
    search_opts.update(kwargs)
    return search_opts


def fake_access(**kwargs):
    access = {
        'id': 'fakeaccid',
        'access_type': 'ip',
        'access_to': '10.0.0.1',
        'access_level': 'rw',
        'state': 'active',
    }
    access.update(kwargs)
    return db_fakes.FakeModel(access)


def fake_replica(id=None, as_primitive=True, for_manager=False, **kwargs):
    replica = {
        'id': id or str(uuid.uuid4()),
        'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
        'deleted': False,
        'host': 'openstack@BackendZ#PoolA',
        'status': 'available',
        'scheduled_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
        'launched_at': datetime.datetime(2015, 8, 10, 0, 5, 58),
        'terminated_at': None,
        'replica_state': None,
        'availability_zone_id': 'f6e146d0-65f0-11e5-9d70-feff819cdc9f',
        'export_locations': [{'path': 'path1'}, {'path': 'path2'}],
        'share_network_id': '4ccd5318-65f1-11e5-9d70-feff819cdc9f',
        'share_server_id': '53099868-65f1-11e5-9d70-feff819cdc9f',
        'access_rules_status': 'out_of_sync',
    }
    if for_manager:
        replica.update({
            'user_id': None,
            'project_id': None,
            'share_type_id': None,
            'size': None,
            'display_name': None,
            'display_description': None,
            'snapshot_id': None,
            'share_proto': None,
            'is_public': None,
            'consistency_group_id': None,
            'source_cgsnapshot_member_id': None,
            'availability_zone': 'fake_az',
        })
    replica.update(kwargs)
    if as_primitive:
        return replica
    else:
        return db_fakes.FakeModel(replica)


def fake_replica_request_spec(as_primitive=True, **kwargs):
    replica = fake_replica(id='9c0db763-a109-4862-b010-10f2bd395295')
    all_replica_hosts = ','.join(['fake_active_replica_host', replica['host']])
    request_spec = {
        'share_properties': fake_share(
            id='f0e4bb5e-65f0-11e5-9d70-feff819cdc9f'),
        'share_instance_properties': replica,
        'share_proto': 'nfs',
        'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
        'snapshot_id': None,
        'share_type': 'fake_share_type',
        'consistency_group': None,
        'active_replica_host': 'fake_active_replica_host',
        'all_replica_hosts': all_replica_hosts,
    }
    request_spec.update(kwargs)
    if as_primitive:
        return request_spec
    else:
        return db_fakes.FakeModel(request_spec)
