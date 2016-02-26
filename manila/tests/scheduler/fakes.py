# Copyright 2011 OpenStack LLC.
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
Fakes For Scheduler tests.
"""

from oslo_utils import timeutils

from manila.scheduler.drivers import filter
from manila.scheduler import host_manager
from manila.scheduler.weighers import base_host as base_host_weigher

SHARE_SERVICES_NO_POOLS = [
    dict(id=1, host='host1', topic='share', disabled=False,
         availability_zone='zone1', updated_at=timeutils.utcnow()),
    dict(id=2, host='host2@back1', topic='share', disabled=False,
         availability_zone='zone1', updated_at=timeutils.utcnow()),
    dict(id=3, host='host2@back2', topic='share', disabled=False,
         availability_zone='zone2', updated_at=timeutils.utcnow()),
]

SERVICE_STATES_NO_POOLS = {
    'host1': dict(share_backend_name='AAA',
                  total_capacity_gb=512, free_capacity_gb=200,
                  timestamp=None, reserved_percentage=0,
                  provisioned_capacity_gb=312,
                  max_over_subscription_ratio=1.0,
                  thin_provisioning=False,
                  snapshot_support=False,
                  driver_handles_share_servers=False),
    'host2@back1': dict(share_backend_name='BBB',
                        total_capacity_gb=256, free_capacity_gb=100,
                        timestamp=None, reserved_percentage=0,
                        provisioned_capacity_gb=400,
                        max_over_subscription_ratio=2.0,
                        thin_provisioning=True,
                        snapshot_support=True,
                        driver_handles_share_servers=False),
    'host2@back2': dict(share_backend_name='CCC',
                        total_capacity_gb=10000, free_capacity_gb=700,
                        timestamp=None, reserved_percentage=0,
                        provisioned_capacity_gb=50000,
                        max_over_subscription_ratio=20.0,
                        thin_provisioning=True,
                        snapshot_support=True,
                        driver_handles_share_servers=False),
}

SHARE_SERVICES_WITH_POOLS = [
    dict(id=1, host='host1@AAA', topic='share', disabled=False,
         availability_zone='zone1', updated_at=timeutils.utcnow()),
    dict(id=2, host='host2@BBB', topic='share', disabled=False,
         availability_zone='zone1', updated_at=timeutils.utcnow()),
    dict(id=3, host='host3@CCC', topic='share', disabled=False,
         availability_zone='zone2', updated_at=timeutils.utcnow()),
    dict(id=4, host='host4@DDD', topic='share', disabled=False,
         availability_zone='zone3', updated_at=timeutils.utcnow()),
    # service on host5 is disabled
    dict(id=5, host='host5@EEE', topic='share', disabled=True,
         availability_zone='zone4', updated_at=timeutils.utcnow()),
    dict(id=5, host='host6@FFF', topic='share', disabled=True,
         availability_zone='zone5', updated_at=timeutils.utcnow()),
]

SHARE_SERVICE_STATES_WITH_POOLS = {
    'host1@AAA': dict(share_backend_name='AAA',
                      timestamp=None, reserved_percentage=0,
                      driver_handles_share_servers=False,
                      snapshot_support=True,
                      replication_type=None,
                      pools=[dict(pool_name='pool1',
                                  total_capacity_gb=51,
                                  free_capacity_gb=41,
                                  reserved_percentage=0,
                                  provisioned_capacity_gb=10,
                                  max_over_subscription_ratio=1.0,
                                  thin_provisioning=False)]),
    'host2@BBB': dict(share_backend_name='BBB',
                      timestamp=None, reserved_percentage=0,
                      driver_handles_share_servers=False,
                      snapshot_support=True,
                      replication_type=None,
                      pools=[dict(pool_name='pool2',
                                  total_capacity_gb=52,
                                  free_capacity_gb=42,
                                  reserved_percentage=0,
                                  provisioned_capacity_gb=60,
                                  max_over_subscription_ratio=2.0,
                                  thin_provisioning=True)]),
    'host3@CCC': dict(share_backend_name='CCC',
                      timestamp=None, reserved_percentage=0,
                      driver_handles_share_servers=False,
                      snapshot_support=True,
                      replication_type=None,
                      pools=[dict(pool_name='pool3',
                                  total_capacity_gb=53,
                                  free_capacity_gb=43,
                                  reserved_percentage=0,
                                  provisioned_capacity_gb=100,
                                  max_over_subscription_ratio=20.0,
                                  thin_provisioning=True,
                                  consistency_group_support='pool')]),
    'host4@DDD': dict(share_backend_name='DDD',
                      timestamp=None, reserved_percentage=0,
                      driver_handles_share_servers=False,
                      snapshot_support=True,
                      replication_type=None,
                      pools=[dict(pool_name='pool4a',
                                  total_capacity_gb=541,
                                  free_capacity_gb=441,
                                  reserved_percentage=0,
                                  provisioned_capacity_gb=800,
                                  max_over_subscription_ratio=2.0,
                                  thin_provisioning=True,
                                  consistency_group_support='host'),
                             dict(pool_name='pool4b',
                                  total_capacity_gb=542,
                                  free_capacity_gb=442,
                                  reserved_percentage=0,
                                  provisioned_capacity_gb=2000,
                                  max_over_subscription_ratio=10.0,
                                  thin_provisioning=True,
                                  consistency_group_support='host')]),
    'host5@EEE': dict(share_backend_name='EEE',
                      timestamp=None, reserved_percentage=0,
                      driver_handles_share_servers=False,
                      snapshot_support=True,
                      replication_type=None,
                      pools=[dict(pool_name='pool5a',
                                  total_capacity_gb=551,
                                  free_capacity_gb=451,
                                  reserved_percentage=0,
                                  provisioned_capacity_gb=100,
                                  max_over_subscription_ratio=1.0,
                                  thin_provisioning=False),
                             dict(pool_name='pool5b',
                                  total_capacity_gb=552,
                                  free_capacity_gb=452,
                                  reserved_percentage=0,
                                  provisioned_capacity_gb=100,
                                  max_over_subscription_ratio=1.0,
                                  thin_provisioning=False)]),
    'host6@FFF': dict(share_backend_name='FFF',
                      timestamp=None, reserved_percentage=0,
                      driver_handles_share_servers=False,
                      snapshot_support=True,
                      replication_type=None,
                      pools=[dict(pool_name='pool6a',
                                  total_capacity_gb='unknown',
                                  free_capacity_gb='unknown',
                                  reserved_percentage=0,
                                  provisioned_capacity_gb=100,
                                  max_over_subscription_ratio=1.0,
                                  thin_provisioning=False),
                             dict(pool_name='pool6b',
                                  total_capacity_gb='unknown',
                                  free_capacity_gb='unknown',
                                  reserved_percentage=0,
                                  provisioned_capacity_gb=100,
                                  max_over_subscription_ratio=1.0,
                                  thin_provisioning=False)]),
}


class FakeFilterScheduler(filter.FilterScheduler):
    def __init__(self, *args, **kwargs):
        super(FakeFilterScheduler, self).__init__(*args, **kwargs)
        self.host_manager = host_manager.HostManager()


class FakeHostManager(host_manager.HostManager):
    def __init__(self):
        super(FakeHostManager, self).__init__()

        self.service_states = {
            'host1': {'total_capacity_gb': 1024,
                      'free_capacity_gb': 1024,
                      'allocated_capacity_gb': 0,
                      'thin_provisioning': False,
                      'reserved_percentage': 10,
                      'timestamp': None,
                      'snapshot_support': True,
                      'replication_type': 'writable',
                      'replication_domain': 'endor',
                      },
            'host2': {'total_capacity_gb': 2048,
                      'free_capacity_gb': 300,
                      'allocated_capacity_gb': 1748,
                      'provisioned_capacity_gb': 1748,
                      'max_over_subscription_ratio': 2.0,
                      'thin_provisioning': True,
                      'reserved_percentage': 10,
                      'timestamp': None,
                      'snapshot_support': True,
                      'replication_type': 'readable',
                      'replication_domain': 'kashyyyk',
                      },
            'host3': {'total_capacity_gb': 512,
                      'free_capacity_gb': 256,
                      'allocated_capacity_gb': 256,
                      'provisioned_capacity_gb': 256,
                      'max_over_subscription_ratio': 2.0,
                      'thin_provisioning': False,
                      'consistency_group_support': 'host',
                      'reserved_percentage': 0,
                      'snapshot_support': True,
                      'timestamp': None,
                      },
            'host4': {'total_capacity_gb': 2048,
                      'free_capacity_gb': 200,
                      'allocated_capacity_gb': 1848,
                      'provisioned_capacity_gb': 1848,
                      'max_over_subscription_ratio': 1.0,
                      'thin_provisioning': True,
                      'reserved_percentage': 5,
                      'timestamp': None,
                      'snapshot_support': True,
                      'replication_type': 'dr',
                      'replication_domain': 'naboo',
                      },
            'host5': {'total_capacity_gb': 2048,
                      'free_capacity_gb': 500,
                      'allocated_capacity_gb': 1548,
                      'provisioned_capacity_gb': 1548,
                      'max_over_subscription_ratio': 1.5,
                      'thin_provisioning': True,
                      'reserved_percentage': 5,
                      'timestamp': None,
                      'snapshot_support': True,
                      'consistency_group_support': 'pool',
                      'replication_type': None,
                      },
            'host6': {'total_capacity_gb': 'unknown',
                      'free_capacity_gb': 'unknown',
                      'allocated_capacity_gb': 1548,
                      'thin_provisioning': False,
                      'reserved_percentage': 5,
                      'snapshot_support': True,
                      'timestamp': None,
                      },
        }


class FakeHostState(host_manager.HostState):
    def __init__(self, host, attribute_dict):
        super(FakeHostState, self).__init__(host)
        for (key, val) in attribute_dict.items():
            setattr(self, key, val)

FAKE_HOST_STRING_1 = 'openstack@BackendA#PoolX'
FAKE_HOST_STRING_2 = 'openstack@BackendB#PoolY'
FAKE_HOST_STRING_3 = 'openstack@BackendC#PoolZ'


def mock_host_manager_db_calls(mock_obj, disabled=None):
    services = [
        dict(id=1, host='host1', topic='share', disabled=False,
             availability_zone_id='zone1', updated_at=timeutils.utcnow()),
        dict(id=2, host='host2', topic='share', disabled=False,
             availability_zone_id='zone1', updated_at=timeutils.utcnow()),
        dict(id=3, host='host3', topic='share', disabled=False,
             availability_zone_id='zone2', updated_at=timeutils.utcnow()),
        dict(id=4, host='host4', topic='share', disabled=False,
             availability_zone_id='zone3', updated_at=timeutils.utcnow()),
        dict(id=5, host='host5', topic='share', disabled=False,
             availability_zone_id='zone3', updated_at=timeutils.utcnow()),
        dict(id=6, host='host6', topic='share', disabled=False,
             availability_zone_id='zone4', updated_at=timeutils.utcnow()),
    ]
    if disabled is None:
        mock_obj.return_value = services
    else:
        mock_obj.return_value = [service for service in services
                                 if service['disabled'] == disabled]


class FakeWeigher1(base_host_weigher.BaseHostWeigher):
    def __init__(self):
        pass


class FakeWeigher2(base_host_weigher.BaseHostWeigher):
    def __init__(self):
        pass


class FakeClass(object):
    def __init__(self):
        pass


def fake_replica_request_spec(**kwargs):
    request_spec = {
        'share_properties': {
            'id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
            'name': 'fakename',
            'size': 1,
            'share_network_id': '4ccd5318-65f1-11e5-9d70-feff819cdc9f',
            'availability_zone': 'fake_az',
            'replication_type': 'dr',
        },
        'share_instance_properties': {
            'id': '8d5566df-1e83-4373-84b8-6f8153a0ac41',
            'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
            'host': 'openstack@BackendZ#PoolA',
            'status': 'available',
            'availability_zone_id': 'f6e146d0-65f0-11e5-9d70-feff819cdc9f',
            'share_network_id': '4ccd5318-65f1-11e5-9d70-feff819cdc9f',
            'share_server_id': '53099868-65f1-11e5-9d70-feff819cdc9f',
        },
        'share_proto': 'nfs',
        'share_id': 'f0e4bb5e-65f0-11e5-9d70-feff819cdc9f',
        'snapshot_id': None,
        'share_type': 'fake_share_type',
        'consistency_group': None,
    }
    request_spec.update(kwargs)
    return request_spec


def get_fake_host(host_name=None):

    class FakeHost(object):
        def __init__(self, host_name=None):
            self.host = host_name or 'openstack@BackendZ#PoolA'

    class FakeWeightedHost(object):
        def __init__(self, host_name=None):
            self.obj = FakeHost(host_name=host_name)

    return FakeWeightedHost(host_name=host_name)
