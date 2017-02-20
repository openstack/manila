# Copyright 2016 Mirantis, Inc.
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
"""Some useful fakes."""

from manila.tests.db import fakes as db_fakes


def fake_share(**kwargs):
    share = {
        'id': 'fakeid',
        'share_id': 'fakeshareid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'NFS',
        'export_location': '127.0.0.1:/mnt/nfs/volume-00002',
    }
    share.update(kwargs)
    return db_fakes.FakeModel(share)


def fake_access(**kwargs):
    access = {
        'id': 'fakeaccid',
        'access_type': 'ip',
        'access_to': '10.0.0.2',
        'access_level': 'rw',
        'state': 'active',
    }
    access.update(kwargs)
    return db_fakes.FakeModel(access)


def fake_network(**kwargs):
    allocations = db_fakes.FakeModel({'id': 'fake_allocation_id',
                                      'ip_address': '127.0.0.0.1',
                                      'mac_address': 'fe:16:3e:61:e0:58'})
    network = {
        'id': 'fake_network_id',
        'server_id': 'fake_server_id',
        'network_allocations': [allocations],
        'neutron_net_id': 'fake_net',
        'neutron_subnet_id': 'fake_subnet',
    }
    network.update(kwargs)
    return db_fakes.FakeModel(network)
