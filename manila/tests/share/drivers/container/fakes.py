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

FAKE_VSCTL_LIST_INTERFACES_X = (
    'fake stuff\n'
    'foo not_a_veth something_fake bar\n'
    'foo veth11b2c34 something_fake bar\n'
    'foo veth25f6g7h manila-container="fake1" bar\n'
    'foo veth3jd83j7 manila-container="my_container" bar\n'
    'foo veth4i9j10k manila-container="fake2" bar\n'
    'more fake stuff\n'
)

FAKE_VSCTL_LIST_INTERFACES = (
    'fake stuff\n'
    'foo not_a_veth something_fake bar\n'
    'foo veth11b2c34 something_fake bar\n'
    'foo veth25f6g7h manila-container="fake1" bar\n'
    'foo veth3jd83j7 manila-container="manila_my_container" bar\n'
    'foo veth4i9j10k manila-container="fake2" bar\n'
    'more fake stuff\n'
)

FAKE_VSCTL_LIST_INTERFACE_1 = (
    'fake stuff\n'
    'foo veth11b2c34 something_fake bar\n'
    'more fake stuff\n'
)

FAKE_VSCTL_LIST_INTERFACE_2 = (
    'fake stuff\n'
    'foo veth25f6g7h manila-container="fake1" bar\n'
    'more fake stuff\n'
)

FAKE_VSCTL_LIST_INTERFACE_3_X = (
    'fake stuff\n'
    'foo veth3jd83j7 manila-container="my_container" bar\n'
    'more fake stuff\n'
)

FAKE_VSCTL_LIST_INTERFACE_3 = (
    'fake stuff\n'
    'foo veth3jd83j7 manila-container="manila_my_container" bar\n'
    'more fake stuff\n'
)

FAKE_VSCTL_LIST_INTERFACE_4 = (
    'fake stuff\n'
    'foo veth4i9j10k manila-container="fake2" bar\n'
    'more fake stuff\n'
)

FAKE_IP_LINK_SHOW = (
    ('1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN '
     'mode DEFAULT group default qlen 1000\\    link/loopback '
     '00:00:00:00:00:00 brd 00:00:00:00:00:00\n'
     '13: eth0@if16: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue '
     'state UP mode DEFAULT group default \\    link/ether 02:42:ac:15:00:02 '
     'brd ff:ff:ff:ff:ff:ff\n'
     '15: eth1@if14: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue '
     'state UP mode DEFAULT group default \\    link/ether 02:42:ac:14:00:02 '
     'brd ff:ff:ff:ff:ff:ff\n', '')
)

FAKE_IP_LINK_SHOW_MASTER = (
    ('16: fake_veth@if14: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc '
     'noqueue master br-a7d71c3e77c2 state UP mode DEFAULT group default\n'
     '    link/ether 4a:10:0c:f2:d2:2c brd ff:ff:ff:ff:ff:ff link-netnsid 0\n',
     '')
)

FAKE_IP_ADDR_SHOW = (
    [('283: eth0    inet 192.168.144.19/24 brd 192.168.144.255 scope global '
      'eth0\\       valid_lft forever preferred_lft forever', ''),
     ('287: eth1    inet 10.0.0.131/8 brd 8.255.255.255 scope global eth1\\   '
      '    valid_lft forever preferred_lft forever', '')]
)

FAKE_DOCKER_INSPECT_NETWORKS = (
    ('{"fake_docker_network_0":{"IPAMConfig":{},"Links":null,"Aliases":'
     '["dab16d2703dc"],"NetworkID":'
     '"cf8c7cb5cecda1ef8240921d5d09e2a1bf9e308a0261459f5a69114cd4e6283c",'
     '"EndpointID":'
     '"312a035f32be713c7b56093dde2beec950785ddeb29c9bd18018d43ffd4f64bd",'
     '"Gateway":"10.10.10.1","IPAddress":"10.10.10.10","IPPrefixLen":24,'
     '"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,'
     '"MacAddress":"10:10:10:10:10:10","DriverOpts":{}},'
     '"fake_docker_network_1":{"IPAMConfig":{},"Links":null,"Aliases":'
     '["dab16d2703dc"],"NetworkID":'
     '"e978d91d70c30695557018c8847a551267e99c083063391c07dc9a730bfef9dc",'
     '"EndpointID":'
     '"8e34044764cd52b9d092ac66af8fb7130cdd423b521c3bf6e57b8095f6f0a085",'
     '"Gateway":"20.20.20.1","IPAddress":"20.20.20.20","IPPrefixLen":24,'
     '"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,'
     '"MacAddress":"20:20:20:20:20:20","DriverOpts":{}}}', '')
)


def fake_share(**kwargs):
    share = {
        'id': 'fakeid',
        'share_id': 'fakeshareid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'NFS',
        'host': 'host@backend#vg',
        'export_location': '127.0.0.1:/mnt/nfs/volume-00002',
    }
    share.update(kwargs)
    return db_fakes.FakeModel(share)


def fake_share_instances(**kwargs):
    share_instances = {
        'id': 'fakeid',
        'share_id': 'fakeshareid',
        'host': 'host@backend#vg',
        'export_location': '127.0.0.1:/mnt/nfs/volume-00002',
    }
    share_instances.update(kwargs)
    return [db_fakes.FakeModel(share_instances)]


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
        'neutron_subnet_id': 'fake_subnet'
    }
    network.update(kwargs)
    return [db_fakes.FakeModel(network)]


def fake_network_with_security_services(**kwargs):
    allocations = db_fakes.FakeModel({'id': 'fake_allocation_id',
                                      'ip_address': '127.0.0.0.1',
                                      'mac_address': 'fe:16:3e:61:e0:58'})
    security_services = db_fakes.FakeModel({'status': 'fake_status',
                                            'id': 'fake_security_service_id',
                                            'project_id': 'fake_project_id',
                                            'type': 'fake_type',
                                            'name': 'fake_name'})
    network = {
        'id': 'fake_network_id',
        'server_id': 'fake_server_id',
        'network_allocations': [allocations],
        'neutron_net_id': 'fake_net',
        'neutron_subnet_id': 'fake_subnet',
        'security_services': [security_services],
    }
    network.update(kwargs)
    return [db_fakes.FakeModel(network)]


def fake_share_server(**kwargs):
    share_server = {
        'id': 'fake'
    }
    share_server.update(kwargs)
    return db_fakes.FakeModel(share_server)


def fake_identifier():
    return '7cf7c200-d3af-4e05-b87e-9167c95dfcad'


def fake_share_no_export_location(**kwargs):
    share = {
        'share_id': 'fakeshareid',
    }
    share.update(kwargs)
    return db_fakes.FakeModel(share)


def fake_current_network_allocations():
    current_network_allocations = {
        'subnets': [
            {
                'network_allocations': [
                    {
                        'id': 'fake_id_current',
                        'ip_address': '192.168.144.100',
                    }
                ]
            }
        ]
    }

    return current_network_allocations


def fake_new_network_allocations():
    new_network_allocations = {
        'network_allocations': [
            {
                'id': 'fake_id_new',
                'ip_address': '10.0.0.100',
            }
        ]
    }

    return new_network_allocations
