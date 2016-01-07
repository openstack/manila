# Copyright 2013 OpenStack Foundation
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

import uuid

from oslo_config import cfg

CONF = cfg.CONF


class FakeNetwork(object):
    def __init__(self, **kwargs):
        self.id = kwargs.pop('id', 'fake_net_id')
        self.name = kwargs.pop('name', 'net_name')
        self.subnets = kwargs.pop('subnets', [])
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __getitem__(self, attr):
        return getattr(self, attr)


class FakeSubnet(object):
    def __init__(self, **kwargs):
        self.id = kwargs.pop('id', 'fake_subnet_id')
        self.network_id = kwargs.pop('network_id', 'fake_net_id')
        self.cidr = kwargs.pop('cidr', 'fake_cidr')
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __getitem__(self, attr):
        return getattr(self, attr)


class FakePort(object):
    def __init__(self, **kwargs):
        self.id = kwargs.pop('id', 'fake_subnet_id')
        self.network_id = kwargs.pop('network_id', 'fake_net_id')
        self.fixed_ips = kwargs.pop('fixed_ips', [])
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __getitem__(self, attr):
        return getattr(self, attr)


class FakeRouter(object):
    def __init__(self, **kwargs):
        self.id = kwargs.pop('id', 'fake_router_id')
        self.name = kwargs.pop('name', 'fake_router_name')
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __getitem__(self, attr):
        return getattr(self, attr)

    def __setitem__(self, attr, value):
        setattr(self, attr, value)


class FakeDeviceAddr(object):
    def __init__(self, list_of_addresses=None):
        self.addresses = list_of_addresses or [
            dict(ip_version=4, cidr='1.0.0.0/27'),
            dict(ip_version=4, cidr='2.0.0.0/27'),
            dict(ip_version=6, cidr='3.0.0.0/27'),
        ]

    def list(self):
        return self.addresses


class FakeDevice(object):
    def __init__(self, name=None, list_of_addresses=None):
        self.addr = FakeDeviceAddr(list_of_addresses)
        self.name = name or 'fake_device_name'


class API(object):
    """Fake Network API."""
    admin_project_id = 'fake_admin_project_id'

    network = {
        "status": "ACTIVE",
        "subnets": ["fake_subnet_id"],
        "name": "fake_network",
        "tenant_id": "fake_tenant_id",
        "shared": False,
        "id": "fake_id",
        "router:external": False,
    }

    port = {
        "status": "ACTIVE",
        "allowed_address_pairs": [],
        "admin_state_up": True,
        "network_id": "fake_network_id",
        "tenant_id": "fake_tenant_id",
        "extra_dhcp_opts": [],
        "device_owner": "fake",
        "binding:capabilities": {"port_filter": True},
        "mac_address": "00:00:00:00:00:00",
        "fixed_ips": [
            {"subnet_id": "56537094-98d7-430a-b513-81c4dc6d9903",
             "ip_address": "10.12.12.10"}
        ],
        "id": "fake_port_id",
        "security_groups": ["fake_sec_group_id"],
        "device_id": "fake_device_id"
    }

    def get_all_admin_project_networks(self):
        net1 = self.network.copy()
        net1['tenant_id'] = self.admin_project_id
        net1['id'] = str(uuid.uuid4())

        net2 = self.network.copy()
        net2['tenant_id'] = self.admin_project_id
        net2['id'] = str(uuid.uuid4())
        return [net1, net2]

    def create_port(self, tenant_id, network_id, subnet_id=None,
                    fixed_ip=None, device_owner=None, device_id=None):
        port = self.port.copy()
        port['network_id'] = network_id
        port['admin_state_up'] = True
        port['tenant_id'] = tenant_id
        if fixed_ip:
            fixed_ip_dict = {'ip_address': fixed_ip}
            if subnet_id:
                fixed_ip_dict.update({'subnet_id': subnet_id})
            port['fixed_ips'] = [fixed_ip_dict]
        if device_owner:
            port['device_owner'] = device_owner
        if device_id:
            port['device_id'] = device_id
        return port

    def list_ports(self, **search_opts):
        """List ports for the client based on search options."""
        ports = []
        for i in range(2):
            ports.append(self.port.copy())
        for port in ports:
            port['id'] = str(uuid.uuid4())
            for key, val in search_opts.items():
                port[key] = val
            if 'id' in search_opts:
                return ports
        return ports

    def show_port(self, port_id):
        """Return the port for the client given the port id."""
        port = self.port.copy()
        port['id'] = port_id
        return port

    def delete_port(self, port_id):
        pass

    def get_subnet(self, subnet_id):
        pass

    def subnet_create(self, *args, **kwargs):
        pass

    def router_add_interface(self, *args, **kwargs):
        pass

    def show_router(self, *args, **kwargs):
        pass

    def update_port_fixed_ips(self, *args, **kwargs):
        pass

    def router_remove_interface(self, *args, **kwargs):
        pass

    def update_subnet(self, *args, **kwargs):
        pass

    def get_all_networks(self):
        """Get all networks for client."""
        net1 = self.network.copy()
        net2 = self.network.copy()
        net1['id'] = str(uuid.uuid4())
        net2['id'] = str(uuid.uuid4())
        return [net1, net2]

    def get_network(self, network_uuid):
        """Get specific network for client."""
        network = self.network.copy()
        network['id'] = network_uuid
        return network

    def network_create(self, tenant_id, name):
        network = self.network.copy()
        network['tenant_id'] = tenant_id
        network['name'] = name
        return network
