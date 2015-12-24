# Copyright 2014 Mirantis Inc.
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

import six  # noqa
from tempest import config  # noqa
from tempest import test  # noqa
import testtools  # noqa

from manila_tempest_tests.tests.api import base

CONF = config.CONF


class ShareNetworkListMixin(object):

    @test.attr(type=["gate", "smoke", ])
    def test_list_share_networks(self):
        listed = self.shares_client.list_share_networks()
        any(self.sn_with_ldap_ss["id"] in sn["id"] for sn in listed)

        # verify keys
        keys = ["name", "id"]
        [self.assertIn(key, sn.keys()) for sn in listed for key in keys]

    @test.attr(type=["gate", "smoke", ])
    def test_list_share_networks_with_detail(self):
        listed = self.shares_client.list_share_networks_with_detail()
        any(self.sn_with_ldap_ss["id"] in sn["id"] for sn in listed)

        # verify keys
        keys = [
            "name", "id", "description", "network_type",
            "project_id", "cidr", "ip_version",
            "neutron_net_id", "neutron_subnet_id",
            "created_at", "updated_at", "segmentation_id",
        ]
        [self.assertIn(key, sn.keys()) for sn in listed for key in keys]

    @test.attr(type=["gate", "smoke", ])
    def test_list_share_networks_filter_by_ss(self):
        listed = self.shares_client.list_share_networks_with_detail(
            {'security_service_id': self.ss_ldap['id']})
        self.assertTrue(any(self.sn_with_ldap_ss['id'] == sn['id']
                            for sn in listed))
        for sn in listed:
            ss_list = self.shares_client.list_sec_services_for_share_network(
                sn['id'])
            self.assertTrue(any(ss['id'] == self.ss_ldap['id']
                                for ss in ss_list))

    @test.attr(type=["gate", "smoke", ])
    def test_list_share_networks_all_filter_opts(self):
        valid_filter_opts = {
            'created_before': '2002-10-10',
            'created_since': '2001-01-01',
            'neutron_net_id': '1111',
            'neutron_subnet_id': '2222',
            'network_type': 'vlan',
            'segmentation_id': 1000,
            'cidr': '10.0.0.0/24',
            'ip_version': 4,
            'name': 'sn_with_ldap_ss'
        }

        listed = self.shares_client.list_share_networks_with_detail(
            valid_filter_opts)
        self.assertTrue(any(self.sn_with_ldap_ss['id'] == sn['id']
                            for sn in listed))
        created_before = valid_filter_opts.pop('created_before')
        created_since = valid_filter_opts.pop('created_since')
        for sn in listed:
            self.assertTrue(all(sn[key] == value for key, value in
                                six.iteritems(valid_filter_opts)))
            self.assertTrue(sn['created_at'] <= created_before)
            self.assertTrue(sn['created_at'] >= created_since)


class ShareNetworksTest(base.BaseSharesTest, ShareNetworkListMixin):

    @classmethod
    def resource_setup(cls):
        super(ShareNetworksTest, cls).resource_setup()
        ss_data = cls.generate_security_service_data()
        cls.ss_ldap = cls.create_security_service(**ss_data)

        cls.data_sn_with_ldap_ss = {
            'name': 'sn_with_ldap_ss',
            'neutron_net_id': '1111',
            'neutron_subnet_id': '2222',
            'created_at': '2002-02-02',
            'updated_at': None,
            'network_type': 'vlan',
            'segmentation_id': 1000,
            'cidr': '10.0.0.0/24',
            'ip_version': 4,
            'description': 'fake description',
        }
        cls.sn_with_ldap_ss = cls.create_share_network(
            cleanup_in_class=True,
            **cls.data_sn_with_ldap_ss)

        cls.shares_client.add_sec_service_to_share_network(
            cls.sn_with_ldap_ss["id"],
            cls.ss_ldap["id"])

        cls.data_sn_with_kerberos_ss = {
            'name': 'sn_with_kerberos_ss',
            'created_at': '2003-03-03',
            'updated_at': None,
            'neutron_net_id': 'test net id',
            'neutron_subnet_id': 'test subnet id',
            'network_type': 'local',
            'segmentation_id': 2000,
            'cidr': '10.0.0.0/13',
            'ip_version': 6,
            'description': 'fake description',
        }

        cls.ss_kerberos = cls.create_security_service(
            ss_type='kerberos',
            **cls.data_sn_with_ldap_ss)

        cls.sn_with_kerberos_ss = cls.create_share_network(
            cleanup_in_class=True,
            **cls.data_sn_with_kerberos_ss)

        cls.shares_client.add_sec_service_to_share_network(
            cls.sn_with_kerberos_ss["id"],
            cls.ss_kerberos["id"])

    @test.attr(type=["gate", "smoke", ])
    def test_create_delete_share_network(self):
        # generate data for share network
        data = self.generate_share_network_data()

        # create share network
        created = self.shares_client.create_share_network(**data)
        self.assertDictContainsSubset(data, created)

        # Delete share_network
        self.shares_client.delete_share_network(created["id"])

    @test.attr(type=["gate", "smoke", ])
    def test_get_share_network(self):
        get = self.shares_client.get_share_network(self.sn_with_ldap_ss["id"])
        self.assertEqual('2002-02-02T00:00:00.000000', get['created_at'])
        data = self.data_sn_with_ldap_ss.copy()
        del data['created_at']
        self.assertDictContainsSubset(data, get)

    @test.attr(type=["gate", "smoke", ])
    def test_update_share_network(self):
        update_data = self.generate_share_network_data()
        updated = self.shares_client.update_share_network(
            self.sn_with_ldap_ss["id"],
            **update_data)
        self.assertDictContainsSubset(update_data, updated)

    @test.attr(type=["gate", "smoke"])
    @testtools.skipIf(
        not CONF.share.multitenancy_enabled, "Only for multitenancy.")
    def test_update_valid_keys_sh_server_exists(self):
        self.create_share(cleanup_in_class=False)
        update_dict = {
            "name": "new_name",
            "description": "new_description",
        }
        updated = self.shares_client.update_share_network(
            self.shares_client.share_network_id, **update_dict)
        self.assertDictContainsSubset(update_dict, updated)

    @test.attr(type=["gate", "smoke", ])
    def test_recreate_share_network(self):
        # generate data for share network
        data = self.generate_share_network_data()

        # create share network
        sn1 = self.shares_client.create_share_network(**data)
        self.assertDictContainsSubset(data, sn1)

        # Delete first share network
        self.shares_client.delete_share_network(sn1["id"])

        # create second share network with same data
        sn2 = self.shares_client.create_share_network(**data)
        self.assertDictContainsSubset(data, sn2)

        # Delete second share network
        self.shares_client.delete_share_network(sn2["id"])

    @test.attr(type=["gate", "smoke", ])
    def test_create_two_share_networks_with_same_net_and_subnet(self):
        # generate data for share network
        data = self.generate_share_network_data()

        # create first share network
        sn1 = self.create_share_network(**data)
        self.assertDictContainsSubset(data, sn1)

        # create second share network
        sn2 = self.create_share_network(**data)
        self.assertDictContainsSubset(data, sn2)
