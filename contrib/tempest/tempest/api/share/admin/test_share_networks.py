# Copyright 2014 Mirantis Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from tempest.api.share import base
from tempest.api.share import test_share_networks
from tempest import test


class ShareNetworkAdminTest(
        base.BaseSharesAdminTest,
        test_share_networks.ShareNetworkListMixin):

    @classmethod
    def resource_setup(cls):
        super(ShareNetworkAdminTest, cls).resource_setup()
        ss_data = cls.generate_security_service_data()
        resp, cls.ss_ldap = cls.create_security_service(**ss_data)

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
        __, cls.sn_with_ldap_ss = cls.create_share_network(
            cleanup_in_class=True,
            **cls.data_sn_with_ldap_ss)

        resp, body = cls.shares_client.add_sec_service_to_share_network(
            cls.sn_with_ldap_ss["id"],
            cls.ss_ldap["id"])

        cls.isolated_client = cls.get_client_with_isolated_creds(
            type_of_creds='alt')
        cls.data_sn_with_kerberos_ss = {
            'name': 'sn_with_kerberos_ss',
            'neutron_net_id': '3333',
            'neutron_subnet_id': '4444',
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

        resp, cls.ss_kerberos = cls.isolated_client.create_security_service(
            ss_type='kerberos',
            **cls.data_sn_with_ldap_ss)

        __, cls.sn_with_kerberos_ss = cls.isolated_client.create_share_network(
            cleanup_in_class=True,
            **cls.data_sn_with_kerberos_ss)

        resp, body = cls.isolated_client.add_sec_service_to_share_network(
            cls.sn_with_kerberos_ss["id"],
            cls.ss_kerberos["id"])

    @test.attr(type=["gate", "smoke", ])
    def test_list_share_networks_all_tenants(self):
        resp, listed = self.shares_client.list_share_networks_with_detail(
            {'all_tenants': 1})
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertTrue(any(self.sn_with_ldap_ss['id'] == sn['id']
                            for sn in listed))
        self.assertTrue(any(self.sn_with_kerberos_ss['id'] == sn['id']
                            for sn in listed))

    @test.attr(type=["gate", "smoke", ])
    def test_list_share_networks_filter_by_project_id(self):
        resp, listed = self.shares_client.list_share_networks_with_detail(
            {'project_id': self.sn_with_kerberos_ss['project_id']})
        self.assertIn(int(resp["status"]), self.HTTP_SUCCESS)
        self.assertTrue(any(self.sn_with_kerberos_ss['id'] == sn['id']
                            for sn in listed))
        self.assertTrue(all(self.sn_with_kerberos_ss['project_id'] ==
                            sn['project_id'] for sn in listed))
