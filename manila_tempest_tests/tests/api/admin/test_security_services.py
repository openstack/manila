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

from tempest import test  # noqa

from manila_tempest_tests.tests.api import base
from manila_tempest_tests.tests.api import test_security_services


class SecurityServiceAdminTest(
        base.BaseSharesAdminTest,
        test_security_services.SecurityServiceListMixin):

    def setUp(self):
        super(SecurityServiceAdminTest, self).setUp()
        ss_ldap_data = {
            'name': 'ss_ldap',
            'dns_ip': '1.1.1.1',
            'server': 'fake_server_1',
            'domain': 'fake_domain_1',
            'user': 'fake_user',
            'password': 'pass',
        }
        ss_kerberos_data = {
            'name': 'ss_kerberos',
            'dns_ip': '2.2.2.2',
            'server': 'fake_server_2',
            'domain': 'fake_domain_2',
            'user': 'test_user',
            'password': 'word',
        }
        self.ss_ldap = self.create_security_service('ldap', **ss_ldap_data)
        self.ss_kerberos = self.create_security_service(
            'kerberos',
            **ss_kerberos_data)

    @test.attr(type=["gate", "smoke", ])
    def test_list_security_services_all_tenants(self):
        listed = self.shares_client.list_security_services(
            params={'all_tenants': 1})
        self.assertTrue(any(self.ss_ldap['id'] == ss['id'] for ss in listed))
        self.assertTrue(any(self.ss_kerberos['id'] == ss['id']
                            for ss in listed))

        keys = ["name", "id", "status", "type", ]
        [self.assertIn(key, s_s.keys()) for s_s in listed for key in keys]

    @test.attr(type=["gate", "smoke", ])
    def test_list_security_services_invalid_filters(self):
        listed = self.shares_client.list_security_services(
            params={'fake_opt': 'some_value'})
        self.assertEqual(0, len(listed))
