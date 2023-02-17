# Copyright 2018 SAP SE
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

from unittest import mock

import datetime
import ddt

from manila.api.v1 import security_service
from manila.common import constants
from manila import context
from manila import test
from manila.tests.api import fakes


def stub_security_service(self, version, id):
    ss_dict = dict(
        id=id,
        name='security_service_%s' % str(id),
        type=constants.SECURITY_SERVICES_ALLOWED_TYPES[0],
        description='Fake Security Service Desc',
        dns_ip='1.1.1.1',
        server='fake-server',
        domain='fake-domain',
        user='fake-user',
        password='fake-password',
        status=constants.STATUS_NEW,
        share_networks=[],
        created_at=datetime.datetime(2017, 8, 24, 1, 1, 1, 1),
        updated_at=datetime.datetime(2017, 8, 24, 1, 1, 1, 1),
        project_id='fake-project'
    )
    if self.is_microversion_ge(version, '2.44'):
        ss_dict['ou'] = 'fake-ou'
    if self.is_microversion_ge(version, '2.76'):
        ss_dict['default_ad_site'] = 'fake-default_ad_site'

    return ss_dict


@ddt.ddt
class SecurityServicesAPITest(test.TestCase):
    @ddt.data(
        ('2.0'),
        ('2.43'),
        ('2.44'),
        ('2.76'),
    )
    def test_index(self, version):
        ss = [
            stub_security_service(self, version, 1),
            stub_security_service(self, version, 2),
        ]
        ctxt = context.RequestContext('admin', 'fake', True)
        request = fakes.HTTPRequest.blank('/security-services?all_tenants=1',
                                          version=version)
        request.headers['X-Openstack-Manila-Api-Version'] = version
        request.environ['manila.context'] = ctxt
        self.mock_object(security_service.db, 'security_service_get_all',
                         mock.Mock(return_value=ss))
        self.mock_object(security_service.db,
                         'share_network_get_all_by_security_service',
                         mock.Mock(return_value=[]))

        ss_controller = security_service.SecurityServiceController()

        result = ss_controller.detail(request)

        self.assertIsInstance(result, dict)
        self.assertEqual(['security_services'], list(result.keys()))
        self.assertIsInstance(result['security_services'], list)
        self.assertEqual(2, len(result['security_services']))
        self.assertIn(ss[0], result['security_services'])

        ss_keys = list(result['security_services'][0].keys())
        if self.is_microversion_ge(version, '2.44'):
            self.assertIn('ou', ss_keys)
        else:
            self.assertNotIn('ou', ss_keys)

        if self.is_microversion_ge(version, '2.76'):
            self.assertIn('default_ad_site', ss_keys)
        else:
            self.assertNotIn('default_ad_site', ss_keys)
