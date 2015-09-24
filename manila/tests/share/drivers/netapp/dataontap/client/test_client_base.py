# Copyright (c) 2014 Alex Meade.  All rights reserved.
# Copyright (c) 2014 Clinton Knight.  All rights reserved.
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

import ddt
import mock
from oslo_log import log

from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.client import client_base
from manila import test
from manila.tests.share.drivers.netapp.dataontap.client import fakes as fake


class NetAppBaseClientTestCase(test.TestCase):

    def setUp(self):
        super(NetAppBaseClientTestCase, self).setUp()

        # Mock loggers as themselves to allow logger arg validation
        mock_logger = log.getLogger('mock_logger')
        self.mock_object(client_base.LOG,
                         'error',
                         mock.Mock(side_effect=mock_logger.error))

        self.client = client_base.NetAppBaseClient(**fake.CONNECTION_INFO)
        self.client.connection = mock.MagicMock()
        self.connection = self.client.connection

    def test_get_ontapi_version(self):
        version_response = netapp_api.NaElement(fake.ONTAPI_VERSION_RESPONSE)
        self.connection.invoke_successfully.return_value = version_response

        major, minor = self.client.get_ontapi_version(cached=False)

        self.assertEqual('1', major)
        self.assertEqual('19', minor)

    def test_get_ontapi_version_cached(self):

        self.connection.get_api_version.return_value = (1, 20)

        major, minor = self.client.get_ontapi_version()

        self.assertEqual(1, self.connection.get_api_version.call_count)
        self.assertEqual(1, major)
        self.assertEqual(20, minor)

    def test_init_features(self):

        self.client._init_features()

        self.assertSetEqual(set(), self.client.features.defined_features)

    def test_send_request(self):

        element = netapp_api.NaElement('fake-api')

        self.client.send_request('fake-api')

        self.assertEqual(
            element.to_string(),
            self.connection.invoke_successfully.call_args[0][0].to_string())
        self.assertTrue(self.connection.invoke_successfully.call_args[0][1])

    def test_send_request_no_tunneling(self):

        element = netapp_api.NaElement('fake-api')

        self.client.send_request('fake-api', enable_tunneling=False)

        self.assertEqual(
            element.to_string(),
            self.connection.invoke_successfully.call_args[0][0].to_string())
        self.assertFalse(self.connection.invoke_successfully.call_args[0][1])

    def test_send_request_with_args(self):

        element = netapp_api.NaElement('fake-api')
        api_args = {'arg1': 'data1', 'arg2': 'data2'}
        element.translate_struct(api_args)

        self.client.send_request('fake-api', api_args=api_args)

        self.assertEqual(
            element.to_string(),
            self.connection.invoke_successfully.call_args[0][0].to_string())
        self.assertTrue(self.connection.invoke_successfully.call_args[0][1])

    def test_get_licenses(self):

        api_response = netapp_api.NaElement(fake.LICENSE_V2_LIST_INFO_RESPONSE)
        self.mock_object(
            self.client, 'send_request', mock.Mock(return_value=api_response))

        response = self.client.get_licenses()

        self.assertSequenceEqual(fake.LICENSES, response)

    def test_get_licenses_api_error(self):

        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(side_effect=netapp_api.NaApiError))

        self.assertRaises(netapp_api.NaApiError, self.client.get_licenses)
        self.assertEqual(1, client_base.LOG.error.call_count)

    def test_send_ems_log_message(self):

        self.assertRaises(NotImplementedError,
                          self.client.send_ems_log_message,
                          {})


@ddt.ddt
class FeaturesTestCase(test.TestCase):

    def setUp(self):
        super(FeaturesTestCase, self).setUp()
        self.features = client_base.Features()

    def test_init(self):
        self.assertSetEqual(set(), self.features.defined_features)

    def test_add_feature_default(self):
        self.features.add_feature('FEATURE_1')

        self.assertTrue(self.features.FEATURE_1)
        self.assertIn('FEATURE_1', self.features.defined_features)

    @ddt.data(True, False)
    def test_add_feature(self, value):
        self.features.add_feature('FEATURE_2', value)

        self.assertEqual(value, self.features.FEATURE_2)
        self.assertIn('FEATURE_2', self.features.defined_features)

    @ddt.data('True', 'False', 0, 1, 1.0, None, [], {}, (True,))
    def test_add_feature_type_error(self, value):
        self.assertRaises(TypeError,
                          self.features.add_feature,
                          'FEATURE_3',
                          value)
        self.assertNotIn('FEATURE_3', self.features.defined_features)

    def test_get_attr_missing(self):
        self.assertRaises(AttributeError, getattr, self.features, 'FEATURE_4')
