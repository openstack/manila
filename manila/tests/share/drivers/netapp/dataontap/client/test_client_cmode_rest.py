# Copyright (c) 2023 NetApp, Inc. All rights reserved.
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

import copy
from unittest import mock

import ddt
from oslo_log import log

from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp.dataontap.client import client_cmode_rest
from manila.share.drivers.netapp import utils as netapp_utils
from manila import test
from manila.tests.share.drivers.netapp.dataontap.client import fakes as fake


@ddt.ddt
class NetAppRestCmodeClientTestCase(test.TestCase):

    def setUp(self):
        super(NetAppRestCmodeClientTestCase, self).setUp()

        # Mock loggers as themselves to allow logger arg validation
        mock_logger = log.getLogger('mock_logger')
        self.mock_object(client_cmode_rest.LOG,
                         'error',
                         mock.Mock(side_effect=mock_logger.error))
        self.mock_object(client_cmode_rest.LOG,
                         'warning',
                         mock.Mock(side_effect=mock_logger.warning))
        self.mock_object(client_cmode_rest.LOG,
                         'debug',
                         mock.Mock(side_effect=mock_logger.debug))
        self.mock_object(client_cmode.NetAppCmodeClient,
                         'get_ontapi_version',
                         mock.Mock(return_value=(1, 20)))
        # store the original reference so we can call it later in
        # test_get_ontap_version
        self.original_get_ontap_version = (
            client_cmode_rest.NetAppRestClient.get_ontap_version)
        self.mock_object(client_cmode_rest.NetAppRestClient,
                         'get_ontap_version',
                         mock.Mock(return_value={
                             'version-tuple': (9, 11, 1),
                             'version': fake.VERSION,
                         }))
        self.mock_object(client_cmode.NetAppCmodeClient,
                         'get_system_version',
                         mock.Mock(return_value={
                             'version-tuple': (9, 10, 1),
                             'version': fake.VERSION,
                         }))

        self.client = client_cmode_rest.NetAppRestClient(
            **fake.CONNECTION_INFO)
        self.client.connection = mock.MagicMock()

        self.vserver_client = client_cmode.NetAppCmodeClient(
            **fake.CONNECTION_INFO)
        self.vserver_client.set_vserver(fake.VSERVER_NAME)
        self.vserver_client.connection = mock.MagicMock()

    def test_send_request(self):
        expected = 'fake_response'
        mock_get_records = self.mock_object(
            self.client, 'get_records',
            mock.Mock(return_value=expected))

        res = self.client.send_request(
            fake.FAKE_ACTION_URL, 'get',
            body=fake.FAKE_HTTP_BODY,
            query=fake.FAKE_HTTP_QUERY, enable_tunneling=False)

        self.assertEqual(expected, res)
        mock_get_records.assert_called_once_with(
            fake.FAKE_ACTION_URL,
            fake.FAKE_HTTP_QUERY, False, 10000)

    def test_send_request_post(self):
        expected = (201, 'fake_response')
        mock_invoke = self.mock_object(
            self.client.connection, 'invoke_successfully',
            mock.Mock(return_value=expected))

        res = self.client.send_request(
            fake.FAKE_ACTION_URL, 'post',
            body=fake.FAKE_HTTP_BODY,
            query=fake.FAKE_HTTP_QUERY, enable_tunneling=False)

        self.assertEqual(expected[1], res)
        mock_invoke.assert_called_once_with(
            fake.FAKE_ACTION_URL, 'post',
            body=fake.FAKE_HTTP_BODY,
            query=fake.FAKE_HTTP_QUERY, enable_tunneling=False)

    def test_send_request_wait(self):
        expected = (202, fake.JOB_RESPONSE_REST)
        mock_invoke = self.mock_object(
            self.client.connection, 'invoke_successfully',
            mock.Mock(return_value=expected))

        mock_wait = self.mock_object(
            self.client, '_wait_job_result',
            mock.Mock(return_value=expected[1]))

        res = self.client.send_request(
            fake.FAKE_ACTION_URL, 'post',
            body=fake.FAKE_HTTP_BODY,
            query=fake.FAKE_HTTP_QUERY, enable_tunneling=False)

        self.assertEqual(expected[1], res)
        mock_invoke.assert_called_once_with(
            fake.FAKE_ACTION_URL, 'post',
            body=fake.FAKE_HTTP_BODY,
            query=fake.FAKE_HTTP_QUERY, enable_tunneling=False)
        mock_wait.assert_called_once_with(
            expected[1]['job']['_links']['self']['href'][4:])

    @ddt.data(True, False)
    def test_get_records(self, enable_tunneling):
        api_responses = [
            (200, fake.VOLUME_GET_ITER_RESPONSE_REST_PAGE),
            (200, fake.VOLUME_GET_ITER_RESPONSE_REST_PAGE),
            (200, fake.VOLUME_GET_ITER_RESPONSE_REST_LAST_PAGE),
        ]

        mock_invoke = self.mock_object(
            self.client.connection, 'invoke_successfully',
            mock.Mock(side_effect=copy.deepcopy(api_responses)))

        query = {
            'fields': 'name'
        }

        result = self.client.get_records(
            '/storage/volumes/', query=query,
            enable_tunneling=enable_tunneling,
            max_page_length=10)

        num_records = result['num_records']
        self.assertEqual(28, num_records)
        self.assertEqual(28, len(result['records']))

        expected_records = []
        expected_records.extend(api_responses[0][1]['records'])
        expected_records.extend(api_responses[1][1]['records'])
        expected_records.extend(api_responses[2][1]['records'])

        self.assertEqual(expected_records, result['records'])

        next_tag = result.get('next')
        self.assertIsNone(next_tag)

        expected_query = copy.deepcopy(query)
        expected_query['max_records'] = 10

        next_url_1 = api_responses[0][1]['_links']['next']['href'][4:]
        next_url_2 = api_responses[1][1]['_links']['next']['href'][4:]

        mock_invoke.assert_has_calls([
            mock.call('/storage/volumes/', 'get', query=expected_query,
                      enable_tunneling=enable_tunneling),
            mock.call(next_url_1, 'get', query=None,
                      enable_tunneling=enable_tunneling),
            mock.call(next_url_2, 'get', query=None,
                      enable_tunneling=enable_tunneling),
        ])

    def test_get_records_single_page(self):

        api_response = (
            200, fake.VOLUME_GET_ITER_RESPONSE_REST_LAST_PAGE)
        mock_invoke = self.mock_object(self.client.connection,
                                       'invoke_successfully',
                                       mock.Mock(return_value=api_response))

        query = {
            'fields': 'name'
        }

        result = self.client.get_records(
            '/storage/volumes/', query=query, max_page_length=10)

        num_records = result['num_records']
        self.assertEqual(8, num_records)
        self.assertEqual(8, len(result['records']))

        next_tag = result.get('next')
        self.assertIsNone(next_tag)

        args = copy.deepcopy(query)
        args['max_records'] = 10

        mock_invoke.assert_has_calls([
            mock.call('/storage/volumes/', 'get', query=args,
                      enable_tunneling=True),
        ])

    def test_get_records_not_found(self):

        api_response = (200, fake.NO_RECORDS_RESPONSE_REST)
        mock_invoke = self.mock_object(self.client.connection,
                                       'invoke_successfully',
                                       mock.Mock(return_value=api_response))

        result = self.client.get_records('/storage/volumes/')

        num_records = result['num_records']
        self.assertEqual(0, num_records)
        self.assertEqual(0, len(result['records']))

        args = {
            'max_records': client_cmode_rest.DEFAULT_MAX_PAGE_LENGTH
        }

        mock_invoke.assert_has_calls([
            mock.call('/storage/volumes/', 'get', query=args,
                      enable_tunneling=True),
        ])

    def test_get_records_timeout(self):
        # To simulate timeout, max_records is 30, but the API returns less
        # records and fill the 'next url' pointing to the next page.
        max_records = 30
        api_responses = [
            (200, fake.VOLUME_GET_ITER_RESPONSE_REST_PAGE),
            (200, fake.VOLUME_GET_ITER_RESPONSE_REST_PAGE),
            (200, fake.VOLUME_GET_ITER_RESPONSE_REST_LAST_PAGE),
        ]

        mock_invoke = self.mock_object(
            self.client.connection, 'invoke_successfully',
            mock.Mock(side_effect=copy.deepcopy(api_responses)))

        query = {
            'fields': 'name'
        }

        result = self.client.get_records(
            '/storage/volumes/', query=query, max_page_length=max_records)

        num_records = result['num_records']
        self.assertEqual(28, num_records)
        self.assertEqual(28, len(result['records']))

        expected_records = []
        expected_records.extend(api_responses[0][1]['records'])
        expected_records.extend(api_responses[1][1]['records'])
        expected_records.extend(api_responses[2][1]['records'])

        self.assertEqual(expected_records, result['records'])

        next_tag = result.get('next', None)
        self.assertIsNone(next_tag)

        args1 = copy.deepcopy(query)
        args1['max_records'] = max_records

        next_url_1 = api_responses[0][1]['_links']['next']['href'][4:]
        next_url_2 = api_responses[1][1]['_links']['next']['href'][4:]

        mock_invoke.assert_has_calls([
            mock.call('/storage/volumes/', 'get', query=args1,
                      enable_tunneling=True),
            mock.call(next_url_1, 'get', query=None, enable_tunneling=True),
            mock.call(next_url_2, 'get', query=None, enable_tunneling=True),
        ])

    def test__getattr__(self):
        # NOTE(nahimsouza): get_ontapi_version is implemented only in ZAPI
        # client, therefore, it will call __getattr__
        self.client.get_ontapi_version()

    @ddt.data(True, False)
    def test_get_ontap_version(self, cached):
        self.client.get_ontap_version = (
            self.original_get_ontap_version)
        api_response = {
            'records': [
                {
                    'version': {
                        'generation': 9,
                        'major': 11,
                        'minor': 1,
                        'full': 'NetApp Release 9.11.1'
                    }
                }]

        }
        return_mock = {
            'version': 'NetApp Release 9.11.1',
            'version-tuple': (9, 11, 1)
        }
        mock_connect = self.mock_object(self.client.connection,
                                        'get_ontap_version',
                                        mock.Mock(return_value=return_mock))
        mock_send_request = self.mock_object(
            self.client,
            'send_request',
            mock.Mock(return_value=api_response))

        result = self.client.get_ontap_version(self=self.client, cached=cached)

        if cached:
            mock_connect.assert_called_once()
        else:
            mock_send_request.assert_called_once_with(
                '/cluster/nodes', 'get', query={'fields': 'version'})

        self.assertEqual(return_mock, result)

    def test__wait_job_result(self):
        response = fake.JOB_SUCCESSFUL_REST
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=response))
        result = self.client._wait_job_result(
            f'/cluster/jobs/{fake.FAKE_UUID}')
        self.assertEqual(response, result)

    def test__wait_job_result_failure(self):
        response = fake.JOB_ERROR_REST
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=response))
        self.assertRaises(netapp_utils.NetAppDriverException,
                          self.client._wait_job_result,
                          f'/cluster/jobs/{fake.FAKE_UUID}')

    def test__wait_job_result_timeout(self):
        response = fake.JOB_RUNNING_REST
        self.client.async_rest_timeout = 2
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=response))
        self.assertRaises(netapp_utils.NetAppDriverException,
                          self.client._wait_job_result,
                          f'/cluster/jobs/{fake.FAKE_UUID}')
