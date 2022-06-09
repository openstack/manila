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
import time
from unittest import mock

import ddt
from oslo_log import log

from manila import exception
from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp.dataontap.client import client_cmode_rest
from manila.share.drivers.netapp.dataontap.client import rest_api as netapp_api
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
                             'version-tuple': (9, 12, 1),
                             'version': fake.VERSION,
                         }))
        self.original_check_for_cluster_credentials = (
            client_cmode_rest.NetAppRestClient._check_for_cluster_credentials)
        self.mock_object(client_cmode_rest.NetAppRestClient,
                         '_check_for_cluster_credentials',
                         mock.Mock(return_value=True))
        self.mock_object(client_cmode.NetAppCmodeClient,
                         'get_system_version',
                         mock.Mock(return_value={
                             'version-tuple': (9, 10, 1),
                             'version': fake.VERSION,
                         }))

        self.client = client_cmode_rest.NetAppRestClient(
            **fake.CONNECTION_INFO)
        self.client.connection = mock.MagicMock()

    def _mock_api_error(self, code='fake', message='fake'):
        return mock.Mock(
            side_effect=netapp_api.api.NaApiError(code=code, message=message))

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
        self.client.get_ontap_version = self.original_get_ontap_version
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
                '/cluster/nodes', 'get', query={'fields': 'version'},
                enable_tunneling=False)

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

    def test_list_cluster_nodes(self):
        """Get all available cluster nodes."""

        return_value = fake.FAKE_GET_CLUSTER_NODE_VERSION_REST

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))
        test_result = self.client.list_cluster_nodes()

        self.client.send_request.assert_called_once_with(
            '/cluster/nodes', 'get'
        )

        nodes = return_value.get('records', [])

        expected_result = [node['name'] for node in nodes]

        self.assertEqual(expected_result, test_result)

    @ddt.data(True, False)
    def test_check_for_cluster_credentials(self, cluster_creds):
        self.client._have_cluster_creds = cluster_creds

        result = self.client.check_for_cluster_credentials()

        self.assertEqual(cluster_creds, result)

    def test__check_for_cluster_credentials(self):
        self.client._check_for_cluster_credentials = (
            self.original_check_for_cluster_credentials)
        api_response = fake.FAKE_GET_CLUSTER_NODE_VERSION_REST
        self.mock_object(self.client,
                         'list_cluster_nodes',
                         mock.Mock(return_value=api_response))

        result = self.client._check_for_cluster_credentials(self=self.client)

        self.assertTrue(result)

    def test__check_for_cluster_credentials_not_cluster(self):
        self.client._check_for_cluster_credentials = (
            self.original_check_for_cluster_credentials)
        self.mock_object(self.client, 'list_cluster_nodes',
                         self._mock_api_error(
                             netapp_api.EREST_NOT_AUTHORIZED))

        result = self.client._check_for_cluster_credentials(self=self.client)

        self.assertFalse(result)

    def test__check_for_cluster_credentials_api_error(self):
        self.client._check_for_cluster_credentials = (
            self.original_check_for_cluster_credentials)
        self.mock_object(self.client, 'list_cluster_nodes',
                         self._mock_api_error())

        self.assertRaises(netapp_api.api.NaApiError,
                          self.client._check_for_cluster_credentials,
                          self.client)

    def test_get_licenses(self):
        return_value = fake.FAKE_GET_LICENSES_REST

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        test_result = self.client.get_licenses()

        expected_result = sorted(
            [license['name'] for license in return_value.get('records', [])])

        self.assertEqual(test_result, expected_result)

    @ddt.data(((9, 1, 0), fake.VERSION_NO_DARE), ((8, 3, 2), fake.VERSION))
    @ddt.unpack
    def test_is_nve_supported_unsupported_release_or_platform(self, gen, ver):
        system_version = {'version-tuple': gen, 'version': ver}
        self.mock_object(self.client,
                         'get_ontap_version',
                         mock.Mock(return_value=system_version))
        self.mock_object(self.client,
                         '_get_security_key_manager_nve_support',
                         mock.Mock(return_value=False))
        self.mock_object(self.client,
                         'list_cluster_nodes',
                         mock.Mock(return_value=fake.NODE_NAMES))

        result = self.client.is_nve_supported()

        self.assertFalse(result)

    def test_is_nve_supported_valid_platform_and_supported_release(self):

        system_version = {
            'version-tuple': (9, 1, 0),
            'version': fake.VERSION,
        }
        self.mock_object(self.client,
                         'get_ontap_version',
                         mock.Mock(return_value=system_version))
        self.mock_object(self.client,
                         '_get_security_key_manager_nve_support',
                         mock.Mock(return_value=True))
        self.mock_object(self.client,
                         'list_cluster_nodes',
                         mock.Mock(return_value=fake.NODE_NAMES))

        result = self.client.is_nve_supported()
        self.assertTrue(result)

    def test_is_nve_supported_key_manager_not_enabled(self):

        system_version = {
            'version-tuple': (9, 1, 0),
            'version': fake.VERSION,
        }
        self.mock_object(self.client,
                         'get_ontap_version',
                         mock.Mock(return_value=system_version))
        self.mock_object(self.client,
                         '_get_security_key_manager_nve_support',
                         mock.Mock(return_value=False))
        self.mock_object(self.client,
                         'list_cluster_nodes',
                         mock.Mock(return_value=fake.NODE_NAMES))

        result = self.client.is_nve_supported()

        self.assertFalse(result)

    def test__get_volume_by_args(self):
        response = fake.VOLUME_LIST_SIMPLE_RESPONSE_REST
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))

        result = self.client._get_volume_by_args(
            vol_name=fake.VOLUME_NAMES[0],
            aggregate_name=fake.SHARE_AGGREGATE_NAME,
            vol_path=fake.VOLUME_JUNCTION_PATH,
            vserver=fake.VSERVER_NAME,
            fields='name,style,svm.name,svm.uuid')

        query = {
            'name': fake.VOLUME_NAMES[0],
            'aggregates.name': fake.SHARE_AGGREGATE_NAME,
            'nas.path': fake.VOLUME_JUNCTION_PATH,
            'svm.name': fake.VSERVER_NAME,
            'style': 'flex*',  # Match both 'flexvol' and 'flexgroup'
            'error_state.is_inconsistent': 'false',
            'fields': 'name,style,svm.name,svm.uuid'
        }
        self.client.send_request.assert_called_once_with(
            '/storage/volumes/', 'get', query=query)

        self.assertEqual(volume, result)

    def test_restore_snapshot(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST["uuid"]
        body = {
            'restore_to.snapshot.name': fake.SNAPSHOT_NAME
        }

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request')

        self.client.restore_snapshot(fake.VOLUME_NAMES[0], fake.SNAPSHOT_NAME)

        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])
        self.client.send_request.assert_called_once_with(
            f'/storage/volumes/{uuid}', 'patch', body=body)

    @ddt.data(0, 10)
    def test__has_records(self, num_records):
        result = self.client._has_records({'num_records': num_records})

        if not num_records or num_records == 0:
            self.assertFalse(result)
        else:
            self.assertTrue(result)

    def test_vserver_exists(self):
        query = {
            'name': fake.VSERVER_NAME
        }
        return_value = fake.SVMS_LIST_SIMPLE_RESPONSE_REST

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))

        result = self.client.vserver_exists(fake.VSERVER_NAME)

        self.client.send_request.assert_called_once_with(
            '/svm/svms', 'get', query=query, enable_tunneling=False)
        self.client._has_records.assert_called_once_with(
            fake.SVMS_LIST_SIMPLE_RESPONSE_REST)

        self.assertEqual(result, True)

    def test_get_aggregate(self):

        response = fake.AGGR_GET_ITER_RESPONSE_REST['records']
        self.mock_object(self.client,
                         '_get_aggregates',
                         mock.Mock(return_value=response))

        result = self.client.get_aggregate(fake.SHARE_AGGREGATE_NAME)

        fields = ('name,block_storage.primary.raid_type,'
                  'block_storage.storage_type')

        self.client._get_aggregates.assert_has_calls([
            mock.call(
                aggregate_names=[fake.SHARE_AGGREGATE_NAME],
                fields=fields)])

        expected = {
            'name': fake.SHARE_AGGREGATE_NAME,
            'raid-type': response[0]['block_storage']['primary']['raid_type'],
            'is-hybrid':
                response[0]['block_storage']['storage_type'] == 'hybrid',
        }

        self.assertEqual(expected, result)

    def test_get_cluster_aggregate_capacities(self):

        response = fake.AGGR_GET_ITER_RESPONSE_REST['records']
        self.mock_object(self.client,
                         '_get_aggregates',
                         mock.Mock(return_value=response))

        result = self.client.get_cluster_aggregate_capacities(
            response)

        fields = 'name,space'
        self.client._get_aggregates.assert_has_calls([
            mock.call(
                aggregate_names=response,
                fields=fields)])
        expected = {
            response[0]['name']: {
                'available': 568692293632,
                'total': 1271819509760,
                'used': 703127216128,
            },
            response[1]['name']: {
                'available': 727211110400,
                'total': 1426876227584,
                'used': 699665117184,
            }
        }

        self.assertDictEqual(expected, result)

    def test_list_non_root_aggregates(self):
        return_value = fake.FAKE_AGGR_LIST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        result = self.client.list_non_root_aggregates()

        expected = [fake.SHARE_AGGREGATE_NAMES_LIST[0]]
        self.assertEqual(expected, result)

    def test__get_aggregates(self):

        api_response = fake.AGGR_GET_ITER_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))
        result = self.client._get_aggregates(
            aggregate_names=fake.SHARE_AGGREGATE_NAMES)
        expected = fake.AGGR_GET_ITER_RESPONSE_REST['records']
        self.assertEqual(expected, result)

    def test_get_node_for_aggregate(self):

        response = fake.AGGR_GET_ITER_RESPONSE_REST['records']
        self.mock_object(self.client,
                         '_get_aggregates',
                         mock.Mock(return_value=response))
        result = self.client.get_node_for_aggregate(fake.SHARE_AGGREGATE_NAME)
        expected = 'fake_home_node_name'
        self.assertEqual(expected, result)

    @ddt.data({'types': {'FCAL'}, 'expected': ['FCAL']},
              {'types': {'SATA', 'SSD'}, 'expected': ['SATA', 'SSD']},)
    @ddt.unpack
    def test_get_aggregate_disk_types(self, types, expected):

        mock_get_aggregate_disk_types = self.mock_object(
            self.client, '_get_aggregate_disk_types',
            mock.Mock(return_value=types))

        result = self.client.get_aggregate_disk_types(
            fake.SHARE_AGGREGATE_NAME)

        self.assertEqual(sorted(expected), sorted(result))
        mock_get_aggregate_disk_types.assert_called_once_with(
            fake.SHARE_AGGREGATE_NAME)

    def test_volume_exists(self):
        query = {
            'name': fake.VOLUME_NAMES[0]
        }
        return_value = fake.VOLUME_LIST_SIMPLE_RESPONSE_REST

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))

        result = self.client.volume_exists(fake.VOLUME_NAMES[0])

        self.client.send_request.assert_called_once_with(
            '/storage/volumes', 'get', query=query)
        self.client._has_records.assert_called_once_with(
            fake.VOLUME_LIST_SIMPLE_RESPONSE_REST)
        self.assertEqual(result, True)

    def test_list_vserver_aggregates(self):

        self.mock_object(self.client,
                         'get_vserver_aggregate_capacities',
                         mock.Mock(return_value=fake.VSERVER_AGGREGATES))

        result = self.client.list_vserver_aggregates()

        self.assertListEqual(list(fake.VSERVER_AGGREGATES.keys()), result)

    def test_list_vserver_aggregates_none_found(self):

        self.mock_object(self.client,
                         'get_vserver_aggregate_capacities',
                         mock.Mock(return_value={}))

        result = self.client.list_vserver_aggregates()

        self.assertListEqual([], result)

    def test_get_vserver_aggregate_capacities(self):

        response = fake.FAKE_SVM_AGGREGATES
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=response))

        result = self.client.get_vserver_aggregate_capacities(
            fake.SHARE_AGGREGATE_NAMES_LIST)

        query = {
            'fields': 'name,aggregates.name,aggregates.available_size'
        }

        self.client.send_request.assert_has_calls([
            mock.call('/svm/svms', 'get', query=query)])

        expected = {
            response['records'][0].get('aggregates')[0].get('name'): {
                'available': 568692293632,
            },
            response['records'][0].get('aggregates')[1].get('name'): {
                'available': 727211110400,
            }
        }

        self.assertDictEqual(expected, result)

    def test_get_vserver_aggregate_capacities_partial_request(self):
        response = fake.FAKE_SVM_AGGREGATES
        size = response['records'][0].get('aggregates')[0].get(
            'available_size')
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=response))

        result = self.client.get_vserver_aggregate_capacities(
            [fake.SHARE_AGGREGATE_NAMES[0]])

        expected = {
            fake.SHARE_AGGREGATE_NAMES[0]: {
                'available': size
            }
        }
        self.assertDictEqual(expected, result)

    def test_get_vserver_aggregate_capacities_aggregate_not_found(self):
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=fake.FAKE_SVM_AGGR_EMPTY))

        result = self.client.get_vserver_aggregate_capacities(
            ['other-aggr'])

        self.assertDictEqual({}, result)
        self.assertEqual(1, client_cmode_rest.LOG.warning.call_count)

    def test_get_vserver_aggregate_capacities_none_requested(self):
        result = self.client.get_vserver_aggregate_capacities([])
        self.assertEqual({}, result)

    @ddt.data(None, fake.QOS_MAX_THROUGHPUT)
    def test_qos_policy_group_create(self, max_throughput):
        return_value = fake.GENERIC_JOB_POST_RESPONSE
        body = {
            'name': fake.QOS_POLICY_GROUP_NAME,
            'svm.name': fake.VSERVER_NAME,
        }
        if max_throughput:
            body['fixed.max_throughput_iops'] = fake.QOS_MAX_THROUGHPUT_NO_UNIT

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        if max_throughput:
            result = self.client.qos_policy_group_create(
                fake.QOS_POLICY_GROUP_NAME, fake.VSERVER_NAME,
                fake.QOS_MAX_THROUGHPUT)
        else:
            result = self.client.qos_policy_group_create(
                fake.QOS_POLICY_GROUP_NAME, fake.VSERVER_NAME)

        self.client.send_request.assert_called_once_with(
            '/storage/qos/policies', 'post', body=body)
        self.assertEqual(result, return_value)

    @ddt.data(None, ['CIFS', 'NFS'])
    def test_get_network_interfaces(self, protocols):
        return_value = fake.GENERIC_NETWORK_INTERFACES_GET_REPONSE

        lif_info = return_value.get('records', [])[0]

        fake_lif = [{
            'address': lif_info['ip']['address'],
            'home-node': lif_info['location']['home_node']['name'],
            'home-port': lif_info['location']['home_port']['name'],
            'interface-name': lif_info['name'],
            'netmask': lif_info['ip']['netmask'],
            'role': lif_info['services'],
            'vserver': lif_info['svm']['name'],
        }]

        if protocols:
            query = {
                'services': 'data_cifs,data_nfs',
                'fields': 'ip.address,location.home_node.name,'
                          'location.home_port.name,ip.netmask,'
                          'services,svm.name'
            }
        else:
            query = {
                'fields': 'ip.address,location.home_node.name,'
                          'location.home_port.name,ip.netmask,'
                          'services,svm.name'
            }

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        result = self.client.get_network_interfaces(protocols)

        self.client.send_request.assert_called_once_with(
            '/network/ip/interfaces', 'get', query=query)

        self.assertEqual(result, fake_lif)

    def test_clear_nfs_export_policy_for_volume(self):

        mock_set_nfs_export_policy_for_volume = self.mock_object(
            self.client, 'set_nfs_export_policy_for_volume')

        self.client.clear_nfs_export_policy_for_volume(fake.SHARE_NAME)

        mock_set_nfs_export_policy_for_volume.assert_called_once_with(
            fake.SHARE_NAME, 'default')

    def test_set_nfs_export_policy_for_volume(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        query = {'name': volume['name']}

        body = {
            'nas.export_policy.name': fake.EXPORT_POLICY_NAME
        }

        self.mock_object(self.client, 'send_request')

        self.client.set_nfs_export_policy_for_volume(
            fake.VOLUME_NAMES[0], fake.EXPORT_POLICY_NAME)

        self.client.send_request.assert_called_once_with(
            '/storage/volumes/', 'patch',
            query=query, body=body)

    def test_create_nfs_export_policy(self):

        body = {'name': fake.EXPORT_POLICY_NAME}

        self.mock_object(self.client, 'send_request')

        self.client.create_nfs_export_policy(fake.EXPORT_POLICY_NAME)

        self.client.send_request.assert_called_once_with(
            '/protocols/nfs/export-policies', 'post', body=body)

    def test_soft_delete_nfs_export_policy(self):
        self.mock_object(self.client, 'delete_nfs_export_policy',
                         mock.Mock(side_effect=self._mock_api_error()))
        self.mock_object(self.client, 'rename_nfs_export_policy')

        self.client.soft_delete_nfs_export_policy(fake.EXPORT_POLICY_NAME)

        self.client.rename_nfs_export_policy.assert_has_calls([
            mock.call(
                fake.EXPORT_POLICY_NAME,
                'deleted_manila_' + fake.EXPORT_POLICY_NAME)])

    def test_rename_nfs_export_policy(self):
        return_uuid = fake.GENERIC_EXPORT_POLICY_RESPONSE_AND_VOLUMES
        uuid = "fake-policy-uuid"

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_uuid))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))

        body = {
            'name': 'fake_new_policy_name'
        }

        self.client.rename_nfs_export_policy(fake.EXPORT_POLICY_NAME,
                                             'fake_new_policy_name')

        self.client._has_records.assert_called_once_with(return_uuid)

        self.client.send_request.assert_has_calls([
            mock.call('/protocols/nfs/export-policies', 'get',
                      query={'name': fake.EXPORT_POLICY_NAME}),
            mock.call(f'/protocols/nfs/export-policies/{uuid}', 'patch',
                      body=body)])

    def test_get_volume_junction_path(self):
        return_value = fake.GENERIC_EXPORT_POLICY_RESPONSE_AND_VOLUMES

        query = {
            'name': fake.SHARE_NAME,
            'fields': 'nas.path'
        }

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        result = self.client.get_volume_junction_path(fake.SHARE_NAME)

        expected = fake.VOLUME_JUNCTION_PATH

        self.client.send_request.assert_called_once_with('/storage/volumes/',
                                                         'get', query=query)

        self.assertEqual(result, expected)

    def test_get_volume(self):
        return_value = fake.GENERIC_EXPORT_POLICY_RESPONSE_AND_VOLUMES

        fake_volume = return_value.get('records', [])[0]

        expected = {
            'aggregate': fake.SHARE_AGGREGATE_NAME,
            'aggr-list': [fake.SHARE_AGGREGATE_NAME],
            'junction-path': fake_volume.get('nas', {}).get('path', ''),
            'name': fake_volume.get('name', ''),
            'owning-vserver-name': fake_volume.get('svm', {}).get('name', ''),
            'type': fake_volume.get('type', ''),
            'style': fake_volume.get('style', ''),
            'size': fake_volume.get('space', {}).get('size', ''),
            'qos-policy-group-name': fake_volume.get('qos', {})
                                                .get('policy', {})
                                                .get('name', ''),
            'style-extended': fake_volume.get('style', '')
        }

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))

        result = self.client.get_volume(fake.SHARE_NAME)

        self.client._has_records.assert_called_once_with(return_value)
        self.assertEqual(result, expected)

    def test_cifs_share_exists(self):
        return_value = fake.VOLUME_LIST_SIMPLE_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))

        result = self.client.cifs_share_exists(fake.SHARE_NAME)

        query = {
            'name': fake.SHARE_NAME,
            'path': fake.VOLUME_JUNCTION_PATH
        }
        self.client._has_records.assert_called_once_with(return_value)
        self.client.send_request.assert_called_once_with(
            '/protocols/cifs/shares', 'get', query=query)
        self.assertTrue(result)

    def test_create_cifs_share(self):

        body = {
            'name': fake.SHARE_NAME,
            'path': fake.VOLUME_JUNCTION_PATH,
            'svm.name': self.client.vserver,
        }

        self.mock_object(self.client, 'send_request')

        self.client.create_cifs_share(fake.SHARE_NAME)

        self.client.send_request.assert_called_once_with(
            '/protocols/cifs/shares', 'post', body=body)

    @ddt.data(None, 'fake_security_style')
    def test_set_volume_security_style(self, security_style):

        self.mock_object(self.client, 'send_request')

        if security_style:
            self.client.set_volume_security_style(fake.VOLUME_NAMES[0],
                                                  security_style)
        else:
            self.client.set_volume_security_style(fake.VOLUME_NAMES[0])

        query = {
            'name': fake.VOLUME_NAMES[0],
        }
        body = {
            'nas.security_style': security_style if security_style else 'unix'
        }
        self.client.send_request.assert_called_once_with(
            '/storage/volumes', 'patch', body=body, query=query)

    def test_remove_cifs_share_access(self):
        return_uuid = fake.GENERIC_EXPORT_POLICY_RESPONSE_AND_VOLUMES
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_uuid))

        self.client.remove_cifs_share_access(fake.SHARE_NAME, fake.USER_NAME)

        fake_uuid = "fake_uuid"
        self.client.send_request.assert_has_calls([
            mock.call('/protocols/cifs/shares', 'get',
                      query={'name': fake.SHARE_NAME, 'fields': 'svm.uuid'}),
            mock.call(f'/protocols/cifs/shares/{fake_uuid}/{fake.SHARE_NAME}/'
                      f'acls/{fake.USER_NAME}/windows', 'delete')])

    def test_create_volume(self):

        mock_create_volume_async = self.mock_object(self.client,
                                                    'create_volume_async')
        mock_update = self.mock_object(
            self.client, 'update_volume_efficiency_attributes')
        self.client.create_volume(fake.SHARE_AGGREGATE_NAME,
                                  fake.VOLUME_NAMES[0], fake.SHARE_SIZE)

        mock_create_volume_async.assert_called_once_with(
            [fake.SHARE_AGGREGATE_NAME], fake.VOLUME_NAMES[0], fake.SHARE_SIZE,
            is_flexgroup=False, thin_provisioned=False, snapshot_policy=None,
            language=None, max_files=None, snapshot_reserve=None,
            volume_type='rw', qos_policy_group=None, encrypt=False,
            adaptive_qos_policy_group=None)
        mock_update.assert_called_once_with(fake.VOLUME_NAMES[0], False, False)

    def test_create_volume_async(self):
        body = {
            'size': 1073741824,
            'name': fake.VOLUME_NAMES[0],
            'style': 'flexvol',
            'aggregates': [{'name': fake.SHARE_AGGREGATE_NAME}]
        }

        return_value = fake.GENERIC_JOB_POST_RESPONSE

        expected_result = {
            'jobid': fake.GENERIC_JOB_POST_RESPONSE['job']['uuid'],
            'error-code': '',
            'error-message': '',
        }

        self.mock_object(self.client, '_get_create_volume_body',
                         mock.Mock(return_value={}))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        result = self.client.create_volume_async([
            fake.SHARE_AGGREGATE_NAME], fake.VOLUME_NAMES[0], 1,
            is_flexgroup=False)

        self.client._get_create_volume_body.assert_called_once_with(
            fake.VOLUME_NAMES[0], False, None, None, None, 'rw', None, False,
            None)
        self.client.send_request.assert_called_once_with(
            '/storage/volumes', 'post', body=body, wait_on_accepted=True)
        self.assertEqual(expected_result, result)

    def test_get_volume_efficiency_status(self):
        return_value = fake.VOLUME_LIST_SIMPLE_RESPONSE_REST

        query = {
            'efficiency.volume_path': '/vol/%s' % fake.VOLUME_NAMES[0],
            'fields': 'efficiency.state,efficiency.compression'
        }

        expected_result = {
            'dedupe': True,
            'compression': True
        }

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        result = self.client.get_volume_efficiency_status(fake.VOLUME_NAMES[0])

        self.client.send_request.assert_called_once_with(
            '/storage/volumes', 'get', query=query)
        self.assertEqual(expected_result, result)

    def test_enable_dedupe_async(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = volume["uuid"]
        return_value = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        body = {
            'efficiency': {'dedupe': 'background'}
        }

        self.client.enable_dedupe_async(fake.VOLUME_NAMES[0])

        self.client.send_request.assert_called_once_with(
            f'/storage/volumes/{uuid}', 'patch', body=body)
        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])

    def test_disable_dedupe_async(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = volume["uuid"]
        return_value = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        body = {
            'efficiency': {'dedupe': 'none'}
        }

        self.client.disable_dedupe_async(fake.VOLUME_NAMES[0])

        self.client.send_request.assert_called_once_with(
            f'/storage/volumes/{uuid}', 'patch', body=body)
        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])

    def test_enable_compression_async(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = volume["uuid"]
        return_value = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        body = {
            'efficiency': {'compression': 'background'}
        }

        self.client.enable_compression_async(fake.VOLUME_NAMES[0])

        self.client.send_request.assert_called_once_with(
            f'/storage/volumes/{uuid}', 'patch', body=body)
        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])

    def test_disable_compression_async(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = volume["uuid"]
        return_value = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        body = {
            'efficiency': {'compression': 'none'}
        }

        self.client.disable_compression_async(fake.VOLUME_NAMES[0])

        self.client.send_request.assert_called_once_with(
            f'/storage/volumes/{uuid}', 'patch', body=body)
        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])

    def test_set_volume_max_files(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = volume["uuid"]
        return_value = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        fake_max_files = '40000'

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        body = {
            'files.maximum': int(fake_max_files)
        }

        self.client.set_volume_max_files(fake.VOLUME_NAMES[0], fake_max_files)

        self.client.send_request.assert_called_once_with(
            f'/storage/volumes/{uuid}', 'patch', body=body)
        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])

    def test_set_volume_snapdir_access(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = volume["uuid"]
        return_value = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        fake_hide_snapdir = 'fake-snapdir'

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        body = {
            'snapshot_directory_access_enabled': str(
                not fake_hide_snapdir).lower()
        }

        self.client.set_volume_snapdir_access(fake.VOLUME_NAMES[0],
                                              fake_hide_snapdir)

        self.client.send_request.assert_called_once_with(
            f'/storage/volumes/{uuid}', 'patch', body=body)
        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])

    def test_get_fpolicy_scopes(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = volume["uuid"]
        return_value = fake.GENERIC_FPOLICY_RESPONSE

        query = {
            'name': fake.FPOLICY_POLICY_NAME,
            'scope.include_shares': fake.VOLUME_NAMES[0],
            'scope.include_extension': fake.FPOLICY_EXT_TO_INCLUDE,
            'scope.exclude_extension': fake.FPOLICY_EXT_TO_EXCLUDE
        }

        expected_result = [
            {
                'policy-name': fake.FPOLICY_POLICY_NAME,
                'file-extensions-to-include': fake.FPOLICY_EXT_TO_INCLUDE_LIST,
                'file-extensions-to-exclude': fake.FPOLICY_EXT_TO_EXCLUDE_LIST,
                'shares-to-include': [fake.VOLUME_NAMES[0]],
            }
        ]

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        result = self.client.get_fpolicy_scopes(
            fake.VOLUME_NAMES[0], fake.FPOLICY_POLICY_NAME,
            fake.FPOLICY_EXT_TO_INCLUDE_LIST, fake.FPOLICY_EXT_TO_EXCLUDE_LIST,
            [fake.VOLUME_NAMES[0]])

        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])
        self.client.send_request.assert_called_once_with(
            f'/protocols/fpolicy/{uuid}/policies', 'get', query=query)

        self.assertEqual(expected_result, result)

    def test_get_fpolicy_policies_status(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = volume["uuid"]
        return_value = fake.GENERIC_FPOLICY_RESPONSE

        query = {
            'name': fake.FPOLICY_POLICY_NAME,
            'enabled': 'true'
        }

        expected_result = [
            {
                'policy-name': fake.FPOLICY_POLICY_NAME,
                'status': True,
                'sequence-number': 1
            }
        ]

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        result = self.client.get_fpolicy_policies_status(
            fake.VOLUME_NAMES[0], fake.FPOLICY_POLICY_NAME, 'true')

        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])
        self.client.send_request.assert_called_once_with(
            f'/protocols/fpolicy/{uuid}/policies', 'get', query=query)

        self.assertEqual(expected_result, result)

    def test_get_fpolicy_policies(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = volume["uuid"]
        return_value = fake.GENERIC_FPOLICY_RESPONSE

        query = {
            'name': fake.FPOLICY_POLICY_NAME,
            'engine.name': 'native',
            'events': fake.FPOLICY_EVENT_NAME
        }

        expected_result = [
            {
                'policy-name': fake.FPOLICY_POLICY_NAME,
                'engine-name': 'native',
                'events': [fake.FPOLICY_EVENT_NAME]
            }
        ]

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        result = self.client.get_fpolicy_policies(
            fake.VOLUME_NAMES[0], fake.FPOLICY_POLICY_NAME, 'native',
            [fake.FPOLICY_EVENT_NAME])

        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])
        self.client.send_request.assert_called_once_with(
            f'/protocols/fpolicy/{uuid}/policies', 'get', query=query)

        self.assertEqual(expected_result, result)

    def test_get_fpolicy_events(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = volume["uuid"]
        return_value = fake.GENERIC_FPOLICY_EVENTS_RESPONSE

        query = {
            'name': fake.FPOLICY_EVENT_NAME,
            'protocol': fake.FPOLICY_PROTOCOL,
            'fields': 'file_operations.create,file_operations.write,'
                      'file_operations.rename'
        }

        expected_result = [
            {
                'event-name': fake.FPOLICY_EVENT_NAME,
                'protocol': fake.FPOLICY_PROTOCOL,
                'file-operations': fake.FPOLICY_FILE_OPERATIONS_LIST
            }
        ]

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        result = self.client.get_fpolicy_events(
            fake.VOLUME_NAMES[0], fake.FPOLICY_EVENT_NAME,
            fake.FPOLICY_PROTOCOL, fake.FPOLICY_FILE_OPERATIONS_LIST)

        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])
        self.client.send_request.assert_called_once_with(
            f'/protocols/fpolicy/{uuid}/events', 'get', query=query)

        self.assertEqual(expected_result, result)

    def test_create_fpolicy_event(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = volume["uuid"]

        body = {
            'name': fake.FPOLICY_EVENT_NAME,
            'protocol': fake.FPOLICY_PROTOCOL,
            'file_operations.create': 'true',
            'file_operations.write': 'true',
            'file_operations.rename': 'true'
        }

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request')

        self.client.create_fpolicy_event(
            fake.VOLUME_NAMES[0], fake.FPOLICY_EVENT_NAME,
            fake.FPOLICY_PROTOCOL, fake.FPOLICY_FILE_OPERATIONS_LIST)

        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])
        self.client.send_request.assert_called_once_with(
            f'/protocols/fpolicy/{uuid}/events', 'post', body=body)

    def test_delete_fpolicy_policy(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = volume["uuid"]

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request')

        self.client.delete_fpolicy_policy(
            fake.VOLUME_NAMES[0], fake.FPOLICY_POLICY_NAME)

        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])
        self.client.send_request.assert_called_once_with(
            f'/protocols/fpolicy/{uuid}/policies/{fake.FPOLICY_POLICY_NAME}',
            'delete')

    def test_delete_fpolicy_event(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = volume["uuid"]

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request')

        self.client.delete_fpolicy_event(
            fake.VOLUME_NAMES[0], fake.FPOLICY_EVENT_NAME)

        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])
        self.client.send_request.assert_called_once_with(
            f'/protocols/fpolicy/{uuid}/events/{fake.FPOLICY_EVENT_NAME}',
            'delete')

    def test_enable_fpolicy_policy(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = volume["uuid"]

        body = {
            'priority': 1,
        }

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request')

        self.client.enable_fpolicy_policy(
            fake.VOLUME_NAMES[0], fake.FPOLICY_POLICY_NAME, 1)

        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])
        self.client.send_request.assert_called_once_with(
            f'/protocols/fpolicy/{uuid}/policies/{fake.FPOLICY_POLICY_NAME}',
            'patch', body=body)

    def test_create_fpolicy_policy_with_scope(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        uuid = volume["uuid"]

        body = {
            'name': fake.FPOLICY_POLICY_NAME,
            'events.name': fake.FPOLICY_EVENT_NAME,
            'engine.name': fake.FPOLICY_ENGINE,
            'scope.include_shares': [fake.VOLUME_NAMES[0]],
            'scope.include_extension': fake.FPOLICY_EXT_TO_INCLUDE_LIST,
            'scope.exclude_extension': fake.FPOLICY_EXT_TO_EXCLUDE_LIST
        }

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request')

        self.client.create_fpolicy_policy_with_scope(
            fake.FPOLICY_POLICY_NAME, fake.VOLUME_NAMES[0],
            fake.FPOLICY_EVENT_NAME, fake.FPOLICY_ENGINE,
            extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
            extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE)

        self.client._get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])
        self.client.send_request.assert_called_once_with(
            f'/protocols/fpolicy/{uuid}/policies', 'post', body=body)

    def test_delete_nfs_export_policy(self):
        policy_name = 'fake_policy_name'

        query = {
            'name': policy_name,
        }

        api_response = fake.EXPORT_POLICY_REST

        mock_sr = self.mock_object(self.client, 'send_request', mock.Mock(
                                   return_value=api_response))

        if not api_response.get('records'):
            return
        id = api_response.get('records')[0]['id']

        self.client.delete_nfs_export_policy(policy_name)

        mock_sr.assert_has_calls([
            mock.call('/protocols/nfs/export-policies', 'get',
                      query=query),
            mock.call(f'/protocols/nfs/export-policies/{id}', 'delete'),
        ])

    def test_delete_volume(self):
        """Deletes a volume."""
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))

        mock_sr = self.mock_object(self.client, 'send_request')
        # Get volume UUID.
        uuid = volume['uuid']

        self.client.delete_volume('fake_volume_name')

        mock_sr.assert_called_once_with(f'/storage/volumes/{uuid}', 'delete')

    def test__unmount_volume(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        mock_send_request = self.mock_object(self.client, 'send_request')
        uuid = volume['uuid']

        # Unmount volume async operation.
        body = {"nas": {"path": ""}}

        self.client._unmount_volume('fake_volume_name')
        mock_send_request.assert_called_once_with(
            f'/storage/volumes/{uuid}', 'patch', body=body)

    def test_offline_volume(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        mock_send_request = self.mock_object(self.client, 'send_request')
        uuid = volume['uuid']

        body = {'state': 'offline'}
        self.client.offline_volume('fake_volume_name')
        mock_send_request.assert_called_once_with(f'/storage/volumes/{uuid}',
                                                  'patch', body=body)

    def test_qos_policy_group_rename(self):
        """Renames a QoS policy group."""

        qos_policy_group_name = 'extreme'
        new_name = 'new_name'
        res = fake.QOS_POLICY_GROUP_REST
        mock_send_request = self.mock_object(self.client, 'send_request',
                                             mock.Mock(return_value=res))
        query = {
            'name': qos_policy_group_name,
            'fields': 'uuid',
        }
        uuid = res.get('records')[0]['uuid']
        body = {"name": new_name}

        self.client.qos_policy_group_rename(qos_policy_group_name, new_name)

        mock_send_request.assert_has_calls([
            mock.call('/storage/qos/policies', 'get', query=query),
            mock.call(f'/storage/qos/policies/{uuid}', 'patch',
                                                       body=body),
        ])

    def test_qos_policy_group_get(self):
        qos_policy_group_name = 'extreme'
        qos_policy_group = fake.QOS_POLICY_GROUP_REST
        qos_policy = qos_policy_group.get('records')[0]

        expected = {
            'policy-group': qos_policy.get('name'),
            'vserver': qos_policy.get('svm', {}).get('name'),
            'max-throughput': qos_policy.get('fixed', {}).get(
                'max_throughput_iops'),
            'num-workloads': int(qos_policy.get('object_count')),
            }

        query = {
            'name': qos_policy_group_name,
            'fields': 'name,object_count,fixed.max_throughput_iops,svm.name',
        }

        mock_sr = self.mock_object(self.client, 'send_request',
                                   mock.Mock(return_value=qos_policy_group))

        result = self.client.qos_policy_group_get(qos_policy_group_name)
        mock_sr.assert_called_once_with('/storage/qos/policies', 'get',
                                        query=query)
        self.assertEqual(expected, result)

    def test_remove_unused_qos_policy_groups(self):

        result = fake.QOS_POLICY_GROUP_REST

        query = {
            'name': '%s*' % client_cmode_rest.DELETED_PREFIX,
            'fields': 'uuid,name',
        }

        mock_send_request = self.mock_object(self.client, 'send_request',
                                             mock.Mock(return_value=result))

        res = result.get('records')
        for record in res:
            uuid = record['uuid']

        self.client.remove_unused_qos_policy_groups()

        mock_send_request.assert_has_calls([
            mock.call('/storage/qos/policies', 'get', query=query),
            mock.call(f'/storage/qos/policies/{uuid}', 'delete')])

    def test_unmount_volume(self):

        self.mock_object(self.client, '_unmount_volume')

        self.client.unmount_volume(fake.SHARE_NAME)

        self.client._unmount_volume.assert_called_once_with(fake.SHARE_NAME)
        self.assertEqual(1, client_cmode_rest.LOG.debug.call_count)
        self.assertEqual(0, client_cmode_rest.LOG.warning.call_count)

    def test_unmount_volume_api_error(self):

        self.mock_object(self.client,
                         '_unmount_volume',
                         self._mock_api_error())

        self.assertRaises(netapp_api.api.NaApiError,
                          self.client.unmount_volume,
                          fake.SHARE_NAME)

        self.assertEqual(1, self.client._unmount_volume.call_count)
        self.assertEqual(0, client_cmode_rest.LOG.debug.call_count)
        self.assertEqual(0, client_cmode_rest.LOG.warning.call_count)

    def test_unmount_volume_with_retries(self):

        side_effect = [netapp_api.api.NaApiError(code=netapp_api.api.EAPIERROR,
                                                 message='...job ID...')] * 5
        side_effect.append(None)
        self.mock_object(self.client,
                         '_unmount_volume',
                         mock.Mock(side_effect=side_effect))
        self.mock_object(time, 'sleep')

        self.client.unmount_volume(fake.SHARE_NAME)

        self.assertEqual(6, self.client._unmount_volume.call_count)
        self.assertEqual(1, client_cmode_rest.LOG.debug.call_count)
        self.assertEqual(5, client_cmode_rest.LOG.warning.call_count)

    def test_unmount_volume_with_max_retries(self):

        side_effect = [netapp_api.api.NaApiError(code=netapp_api.api.EAPIERROR,
                                                 message='...job ID...')] * 30
        self.mock_object(self.client,
                         '_unmount_volume',
                         mock.Mock(side_effect=side_effect))
        self.mock_object(time, 'sleep')

        self.assertRaises(exception.NetAppException,
                          self.client.unmount_volume,
                          fake.SHARE_NAME)

        self.assertEqual(10, self.client._unmount_volume.call_count)
        self.assertEqual(0, client_cmode_rest.LOG.debug.call_count)
        self.assertEqual(10, client_cmode_rest.LOG.warning.call_count)

    def test_qos_policy_group_exists(self):
        mock = self.mock_object(self.client, 'qos_policy_group_get')
        response = self.client.qos_policy_group_exists('extreme')
        mock.assert_called_once()
        self.assertTrue(response)

    def test_mark_qos_policy_group_for_deletion(self):
        mock_exists = self.mock_object(self.client, 'qos_policy_group_exists',
                                       mock.Mock(return_value=True))
        mock_rename = self.mock_object(self.client, 'qos_policy_group_rename')
        mk_r = self.mock_object(self.client, 'remove_unused_qos_policy_groups')

        self.client.mark_qos_policy_group_for_deletion('extreme')

        mock_exists.assert_called_once()
        mock_rename.assert_called_once()
        mk_r.assert_called_once()

    def test_set_volume_size(self):
        unique_volume_return = {'uuid': 'teste'}
        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=unique_volume_return))
        mock_sr = self.mock_object(self.client, 'send_request')
        self.client.set_volume_size('fake_name', 1)

        mock_sr.assert_called_once()

    def test_qos_policy_group_modify(self):
        return_request = {
            'records': [{'uuid': 'fake_uuid'}]
        }
        mock_sr = self.mock_object(self.client, 'send_request',
                                   mock.Mock(return_value=return_request))
        self.client.qos_policy_group_modify('qos_fake_name', '1000iops')

        query = {
            'name': 'qos_fake_name',
        }
        body = {
            'fixed.max_throughput_iops': 1000
        }
        mock_sr.assert_has_calls([
            mock.call('/storage/qos/policies', 'get', query=query),
            mock.call('/storage/qos/policies/fake_uuid', 'patch', body=body),
        ])

    @ddt.data(True, False)
    def test_set_volume_filesys_size_fixed(self, filesys_size_fixed):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        mock_send_request = self.mock_object(self.client, 'send_request')
        fake_uuid = volume['uuid']

        self.client.set_volume_filesys_size_fixed(fake.SHARE_NAME,
                                                  filesys_size_fixed)
        body = {
            'space.filesystem_size_fixed': filesys_size_fixed}
        mock_send_request.assert_called_once_with(
            f'/storage/volumes/{fake_uuid}',
            'patch', body=body)

    def test_create_snapshot(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        mock_get_volume = self.mock_object(
            self.client, '_get_volume_by_args',
            mock.Mock(return_value=volume))
        mock_send_request = self.mock_object(self.client, 'send_request')

        self.client.create_snapshot(fake.VOLUME_NAMES[0], fake.SNAPSHOT_NAME)

        mock_get_volume.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])
        body = {
            'name': fake.SNAPSHOT_NAME,
        }
        uuid = volume['uuid']
        mock_send_request.assert_called_once_with(
            f'/storage/volumes/{uuid}/snapshots', 'post', body=body)

    def test_is_flexgroup_supported(self):
        flexgroup_supported = self.client.is_flexgroup_supported()

        self.assertTrue(flexgroup_supported)

    @ddt.data(True, False)
    def test_is_flexgroup_volume(self, is_flexgroup):
        response = copy.deepcopy(fake.VOLUME_LIST_SIMPLE_RESPONSE_REST)
        expected_style = 'flexgroup' if is_flexgroup else 'flexvol'
        response['records'][0]['style'] = expected_style
        mock_send_request = self.mock_object(self.client, 'send_request',
                                             mock.Mock(return_value=response))
        mock_has_records = self.mock_object(
            self.client, '_has_records', mock.Mock(return_value=True))
        mock_na_utils_is_flexgroup = self.mock_object(
            netapp_utils, 'is_style_extended_flexgroup',
            mock.Mock(return_value=is_flexgroup))

        result = self.client.is_flexgroup_volume(fake.VOLUME_NAMES[0])

        self.assertEqual(is_flexgroup, result)
        query = {
            'name': fake.VOLUME_NAMES[0],
            'fields': 'style'
        }
        mock_send_request.assert_called_once_with('/storage/volumes/', 'get',
                                                  query=query)
        mock_has_records.assert_called_once_with(response)
        mock_na_utils_is_flexgroup.assert_called_once_with(expected_style)

    def test_is_flexgroup_volume_raise_no_records(self):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=fake.NO_RECORDS_RESPONSE_REST))
        self.mock_object(
            self.client, '_has_records', mock.Mock(return_value=False))

        self.assertRaises(
            exception.StorageResourceNotFound,
            self.client.is_flexgroup_volume,
            fake.VOLUME_NAMES[0])

    def test_is_flexgroup_volume_raise_more_than_one_volume(self):
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=fake.VOLUME_GET_ITER_RESPONSE_REST_PAGE))
        self.mock_object(
            self.client, '_has_records', mock.Mock(return_value=True))

        self.assertRaises(
            exception.NetAppException,
            self.client.is_flexgroup_volume,
            fake.VOLUME_NAMES[0])

    @ddt.data(
        {'is_busy': True, 'owners': ['volume_clone']},
        {'is_busy': False, 'owners': ['snap_restore_dependent']})
    @ddt.unpack
    def test__is_busy_snapshot(self, is_busy, owners):
        result = self.client._is_busy_snapshot(owners)

        self.assertEqual(is_busy, result)

    @ddt.data(True, False)
    def test_get_snapshot(self, locked):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        mock_get_volume = self.mock_object(
            self.client, '_get_volume_by_args',
            mock.Mock(return_value=volume))
        response = copy.deepcopy(fake.SNAPSHOTS_REST_RESPONSE)
        owners = ['volume_clone'] if locked else []
        response['records'][0]['owners'] = owners
        mock_send_request = self.mock_object(self.client, 'send_request',
                                             mock.Mock(return_value=response))
        mock_has_records = self.mock_object(
            self.client, '_has_records', mock.Mock(return_value=True))

        mock_is_busy = self.mock_object(self.client, '_is_busy_snapshot',
                                        mock.Mock(return_value=True))

        result = self.client.get_snapshot(fake.VOLUME_NAMES[0],
                                          fake.SNAPSHOT_NAME)

        expected_snapshot = {
            'access-time': fake.SNAPSHOT_REST['create_time'],
            'name': fake.SNAPSHOT_REST['name'],
            'volume': fake.SNAPSHOT_REST['volume']['name'],
            'owners': set(owners),
            'busy': True,
            'locked_by_clone': locked,
        }
        self.assertEqual(expected_snapshot, result)
        mock_get_volume.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])
        uuid = volume['uuid']
        query = {
            'name': fake.SNAPSHOT_NAME,
            'fields': 'name,volume,create_time,owners'
        }
        mock_send_request.assert_called_once_with(
            f'/storage/volumes/{uuid}/snapshots', 'get', query=query)
        mock_has_records.assert_called_once_with(response)
        mock_is_busy.assert_called_once_with(set(owners))

    def test_get_snapshot_raise_not_found(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        self.mock_object(
            self.client, '_get_volume_by_args',
            mock.Mock(return_value=volume))
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=fake.NO_RECORDS_RESPONSE_REST))
        self.mock_object(
            self.client, '_has_records', mock.Mock(return_value=False))

        self.assertRaises(
            exception.SnapshotResourceNotFound,
            self.client.get_snapshot,
            fake.VOLUME_NAMES[0],
            fake.SNAPSHOT_NAME)

    def test_get_snapshot_raise_more_than_one(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        self.mock_object(
            self.client, '_get_volume_by_args',
            mock.Mock(return_value=volume))
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=fake.SNAPSHOTS_MULTIPLE_REST_RESPONSE))
        self.mock_object(
            self.client, '_has_records', mock.Mock(return_value=True))

        self.assertRaises(
            exception.NetAppException,
            self.client.get_snapshot,
            fake.VOLUME_NAMES[0],
            fake.SNAPSHOT_NAME)

    def test_get_clone_children_for_snapshot(self):
        mock_get_records = self.mock_object(
            self.client, 'get_records',
            mock.Mock(return_value=fake.VOLUME_LIST_SIMPLE_RESPONSE_REST))

        result = self.client.get_clone_children_for_snapshot(
            fake.VOLUME_NAMES[0], fake.SNAPSHOT_NAME)

        expected_children = [{'name': fake.VOLUME_NAMES[0]}]
        self.assertEqual(expected_children, result)
        query = {
            'clone.parent_snapshot.name': fake.SNAPSHOT_NAME,
            'clone.parent_volume.name': fake.VOLUME_NAMES[0],
            'fields': 'name'
        }
        mock_get_records.assert_called_once_with(
            '/storage/volumes', query=query)

    def test_split_volume_clone(self):
        mock_send_request = self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=fake.VOLUME_LIST_SIMPLE_RESPONSE_REST))

        self.client.split_volume_clone(fake.VOLUME_NAMES[0])

        query = {
            'name': fake.VOLUME_NAMES[0],
        }
        body = {
            'clone.split_initiated': 'true',
        }
        mock_send_request.assert_called_once_with(
            '/storage/volumes/', 'patch', query=query, body=body,
            wait_on_accepted=False)

    def test_rename_snapshot(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        mock_get_volume = self.mock_object(
            self.client, '_get_volume_by_args',
            mock.Mock(return_value=volume))
        mock_send_request = self.mock_object(self.client, 'send_request')

        self.client.rename_snapshot(
            fake.VOLUME_NAMES[0], fake.SNAPSHOT_NAME,
            'new_' + fake.SNAPSHOT_NAME)

        mock_get_volume.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])
        query = {
            'name': fake.SNAPSHOT_NAME,
        }
        body = {
            'name': 'new_' + fake.SNAPSHOT_NAME,
        }
        uuid = volume['uuid']
        mock_send_request.assert_called_once_with(
            f'/storage/volumes/{uuid}/snapshots', 'patch', query=query,
            body=body)

    def test__get_soft_deleted_snapshots(self):
        mock_get_records = self.mock_object(
            self.client, 'get_records',
            mock.Mock(return_value=fake.SNAPSHOTS_MULTIPLE_REST_RESPONSE))
        self.mock_object(
            self.client, '_is_busy_snapshot',
            mock.Mock(side_effect=[True, False]))

        snapshots_map = self.client._get_soft_deleted_snapshots()

        expected_snapshots = {
            fake.VSERVER_NAME: [{
                "uuid": fake.FAKE_SNAPSHOT_UUID,
                "volume_uuid": fake.FAKE_VOLUME_UUID,
            }]
        }
        self.assertEqual(expected_snapshots, snapshots_map)
        query = {
            'name': 'deleted_manila_*',
            'fields': 'uuid,volume,owners,svm.name'
        }
        mock_get_records.assert_called_once_with(
            '/storage/volumes/*/snapshots', query=query)

    @ddt.data(True, False)
    def test_prune_deleted_snapshots(self, fail_deleting):
        soft_deleted_snapshots = {
            fake.VSERVER_NAME: [{
                "uuid": fake.FAKE_SNAPSHOT_UUID,
                "volume_uuid": fake.FAKE_VOLUME_UUID,
            }]
        }
        mock_get_snaps = self.mock_object(
            self.client, '_get_soft_deleted_snapshots',
            mock.Mock(return_value=soft_deleted_snapshots)
        )
        if fail_deleting:
            mock_send_request = self.mock_object(
                self.client, 'send_request',
                mock.Mock(side_effect=netapp_api.api.NaApiError))
        else:
            mock_send_request = self.mock_object(self.client, 'send_request')

        self.client.prune_deleted_snapshots()

        mock_get_snaps.assert_called_once_with()
        vol_uuid = fake.FAKE_VOLUME_UUID
        snap_uuid = fake.FAKE_SNAPSHOT_UUID
        mock_send_request.assert_called_once_with(
            f'/storage/volumes/{vol_uuid}/snapshots/{snap_uuid}', 'delete')

    @ddt.data(True, False)
    def test_snapshot_exists(self, exists):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        vol_uuid = volume['uuid']
        mock_get_vol = self.mock_object(
            self.client, '_get_volume_by_args',
            mock.Mock(return_value=volume))
        mock_send_request = self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=fake.SNAPSHOTS_REST_RESPONSE))
        mock_has_records = self.mock_object(self.client, '_has_records',
                                            mock.Mock(return_value=exists))

        res = self.client.snapshot_exists(fake.SNAPSHOT_NAME,
                                          fake.VOLUME_NAMES[0])

        self.assertEqual(exists, res)
        mock_get_vol.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0])
        query = {
            'name': fake.SNAPSHOT_NAME
        }
        mock_send_request.assert_called_once_with(
            f'/storage/volumes/{vol_uuid}/snapshots/', 'get', query=query)
        mock_has_records.assert_called_once_with(fake.SNAPSHOTS_REST_RESPONSE)

    @ddt.data('source', 'destination', None)
    def test_volume_has_snapmirror_relationships(self, snapmirror_rel_type):
        """Snapmirror relationships can be both ways."""

        vol = fake.FAKE_MANAGE_VOLUME
        snapmirror = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
            'mirror-state': 'snapmirrored',
            'schedule': 'daily',
        }
        expected_get_snapmirrors_call_count = 2
        expected_get_snapmirrors_calls = [
            mock.call(source_vserver=vol['owning-vserver-name'],
                      source_volume=vol['name']),
            mock.call(dest_vserver=vol['owning-vserver-name'],
                      dest_volume=vol['name']),
        ]
        if snapmirror_rel_type is None:
            side_effect = ([], [])
        elif snapmirror_rel_type == 'source':
            snapmirror['source-vserver'] = vol['owning-vserver-name']
            snapmirror['source-volume'] = vol['name']
            side_effect = ([snapmirror], None)
            expected_get_snapmirrors_call_count = 1
            expected_get_snapmirrors_calls.pop()
        else:
            snapmirror['destination-vserver'] = vol['owning-vserver-name']
            snapmirror['destination-volume'] = vol['name']
            side_effect = (None, [snapmirror])
        mock_get_snapmirrors_call = self.mock_object(
            self.client, 'get_snapmirrors', mock.Mock(side_effect=side_effect))
        mock_exc_log = self.mock_object(client_cmode.LOG, 'exception')
        expected_retval = True if snapmirror_rel_type else False

        retval = self.client.volume_has_snapmirror_relationships(vol)

        self.assertEqual(expected_retval, retval)
        self.assertEqual(expected_get_snapmirrors_call_count,
                         mock_get_snapmirrors_call.call_count)
        mock_get_snapmirrors_call.assert_has_calls(
            expected_get_snapmirrors_calls)
        self.assertFalse(mock_exc_log.called)

    def test_volume_has_snapmirror_relationships_api_error(self):

        vol = fake.FAKE_MANAGE_VOLUME
        expected_get_snapmirrors_calls = [
            mock.call(source_vserver=vol['owning-vserver-name'],
                      source_volume=vol['name']),
        ]
        mock_get_snapmirrors_call = self.mock_object(
            self.client, 'get_snapmirrors', mock.Mock(
                side_effect=self._mock_api_error()))
        mock_exc_log = self.mock_object(client_cmode_rest.LOG, 'exception')

        retval = self.client.volume_has_snapmirror_relationships(vol)

        self.assertFalse(retval)
        self.assertEqual(1, mock_get_snapmirrors_call.call_count)
        mock_get_snapmirrors_call.assert_has_calls(
            expected_get_snapmirrors_calls)
        self.assertTrue(mock_exc_log.called)

    def test_get_snapmirrors(self):

        api_response = fake.SNAPMIRROR_GET_ITER_RESPONSE_REST
        mock_send_request = self.mock_object(
            self.client,
            'send_request',
            mock.Mock(return_value=api_response))

        result = self.client.get_snapmirrors(
            fake.SM_SOURCE_PATH, fake.SM_DEST_PATH,
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

        expected = fake.REST_GET_SNAPMIRRORS_RESPONSE

        query = {
            'source.path': (fake.SM_SOURCE_VSERVER + ':' +
                            fake.SM_SOURCE_VOLUME),
            'destination.path': (fake.SM_DEST_VSERVER +
                                 ':' + fake.SM_DEST_VOLUME),
            'fields': 'state,source.svm.name,source.path,destination.svm.name,'
                      'destination.path,transfer.end_time,uuid,policy.type'
        }

        mock_send_request.assert_called_once_with('/snapmirror/relationships',
                                                  'get', query=query)
        self.assertEqual(expected, result)

    @ddt.data(
        {'source_path': fake.SM_SOURCE_PATH, 'dest_path': fake.SM_DEST_PATH},
        {'source_path': None, 'dest_path': None})
    @ddt.unpack
    def test__get_snapmirrors(self, source_path, dest_path):

        api_response = fake.SNAPMIRROR_GET_ITER_RESPONSE_REST
        mock_send_request = self.mock_object(
            self.client,
            'send_request',
            mock.Mock(return_value=api_response))

        result = self.client._get_snapmirrors(
            source_path, dest_path,
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

        query = {
            'source.path': (fake.SM_SOURCE_VSERVER + ':' +
                            fake.SM_SOURCE_VOLUME),
            'destination.path': (fake.SM_DEST_VSERVER +
                                 ':' + fake.SM_DEST_VOLUME),
            'fields': 'state,source.svm.name,source.path,destination.svm.name,'
                      'destination.path,transfer.end_time,uuid,policy.type'
        }

        mock_send_request.assert_called_once_with('/snapmirror/relationships',
                                                  'get', query=query)
        self.assertEqual(1, len(result))

    def test__get_snapmirrors_not_found(self):

        api_response = fake.NO_RECORDS_RESPONSE_REST
        mock_send_request = self.mock_object(
            self.client,
            'send_request',
            mock.Mock(return_value=api_response))

        result = self.client._get_snapmirrors(
            fake.SM_SOURCE_PATH, fake.SM_DEST_PATH,
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

        query = {
            'source.path': (fake.SM_SOURCE_VSERVER + ':' +
                            fake.SM_SOURCE_VOLUME),
            'destination.path': (fake.SM_DEST_VSERVER +
                                 ':' + fake.SM_DEST_VOLUME),
            'fields': 'state,source.svm.name,source.path,destination.svm.name,'
                      'destination.path,transfer.end_time,uuid,policy.type'
        }

        mock_send_request.assert_called_once_with('/snapmirror/relationships',
                                                  'get', query=query)
        self.assertEqual([], result)

    @ddt.data(True, False)
    def test_modify_volume_no_optional_args(self, is_flexgroup):

        self.mock_object(self.client, 'send_request')
        mock_update_volume_efficiency_attributes = self.mock_object(
            self.client, 'update_volume_efficiency_attributes')

        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))

        aggr = fake.SHARE_AGGREGATE_NAME
        if is_flexgroup:
            aggr = list(fake.SHARE_AGGREGATE_NAMES)

        self.client.modify_volume(aggr, fake.SHARE_NAME)

        # default body for call with no optional params
        body = {'guarantee': {'type': 'volume'}}
        self.client.send_request.assert_called_once_with(
            '/storage/volumes/' + volume['uuid'], 'patch', body=body)
        mock_update_volume_efficiency_attributes.assert_called_once_with(
            fake.SHARE_NAME, False, False, is_flexgroup=is_flexgroup)

    @ddt.data((fake.QOS_POLICY_GROUP_NAME, None),
              (None, fake.ADAPTIVE_QOS_POLICY_GROUP_NAME))
    @ddt.unpack
    def test_modify_volume_all_optional_args(self, qos_group,
                                             adaptive_qos_group):
        self.client.features.add_feature('ADAPTIVE_QOS')
        self.mock_object(self.client, 'send_request')
        mock_update_volume_efficiency_attributes = self.mock_object(
            self.client, 'update_volume_efficiency_attributes')

        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))

        self.client.modify_volume(
            fake.SHARE_AGGREGATE_NAME,
            fake.SHARE_NAME,
            thin_provisioned=True,
            snapshot_policy=fake.SNAPSHOT_POLICY_NAME,
            language=fake.LANGUAGE,
            dedup_enabled=True,
            compression_enabled=False,
            max_files=fake.MAX_FILES,
            qos_policy_group=qos_group,
            adaptive_qos_policy_group=adaptive_qos_group,
            autosize_attributes=fake.VOLUME_AUTOSIZE_ATTRS,
            hide_snapdir=True)

        qos_policy_name = qos_group or adaptive_qos_group
        body = {
            'guarantee': {'type': 'none'},
            'autosize': {
                'mode': 'off',
                'grow_threshold': '85',
                'shrink_threshold': '50',
                'maximum': '1258288',
                'minimum': '1048576'
            },
            'files': {'maximum': 5000},
            'snapshot_policy': {'name': 'fake_snapshot_policy'},
            'qos': {'policy': {'name': qos_policy_name}},
            'snapshot_directory_access_enabled': 'false',
            'language': 'fake_language'
        }

        self.client.send_request.assert_called_once_with(
            '/storage/volumes/' + volume['uuid'], 'patch', body=body)
        mock_update_volume_efficiency_attributes.assert_called_once_with(
            fake.SHARE_NAME, True, False, is_flexgroup=False)

    def test__parse_timestamp(self):
        test_time_str = '2022-11-25T14:41:20+00:00'
        res = self.client._parse_timestamp(test_time_str)
        self.assertEqual(1669387280.0, res)

    def test__parse_timestamp_exception(self):
        test_time_str = None
        self.assertRaises(TypeError,
                          self.client._parse_timestamp,
                          test_time_str)

    def test_get_nfs_export_policy_for_volume(self):

        fake_query = {
            'name': 'fake_volume_name',
            'fields': 'nas.export_policy.name'
        }

        ret = {
            'records': [
                {
                    'nas': {
                        'export_policy': {
                            'name': 'fake_name'
                        }
                    }
                }
            ]
        }

        mock_records = self.mock_object(self.client, '_has_records',
                                        mock.Mock(return_value=True))
        mock_sr = self.mock_object(self.client, 'send_request',
                                   mock.Mock(return_value=ret))

        res = self.client.get_nfs_export_policy_for_volume('fake_volume_name')

        mock_records.assert_called_once_with(ret)
        mock_sr.assert_called_once_with('/storage/volumes/', 'get',
                                        query=fake_query)
        expected = 'fake_name'
        self.assertEqual(expected, res)

    def test_get_unique_export_policy_id(self):
        mock_records = self.mock_object(self.client, '_has_records',
                                        mock.Mock(return_value=True))
        expected = 'fake_uuid'
        ret = {
            'records': [
                {
                    'id': 'fake_uuid'
                }
            ]
        }
        mock_sr = self.mock_object(self.client, 'send_request',
                                   mock.Mock(return_value=ret))
        res = self.client.get_unique_export_policy_id('fake_policy_name')
        mock_records.assert_called_once_with(ret)
        mock_sr.assert_called_once_with(
            '/protocols/nfs/export-policies', 'get',
            query={'name': 'fake_policy_name'})
        self.assertEqual(expected, res)

    def test__get_nfs_export_rule_indices(self):
        mockpid = self.mock_object(self.client, 'get_unique_export_policy_id',
                                   mock.Mock(return_value='fake_policy_id'))

        fake_uuid = 'fake_policy_id'

        fake_query = {
            'clients.match': 'fakecl',
            'fields': 'clients.match,index'
        }

        ret = {
            'records': [
                {
                    'index': '0'
                }
            ]
        }

        mock_sr = self.mock_object(self.client, 'send_request',
                                   mock.Mock(return_value=ret))
        res = self.client._get_nfs_export_rule_indices('fake_policy', 'fakecl')
        mockpid.assert_called_once_with('fake_policy')
        mock_sr.assert_called_once_with(
            f'/protocols/nfs/export-policies/{fake_uuid}/rules', 'get',
            query=fake_query)
        expected = ['0']
        self.assertEqual(expected, res)

    def test__add_nfs_export_rule(self):
        mockpid = self.mock_object(self.client, 'get_unique_export_policy_id',
                                   mock.Mock(return_value='fake_policy_id'))
        mock_sr = self.mock_object(self.client, 'send_request')
        self.client._add_nfs_export_rule('fake_policy', 'fakecl', False,
                                         ['rw'])
        mockpid.assert_called_once_with('fake_policy')

        body = {
            'clients': [{'match': 'fakecl'}],
            'ro_rule': ['rw'],
            'rw_rule': ['rw'],
            'superuser': ['rw']
        }
        mock_sr.assert_called_once_with(
            '/protocols/nfs/export-policies/fake_policy_id/rules',
            'post', body=body)

    def test__update_nfs_export_rule(self):

        fake_body = {
            'client_match': 'fake_cli',
            'ro_rule': ['rw'],
            'rw_rule': ['rw'],
            'superuser': ['rw']
        }

        mockpid = self.mock_object(self.client, 'get_unique_export_policy_id',
                                   mock.Mock(return_value='fake_policy_id'))
        mock_sr = self.mock_object(self.client, 'send_request')
        self.client._update_nfs_export_rule('fake_policy', 'fake_cli', False,
                                            '0', ['rw'])
        mockpid.assert_called_once_with('fake_policy')
        mock_sr.assert_called_once_with(
            '/protocols/nfs/export-policies/fake_policy_id/rules/0',
            'patch', body=fake_body)

    def test__remove_nfs_export_rules(self):

        fake_body = {
            'index': 0
        }

        mockpid = self.mock_object(self.client, 'get_unique_export_policy_id',
                                   mock.Mock(return_value='fake_policy_id'))
        mock_sr = self.mock_object(self.client, 'send_request')
        self.client._remove_nfs_export_rules('fake_policy', [0])
        mockpid.assert_called_once_with('fake_policy')
        mock_sr.assert_called_once_with(
            '/protocols/nfs/export-policies/fake_policy_id/rules/0', 'delete',
            body=fake_body)

    def test_modify_cifs_share_access(self):
        return_uuid = fake.GENERIC_EXPORT_POLICY_RESPONSE_AND_VOLUMES
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_uuid))
        self.client.modify_cifs_share_access(fake.SHARE_NAME, fake.USER_NAME,
                                             'read')
        fake_user = 'fake_user'
        FAKE_CIFS_USER_GROUP_TYPE = 'windows'
        fake_uuid = 'fake_uuid'
        fake_share = fake.SHARE_NAME
        query = {'name': 'fake_share'}
        body = {'permission': 'read'}

        self.client.send_request.assert_has_calls([
            mock.call('/protocols/cifs/shares', 'get', query=query),
            mock.call(f'/protocols/cifs/shares/{fake_uuid}/{fake_share}'
                      f'/acls/{fake_user}/{FAKE_CIFS_USER_GROUP_TYPE}',
                      'patch', body=body)])

    def test_add_cifs_share_access(self):
        return_uuid = fake.GENERIC_EXPORT_POLICY_RESPONSE_AND_VOLUMES
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_uuid))
        self.client.add_cifs_share_access(fake.SHARE_NAME,
                                          fake.USER_NAME, 'read')
        fake_uuid = "fake_uuid"
        query = {'name': 'fake_share'}
        body = {'permission': 'read',
                'user_or_group': 'fake_user'}
        self.client.send_request.assert_has_calls([
            mock.call('/protocols/cifs/shares', 'get', query=query),
            mock.call(f'/protocols/cifs/shares/{fake_uuid}/{fake.SHARE_NAME}'
                      '/acls', 'post', body=body)])

    def test_get_cifs_share_access_rules_empty(self):
        return_uuid = fake.GENERIC_EXPORT_POLICY_RESPONSE_AND_VOLUMES
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_uuid))

    def test_get_cifs_share_access_rules_not_empty(self):
        return_uuid = fake.GENERIC_EXPORT_POLICY_RESPONSE_AND_VOLUMES
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_uuid))

        rules = {}

        fake_results = fake.FAKE_CIFS_RECORDS

        for record in fake_results['records']:
            user_or_group = record['user_or_group']
            permission = record['permission']
            rules[user_or_group] = permission

    def test_mount_volume(self):
        volume_name = fake.SHARE_NAME
        junction_path = '/fake_path'
        volume = fake.VOLUME

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request')

        self.client.mount_volume(volume_name, junction_path=junction_path)

        uuid = volume['uuid']

        body = {
            'nas.path': (junction_path if junction_path
                         else '/%s' % volume_name)
        }

        self.client.send_request.assert_called_once_with(
            f'/storage/volumes/{uuid}', 'patch', body=body)

    def test_set_volume_name(self):
        volume_name = fake.SHARE_NAME
        new_volume_name = 'fake_name'

        volume = fake.VOLUME

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request')

        self.client.set_volume_name(volume_name, new_volume_name)

        uuid = volume['uuid']

        body = {
            'name': new_volume_name
        }

        self.client.send_request.assert_called_once_with(
            f'/storage/volumes/{uuid}', 'patch', body=body)

    def test__get_security_key_manager_nve_support_enabled(self):
        api_response = fake.SECUTITY_KEY_MANAGER_SUPPORT_RESPONSE_TRUE_REST
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client._get_security_key_manager_nve_support()

        self.assertTrue(result)

        query = {'fields': 'volume_encryption.*'}
        self.client.send_request.assert_has_calls([
            mock.call('/security/key-managers', 'get', query=query)])

    def test__get_security_key_manager_nve_support_disabled(self):
        api_response = fake.SECUTITY_KEY_MANAGER_SUPPORT_RESPONSE_FALSE_REST
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client._get_security_key_manager_nve_support()

        self.assertFalse(result)

        query = {'fields': 'volume_encryption.*'}
        self.client.send_request.assert_has_calls([
            mock.call('/security/key-managers', 'get', query=query)])

    def test__get_security_key_manager_nve_support_no_records(self):
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=fake.NO_RECORDS_RESPONSE_REST))

        result = self.client._get_security_key_manager_nve_support()

        self.assertFalse(result)

        query = {'fields': 'volume_encryption.*'}
        self.client.send_request.assert_has_calls([
            mock.call('/security/key-managers', 'get', query=query)])

    def test__get_security_key_manager_nve_support_no_license(self):
        self.mock_object(self.client,
                         'send_request',
                         self._mock_api_error())

        result = self.client._get_security_key_manager_nve_support()

        self.assertFalse(result)

        query = {'fields': 'volume_encryption.*'}
        self.client.send_request.assert_has_calls([
            mock.call('/security/key-managers', 'get', query=query)])

    def test_get_job(self):
        mock_sr = self.mock_object(self.client, 'send_request')
        self.client.get_job('fake_job_uuid')
        mock_sr.assert_called_once_with('/cluster/jobs/fake_job_uuid',
                                        'get', enable_tunneling=False)

    @ddt.data(netapp_api.EREST_VSERVER_NOT_FOUND, 'fake')
    def test_vserver_exists_exception(self, er):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error(code=er)))
        if er == netapp_api.EREST_VSERVER_NOT_FOUND:
            result = self.client.vserver_exists(fake.VSERVER_NAME)
            self.assertFalse(result)
        else:
            self.assertRaises(netapp_api.api.NaApiError,
                              self.client.vserver_exists,
                              fake.VSERVER_NAME)

    def test__get_aggregate_disk_types(self):
        response = fake.FAKE_DISK_TYPE_RESPONSE
        aggr = fake.SHARE_AGGREGATE_NAME
        mock_sr = self.mock_object(self.client, 'send_request',
                                   mock.Mock(return_value=response))
        query = {
            'aggregates.name': aggr,
            'fields': 'effective_type'
        }
        expected = {'fakedisk'}

        result = self.client._get_aggregate_disk_types(aggr)

        mock_sr.assert_called_once_with('/storage/disks', 'get', query=query)
        self.assertEqual(expected, result)

    def test__get_aggregate_disk_types_exception(self):
        aggr = fake.SHARE_AGGREGATE_NAME
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error()))
        result = self.client._get_aggregate_disk_types(aggr)
        self.assertEqual(set(), result)

    def test_create_nfs_export_policy_exception(self):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error()))
        self.assertRaises(netapp_api.api.NaApiError,
                          self.client.create_nfs_export_policy,
                          fake.EXPORT_POLICY_NAME)

    @ddt.data(True, False)
    def test__get_create_volume_body(self, thin_provisioned):
        expected = {
            'type': 'fake_type',
            'guarantee.type': ('none' if thin_provisioned else 'volume'),
            'nas.path': '/%s' % fake.VOLUME_NAMES[0],
            'snapshot_policy.name': fake.SNAPSHOT_POLICY_NAME,
            'language': 'fake_language',
            'space.snapshot.reserve_percent': 'fake_percent',
            'qos.policy.name': fake.QOS_POLICY_GROUP_NAME,
            'svm.name': 'fake_vserver',
            'encryption.enabled': 'true'
        }

        self.mock_object(self.client.connection, 'get_vserver',
                         mock.Mock(return_value='fake_vserver'))
        res = self.client._get_create_volume_body(fake.VOLUME_NAMES[0],
                                                  thin_provisioned,
                                                  fake.SNAPSHOT_POLICY_NAME,
                                                  'fake_language',
                                                  'fake_percent',
                                                  'fake_type',
                                                  fake.QOS_POLICY_GROUP_NAME,
                                                  True,
                                                  fake.QOS_POLICY_GROUP_NAME)
        self.assertEqual(expected, res)

    def test_get_job_state(self):
        expected = 'success'
        query = {
            'uuid': 'fake_uuid',
            'fields': 'state'
        }
        response = {
            'records': [fake.JOB_SUCCESSFUL_REST]
        }
        mock_sr = self.mock_object(self.client, 'send_request',
                                   mock.Mock(return_value=response))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))
        result = self.client.get_job_state('fake_uuid')
        mock_sr.assert_called_once_with('/cluster/jobs/', 'get', query=query,
                                        enable_tunneling=False)
        self.assertEqual(expected, result)

    def test_get_job_state_not_found(self):
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=False))
        self.assertRaises(exception.NetAppException,
                          self.client.get_job_state,
                          'fake_uuid')

    @ddt.data(True, False)
    def test_update_volume_efficiency_attributes(self, status):
        response = {
            'dedupe': not(status),
            'compression': not(status)
        }
        self.mock_object(self.client, 'get_volume_efficiency_status',
                         mock.Mock(return_value=response))
        en_dedupe = self.mock_object(self.client, 'enable_dedupe_async')
        dis_dedupe = self.mock_object(self.client, 'disable_dedupe_async')
        en_comp = self.mock_object(self.client, 'enable_compression_async')
        dis_comp = self.mock_object(self.client, 'disable_compression_async')

        self.client.update_volume_efficiency_attributes(fake.VOLUME_NAMES[0],
                                                        status, status)

        if status:
            en_dedupe.assert_called_once_with(fake.VOLUME_NAMES[0])
            en_comp.assert_called_once_with(fake.VOLUME_NAMES[0])
        else:
            dis_dedupe.assert_called_once_with(fake.VOLUME_NAMES[0])
            dis_comp.assert_called_once_with(fake.VOLUME_NAMES[0])
