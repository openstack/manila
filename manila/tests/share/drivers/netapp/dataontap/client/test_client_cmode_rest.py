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
import math
import time
from unittest import mock

import ddt
from oslo_log import log
from oslo_utils import units

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

    @ddt.data(None, fake.QOS_MAX_THROUGHPUT, fake.QOS_MAX_THROUGHPUT_IOPS)
    def test_qos_policy_group_create(self, max_throughput):
        return_value = fake.GENERIC_JOB_POST_RESPONSE
        body = {
            'name': fake.QOS_POLICY_GROUP_NAME,
            'svm.name': fake.VSERVER_NAME,
        }
        if max_throughput:
            if 'iops' in max_throughput:
                qos = fake.QOS_MAX_THROUGHPUT_IOPS_NO_UNIT
                body['fixed.max_throughput_iops'] = qos
            else:
                qos = math.ceil(fake.QOS_MAX_THROUGHPUT_NO_UNIT / units.Mi)
                body['fixed.max_throughput_mbps'] = qos

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        if max_throughput:
            result = self.client.qos_policy_group_create(
                fake.QOS_POLICY_GROUP_NAME, fake.VSERVER_NAME,
                max_throughput)
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
            'uuid': lif_info['uuid'],
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
                                                .get('name'),
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

        self.client.create_cifs_share(fake.SHARE_NAME, f'/{fake.SHARE_NAME}')

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
        mock_max_files = self.mock_object(self.client, 'set_volume_max_files')
        self.client.create_volume(fake.SHARE_AGGREGATE_NAME,
                                  fake.VOLUME_NAMES[0], fake.SHARE_SIZE,
                                  max_files=1)

        mock_create_volume_async.assert_called_once_with(
            [fake.SHARE_AGGREGATE_NAME], fake.VOLUME_NAMES[0], fake.SHARE_SIZE,
            is_flexgroup=False, thin_provisioned=False, snapshot_policy=None,
            language=None, max_files=1, snapshot_reserve=None,
            volume_type='rw', qos_policy_group=None, encrypt=False,
            adaptive_qos_policy_group=None)
        mock_update.assert_called_once_with(fake.VOLUME_NAMES[0], False, False)
        mock_max_files.assert_called_once_with(fake.VOLUME_NAMES[0], 1)

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
        max_throughput = qos_policy.get('fixed',
                                        {}).get('max_throughput_iops')

        expected = {
            'policy-group': qos_policy.get('name'),
            'vserver': qos_policy.get('svm', {}).get('name'),
            'max-throughput': max_throughput if max_throughput else None,
            'num-workloads': int(qos_policy.get('object_count')),
            }

        query = {
            'name': qos_policy_group_name,
            'fields': 'name,object_count,fixed.max_throughput_iops,' +
                      'fixed.max_throughput_mbps,svm.name'
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
        return_code = netapp_api.EREST_UNMOUNT_FAILED_LOCK
        side_effect = [netapp_api.api.NaApiError(code=return_code,
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
        return_code = netapp_api.EREST_UNMOUNT_FAILED_LOCK
        side_effect = [netapp_api.api.NaApiError(code=return_code,
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
        mock.assert_called_once_with('extreme')
        self.assertTrue(response)

    def test_mark_qos_policy_group_for_deletion_rename_failure(self):
        self.mock_object(self.client, 'qos_policy_group_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.client, 'qos_policy_group_rename',
                         mock.Mock(side_effect=netapp_api.api.NaApiError))
        self.mock_object(client_cmode_rest.LOG, 'warning')
        self.mock_object(self.client, 'remove_unused_qos_policy_groups')

        retval = self.client.mark_qos_policy_group_for_deletion(
            fake.QOS_POLICY_GROUP_NAME)

        self.assertIsNone(retval)
        client_cmode_rest.LOG.warning.assert_called_once()
        self.client.qos_policy_group_exists.assert_called_once_with(
            fake.QOS_POLICY_GROUP_NAME)
        self.client.qos_policy_group_rename.assert_called_once_with(
            fake.QOS_POLICY_GROUP_NAME,
            client_cmode_rest.DELETED_PREFIX + fake.QOS_POLICY_GROUP_NAME)
        self.client.remove_unused_qos_policy_groups.assert_called_once_with()

    @ddt.data(True, False)
    def test_mark_qos_policy_group_for_deletion_policy_exists(self, exists):
        self.mock_object(self.client, 'qos_policy_group_exists',
                         mock.Mock(return_value=exists))
        self.mock_object(self.client, 'qos_policy_group_rename')
        mock_remove_unused_policies = self.mock_object(
            self.client, 'remove_unused_qos_policy_groups')
        self.mock_object(client_cmode_rest.LOG, 'warning')

        retval = self.client.mark_qos_policy_group_for_deletion(
            fake.QOS_POLICY_GROUP_NAME)

        self.assertIsNone(retval)

        if exists:
            self.client.qos_policy_group_rename.assert_called_once_with(
                fake.QOS_POLICY_GROUP_NAME,
                client_cmode_rest.DELETED_PREFIX + fake.QOS_POLICY_GROUP_NAME)
            mock_remove_unused_policies.assert_called_once_with()
        else:
            self.assertFalse(self.client.qos_policy_group_rename.called)
            self.assertFalse(
                self.client.remove_unused_qos_policy_groups.called)
        self.assertFalse(client_cmode_rest.LOG.warning.called)

    def test_set_volume_size(self):
        unique_volume_return = {'uuid': 'fake_uuid'}
        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=unique_volume_return))
        mock_sr = self.mock_object(self.client, 'send_request')
        self.client.set_volume_size('fake_name', 1)

        body = {
            'space.size': 1 * units.Gi
        }
        mock_sr.assert_called_once_with(
            '/storage/volumes/fake_uuid', 'patch', body=body)

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
            'fixed.max_throughput_iops': 1000,
            'fixed.max_throughput_mbps': 0
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
        fake_resp_vol = fake.REST_SIMPLE_RESPONSE["records"][0]
        fake_uuid = fake_resp_vol['uuid']
        mock_get_unique_volume = self.mock_object(
            self.client, "_get_volume_by_args",
            mock.Mock(return_value=fake_resp_vol)
            )
        mock_send_request = self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=fake.VOLUME_LIST_SIMPLE_RESPONSE_REST))

        self.client.split_volume_clone(fake.VOLUME_NAMES[0])
        mock_get_unique_volume.assert_called_once()
        body = {
            'clone.split_initiated': 'true',
        }
        mock_send_request.assert_called_once_with(
            f'/storage/volumes/{fake_uuid}', 'patch', body=body,
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
            vol_name=fake.VOLUME_NAMES[0], fields='uuid,state')
        query = {
            'name': fake.SNAPSHOT_NAME
        }
        mock_send_request.assert_called_once_with(
            f'/storage/volumes/{vol_uuid}/snapshots/', 'get', query=query)
        mock_has_records.assert_called_once_with(fake.SNAPSHOTS_REST_RESPONSE)

    def test_snapshot_exists_error(self):
        volume = {'state': 'offline'}
        self.mock_object(
            self.client, '_get_volume_by_args',
            mock.Mock(return_value=volume))

        self.assertRaises(
            exception.SnapshotUnavailable,
            self.client.snapshot_exists,
            fake.SNAPSHOT_NAME, fake.VOLUME_NAMES[0])

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

    def test_get_snapmirrors_svm(self):
        return_get_snp = fake.REST_GET_SNAPMIRRORS_RESPONSE

        mock_get_snap = self.mock_object(
            self.client, 'get_snapmirrors',
            mock.Mock(return_value=return_get_snp))

        res = self.client.get_snapmirrors_svm(fake.SM_SOURCE_VSERVER,
                                              fake.SM_DEST_VSERVER,
                                              None)

        mock_get_snap.assert_called_once_with(
            source_path=fake.SM_SOURCE_VSERVER + ':*',
            dest_path=fake.SM_DEST_VSERVER + ':*',
            desired_attributes=None)
        self.assertEqual(return_get_snp, res)

    def test_get_snapmirrors(self):

        api_response = fake.SNAPMIRROR_GET_ITER_RESPONSE_REST
        mock_send_request = self.mock_object(
            self.client,
            'send_request',
            mock.Mock(return_value=api_response))

        result = self.client.get_snapmirrors(
            fake.SM_SOURCE_PATH, fake.SM_DEST_PATH,
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME,
            enable_tunneling=True)

        expected = fake.REST_GET_SNAPMIRRORS_RESPONSE

        query = {
            'source.path': (fake.SM_SOURCE_VSERVER + ':' +
                            fake.SM_SOURCE_VOLUME),
            'destination.path': (fake.SM_DEST_VSERVER +
                                 ':' + fake.SM_DEST_VOLUME),
            'fields': 'state,source.svm.name,source.path,destination.svm.name,'
                      'destination.path,transfer.end_time,uuid,policy.type,'
                      'transfer_schedule.name,transfer.state'
        }

        mock_send_request.assert_called_once_with('/snapmirror/relationships',
                                                  'get', query=query,
                                                  enable_tunneling=True)
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
                      'destination.path,transfer.end_time,uuid,policy.type,'
                      'transfer_schedule.name,transfer.state'
        }

        mock_send_request.assert_called_once_with('/snapmirror/relationships',
                                                  'get', query=query,
                                                  enable_tunneling=True)
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
                      'destination.path,transfer.end_time,uuid,policy.type,'
                      'transfer_schedule.name,transfer.state'
        }

        mock_send_request.assert_called_once_with('/snapmirror/relationships',
                                                  'get', query=query,
                                                  enable_tunneling=True)
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

    def test_start_volume_move(self):

        mock__send_volume_move_request = self.mock_object(
            self.client, '_send_volume_move_request')

        self.client.start_volume_move(fake.VOLUME_NAMES[0], fake.VSERVER_NAME,
                                      fake.SHARE_AGGREGATE_NAME,
                                      'fake_cutover', False)

        mock__send_volume_move_request.assert_called_once_with(
            fake.VOLUME_NAMES[0], fake.VSERVER_NAME, fake.SHARE_AGGREGATE_NAME,
            cutover_action='fake_cutover', encrypt_destination=False)

    def test_check_volume_move(self):

        mock__send_volume_move_request = self.mock_object(
            self.client, '_send_volume_move_request')

        self.client.check_volume_move(fake.VOLUME_NAMES[0], fake.VSERVER_NAME,
                                      fake.SHARE_AGGREGATE_NAME, False)

        mock__send_volume_move_request.assert_called_once_with(
            fake.VOLUME_NAMES[0], fake.VSERVER_NAME, fake.SHARE_AGGREGATE_NAME,
            validation_only=True, encrypt_destination=False)

    def test__send_volume_move_request(self):
        mock_sr = self.mock_object(self.client, 'send_request')
        self.client._send_volume_move_request('volume_name', 'vserver',
                                              'destination_aggregate',
                                              cutover_action='wait',
                                              validation_only=True,
                                              encrypt_destination=False)
        query = {'name': 'volume_name'}
        body = {
            'movement.destination_aggregate.name': 'destination_aggregate',
            'encryption.enabled': 'false',
            'validate_only': 'true',
            'movement.state': 'wait',
        }
        mock_sr.assert_called_once_with(
            '/storage/volumes/', 'patch', query=query, body=body,
            wait_on_accepted=False)

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

    def test_trigger_volume_move_cutover(self):
        query = {
            'name': fake.VOLUME_NAMES[0]
        }
        body = {
            'movement.state': 'cutover'
        }
        self.mock_object(self.client, 'send_request')
        self.client.trigger_volume_move_cutover(
            fake.VOLUME_NAMES[0], fake.VSERVER_NAME)
        self.client.send_request.assert_called_once_with(
            '/storage/volumes/', 'patch', query=query,
            body=body)

    def test_abort_volume_move(self):
        return_uuid = {
            'uuid': 'fake_uuid'
        }
        mock_get_vol = self.mock_object(self.client, '_get_volume_by_args',
                                        mock.Mock(return_value=return_uuid))
        mock_sr = self.mock_object(self.client, 'send_request')

        self.client.abort_volume_move('fake_volume_name', 'fake_vserver')

        mock_sr.assert_called_once_with('/storage/volumes/fake_uuid', 'patch')
        mock_get_vol.assert_called_once_with(vol_name='fake_volume_name')

    def test_get_volume_move_status(self):
        """Gets the current state of a volume move operation."""

        return_sr = fake.FAKE_VOL_MOVE_STATUS

        fields = 'movement.percent_complete,movement.state'

        query = {
            'name': 'fake_name',
            'svm.name': 'fake_svm',
            'fields': fields
        }

        mock_sr = self.mock_object(self.client, 'send_request',
                                   mock.Mock(return_value=return_sr))

        result = self.client.get_volume_move_status('fake_name', 'fake_svm')

        mock_sr.assert_called_once_with('/storage/volumes/',
                                        'get', query=query)

        volume_move_info = return_sr.get('records')[0]
        volume_movement = volume_move_info['movement']

        expected = {
            'percent-complete': volume_movement['percent_complete'],
            'estimated-completion-time': '',
            'state': volume_movement['state'],
            'details': '',
            'cutover-action': '',
            'phase': volume_movement['state'],
        }

        self.assertEqual(expected, result)

    def test_list_snapmirror_snapshots(self):
        fake_response = fake.SNAPSHOTS_REST_RESPONSE
        api_response = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        mock_volume = self.mock_object(self.client,
                                       '_get_volume_by_args',
                                       mock.Mock(return_value=api_response))
        mock_request = self.mock_object(self.client, 'send_request',
                                        mock.Mock(return_value=fake_response))
        self.client.list_snapmirror_snapshots(fake.VOLUME_NAMES[0])

        query = {
            'owners': 'snapmirror_dependent',
        }
        mock_request.assert_called_once_with(
            '/storage/volumes/fake_uuid/snapshots/',
            'get', query=query)
        mock_volume.assert_called_once_with(vol_name=fake.VOLUME_NAMES[0])

    @ddt.data({'policy': 'fake_policy'},
              {'policy': None})
    @ddt.unpack
    def test_create_snapmirror_vol(self, policy):
        api_responses = [
            {
                "job": {
                    "uuid": fake.FAKE_UUID,
                },
            },
        ]
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=copy.deepcopy(api_responses)))
        self.client.create_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME,
            relationship_type=netapp_utils.EXTENDED_DATA_PROTECTION_TYPE,
            policy=policy)

        body = {
            'source': {
                'path': (fake.SM_SOURCE_VSERVER + ':' +
                         fake.SM_SOURCE_VOLUME),
            },
            'destination': {
                'path': (fake.SM_DEST_VSERVER + ':' +
                         fake.SM_DEST_VOLUME)
            }
        }

        if policy:
            body['policy.name'] = policy

        self.client.send_request.assert_has_calls([
            mock.call('/snapmirror/relationships/', 'post', body=body)])

    def test_create_snapmirror_vol_already_exists(self):
        api_responses = netapp_api.api.NaApiError(
            code=netapp_api.EREST_ERELATION_EXISTS)
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=api_responses))

        response = self.client.create_snapmirror_vol(
            fake.SM_SOURCE_VSERVER,
            fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER,
            fake.SM_DEST_VOLUME,
            schedule=None,
            policy=None,
            relationship_type='data_protection')
        self.assertIsNone(response)
        self.assertTrue(self.client.send_request.called)

    def test_create_snapmirror_vol_error(self):
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(side_effect=netapp_api.api.NaApiError(code=123)))

        self.assertRaises(netapp_api.api.NaApiError,
                          self.client.create_snapmirror_vol,
                          fake.SM_SOURCE_VSERVER,
                          fake.SM_SOURCE_VOLUME,
                          fake.SM_DEST_VSERVER,
                          fake.SM_DEST_VOLUME,
                          schedule=None,
                          policy=None,
                          relationship_type='data_protection')
        self.assertTrue(self.client.send_request.called)

    def test__set_snapmirror_state(self):

        api_responses = [
            fake.SNAPMIRROR_GET_ITER_RESPONSE_REST,
            {
                "job":
                {
                    "uuid": fake.FAKE_UUID
                },
                "num_records": 1
            }
        ]

        expected_body = {'state': 'snapmirrored'}
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(side_effect=copy.deepcopy(api_responses)))

        result = self.client._set_snapmirror_state(
            'snapmirrored', None, None,
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

        self.client.send_request.assert_has_calls([
            mock.call('/snapmirror/relationships/' + fake.FAKE_UUID,
                      'patch', body=expected_body, wait_on_accepted=True)])

        expected = {
            'operation-id': None,
            'status': None,
            'jobid': fake.FAKE_UUID,
            'error-code': None,
            'error-message': None,
            'relationship-uuid': fake.FAKE_UUID
        }
        self.assertEqual(expected, result)

    def test_initialize_snapmirror_vol(self):

        expected_job = {
            'operation-id': None,
            'status': None,
            'jobid': fake.FAKE_UUID,
            'error-code': None,
            'error-message': None,
        }

        mock_set_snapmirror_state = self.mock_object(
            self.client,
            '_set_snapmirror_state',
            mock.Mock(return_value=expected_job))

        result = self.client.initialize_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

        mock_set_snapmirror_state.assert_called_once_with(
            'snapmirrored', None, None,
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME,
            wait_result=False)

        self.assertEqual(expected_job, result)

    def test_modify_snapmirror_vol(self):

        expected_job = {
            'operation-id': None,
            'status': None,
            'jobid': fake.FAKE_UUID,
            'error-code': None,
            'error-message': None,
        }

        mock_set_snapmirror_state = self.mock_object(
            self.client,
            '_set_snapmirror_state',
            mock.Mock(return_value=expected_job))

        result = self.client.modify_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME,
            None)

        mock_set_snapmirror_state.assert_called_once_with(
            None, None, None,
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME,
            wait_result=False, schedule=None)

        self.assertEqual(expected_job, result)

    def test__abort_snapmirror(self):
        return_snp = fake.REST_GET_SNAPMIRRORS_RESPONSE
        mock_get_snap = self.mock_object(self.client, '_get_snapmirrors',
                                         mock.Mock(return_value=return_snp))
        return_sr = fake.REST_SIMPLE_RESPONSE
        mock_sr = self.mock_object(self.client, 'send_request',
                                   mock.Mock(return_value=return_sr))

        self.client._abort_snapmirror(fake.SM_SOURCE_PATH, fake.SM_DEST_PATH)

        mock_get_snap.assert_called_once_with(
            source_path=fake.SM_SOURCE_PATH,
            dest_path=fake.SM_DEST_PATH,
            source_vserver=None,
            source_volume=None,
            dest_vserver=None,
            dest_volume=None,
            enable_tunneling=None,
            list_destinations_only=None)

        mock_sr.assert_has_calls([
            mock.call(f'/snapmirror/relationships/{return_snp[0]["uuid"]}'
                      '/transfers/', 'get',
                      query={'state': 'transferring'}),
            mock.call(f'/snapmirror/relationships/{return_snp[0]["uuid"]}'
                      f'/transfers/{return_sr["records"][0]["uuid"]}',
                      'patch', body={'state': 'aborted'}),
        ])

    def test_abort_snapmirror_vol(self):
        mock_abort = self.mock_object(self.client, '_abort_snapmirror')
        self.client.abort_snapmirror_vol(fake.VSERVER_NAME,
                                         fake.VOLUME_NAMES[0],
                                         fake.VSERVER_NAME_2,
                                         fake.VOLUME_NAMES[1])
        mock_abort.assert_called_once_with(source_vserver=fake.VSERVER_NAME,
                                           source_volume=fake.VOLUME_NAMES[0],
                                           dest_vserver=fake.VSERVER_NAME_2,
                                           dest_volume=fake.VOLUME_NAMES[1],
                                           clear_checkpoint=False)

    def test_release_snapmirror_vol(self):
        mock_sr = self.mock_object(self.client, 'send_request')
        return_snp = fake.REST_GET_SNAPMIRRORS_RESPONSE
        mock_sd = self.mock_object(self.client, 'get_snapmirror_destinations',
                                   mock.Mock(return_value=return_snp))

        self.client.release_snapmirror_vol(fake.VSERVER_NAME,
                                           fake.VOLUME_NAMES[0],
                                           fake.VSERVER_NAME_2,
                                           fake.VOLUME_NAMES[1])

        mock_sd.assert_called_once_with(source_vserver=fake.VSERVER_NAME,
                                        source_volume=fake.VOLUME_NAMES[0],
                                        dest_vserver=fake.VSERVER_NAME_2,
                                        dest_volume=fake.VOLUME_NAMES[1],
                                        desired_attributes=['relationship-id'])

        uuid = return_snp[0].get("uuid")
        query = {"source_only": 'true'}
        mock_sr.assert_called_once_with(f'/snapmirror/relationships/{uuid}',
                                        'delete', query=query)

    def test_delete_snapmirror_no_records(self):
        query_uuid = {}
        query_uuid['source.path'] = (fake.SM_SOURCE_VSERVER + ':' +
                                     fake.SM_SOURCE_VOLUME)

        query_uuid['destination.path'] = (fake.SM_DEST_VSERVER + ':' +
                                          fake.SM_DEST_VOLUME)
        query_uuid['fields'] = 'uuid'

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=fake.NO_RECORDS_RESPONSE_REST))
        self.client._delete_snapmirror(fake.SM_SOURCE_VSERVER,
                                       fake.SM_SOURCE_VOLUME,
                                       fake.SM_DEST_VSERVER,
                                       fake.SM_DEST_VOLUME)
        self.client.send_request.assert_called_once_with(
            '/snapmirror/relationships/', 'get', query=query_uuid)

    def test_delete_snapmirror(self):
        query_uuid = {}
        query_uuid['source.path'] = (fake.SM_SOURCE_VSERVER + ':' +
                                     fake.SM_SOURCE_VOLUME)

        query_uuid['destination.path'] = (fake.SM_DEST_VSERVER + ':' +
                                          fake.SM_DEST_VOLUME)
        query_uuid['fields'] = 'uuid'
        fake_cluster = fake.FAKE_GET_CLUSTER_NODE_VERSION_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=fake_cluster))
        self.client._delete_snapmirror(fake.SM_SOURCE_VSERVER,
                                       fake.SM_SOURCE_VOLUME,
                                       fake.SM_DEST_VSERVER,
                                       fake.SM_DEST_VOLUME)

        query_delete = {"destination_only": "true"}
        snapmirror_uuid = fake_cluster.get('records')[0].get('uuid')
        self.client.send_request.assert_has_calls([
            mock.call('/snapmirror/relationships/', 'get', query=query_uuid),
            mock.call('/snapmirror/relationships/' + snapmirror_uuid, 'delete',
                      query=query_delete)
        ])

    def test_get_snapmirror_destinations(self):
        mock_get_sm = self.mock_object(self.client, '_get_snapmirrors')
        self.client.get_snapmirror_destinations(fake.SM_SOURCE_PATH,
                                                fake.SM_DEST_PATH,
                                                fake.SM_SOURCE_VSERVER,
                                                fake.SM_SOURCE_VOLUME,
                                                fake.SM_DEST_VSERVER,
                                                fake.SM_DEST_VOLUME)

        mock_get_sm.assert_called_once_with(
            source_path=fake.SM_SOURCE_PATH,
            dest_path=fake.SM_DEST_PATH,
            source_vserver=fake.SM_SOURCE_VSERVER,
            source_volume=fake.SM_SOURCE_VOLUME,
            dest_vserver=fake.SM_DEST_VSERVER,
            dest_volume=fake.SM_DEST_VOLUME,
            enable_tunneling=False,
            list_destinations_only=True)

    def test_delete_snapmirror_vol(self):
        mock_delete = self.mock_object(self.client, '_delete_snapmirror')
        self.client.delete_snapmirror_vol(fake.SM_SOURCE_VSERVER,
                                          fake.SM_SOURCE_VOLUME,
                                          fake.SM_DEST_VSERVER,
                                          fake.SM_DEST_VOLUME)
        mock_delete.assert_called_once_with(
            source_vserver=fake.SM_SOURCE_VSERVER,
            dest_vserver=fake.SM_DEST_VSERVER,
            source_volume=fake.SM_SOURCE_VOLUME,
            dest_volume=fake.SM_DEST_VOLUME)

    def test_disable_fpolicy_policy(self):
        query = {
            'name': fake.VSERVER_NAME,
            'fields': 'uuid'
        }
        response_svm = fake.SVMS_LIST_SIMPLE_RESPONSE_REST
        self.client.vserver = fake.VSERVER_NAME
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(side_effect=[response_svm, None]))

        self.client.disable_fpolicy_policy(fake.FPOLICY_POLICY_NAME)

        svm_id = response_svm.get('records')[0]['uuid']

        self.client.send_request.assert_has_calls([
            mock.call('/svm/svms', 'get', query=query,
                      enable_tunneling=False),
            mock.call(f'/protocols/fpolicy/{svm_id}/policies'
                      f'/{fake.FPOLICY_POLICY_NAME}', 'patch')
            ])

    @ddt.data([fake.NO_RECORDS_RESPONSE_REST, None],
              [fake.SVMS_LIST_SIMPLE_RESPONSE_REST,
               netapp_api.api.NaApiError(code="1000", message="")])
    def test_disable_fpolicy_policy_failure(self, side_effect):
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(side_effect=side_effect))

        self.assertRaises(exception.NetAppException,
                          self.client.disable_fpolicy_policy,
                          fake.FPOLICY_POLICY_NAME)

    @ddt.data({'qos_policy_group_name': None,
               'adaptive_qos_policy_group_name': None},
              {'qos_policy_group_name': fake.QOS_POLICY_GROUP_NAME,
               'adaptive_qos_policy_group_name': None},
              {'qos_policy_group_name': None,
               'adaptive_qos_policy_group_name':
                   fake.ADAPTIVE_QOS_POLICY_GROUP_NAME},
              )
    @ddt.unpack
    def test_create_volume_clone(self, qos_policy_group_name,
                                 adaptive_qos_policy_group_name):
        self.mock_object(self.client, 'send_request')

        if qos_policy_group_name:
            volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
            uuid = volume["uuid"]
            self.mock_object(self.client,
                             '_get_volume_by_args',
                             mock.Mock(return_value=volume))
        self.mock_object(self.client, 'split_volume_clone')
        self.mock_object(
            self.client.connection, 'get_vserver',
            mock.Mock(return_value='fake_svm'))
        set_qos_adapt_mock = self.mock_object(
            self.client,
            'set_qos_adaptive_policy_group_for_volume')

        self.client.create_volume_clone(
            fake.SHARE_NAME,
            fake.PARENT_SHARE_NAME,
            fake.PARENT_SNAPSHOT_NAME,
            qos_policy_group=qos_policy_group_name,
            adaptive_qos_policy_group=adaptive_qos_policy_group_name)

        body = {
            'name': fake.SHARE_NAME,
            'clone.parent_volume.name': fake.PARENT_SHARE_NAME,
            'clone.parent_snapshot.name': fake.PARENT_SNAPSHOT_NAME,
            'nas.path': '/%s' % fake.SHARE_NAME,
            'clone.is_flexclone': 'true',
            'svm.name': 'fake_svm',
        }

        if adaptive_qos_policy_group_name is not None:
            set_qos_adapt_mock.assert_called_once_with(
                fake.SHARE_NAME, fake.ADAPTIVE_QOS_POLICY_GROUP_NAME
            )

        if qos_policy_group_name:
            self.client._get_volume_by_args.assert_called_once_with(
                vol_name=fake.SHARE_NAME)
            self.client.send_request.assert_has_calls([
                mock.call('/storage/volumes', 'post', body=body),
                mock.call(f'/storage/volumes/{uuid}', 'patch',
                          body={'qos.policy.name': qos_policy_group_name})
            ])
        else:
            self.client.send_request.assert_called_once_with(
                '/storage/volumes', 'post', body=body)

        self.assertFalse(self.client.split_volume_clone.called)

    @ddt.data(True, False)
    def test_create_volume_split(self, split):
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'split_volume_clone')
        self.mock_object(
            self.client.connection, 'get_vserver',
            mock.Mock(return_value='fake_svm'))
        body = {
            'name': fake.SHARE_NAME,
            'clone.parent_volume.name': fake.PARENT_SHARE_NAME,
            'clone.parent_snapshot.name': fake.PARENT_SNAPSHOT_NAME,
            'nas.path': '/%s' % fake.SHARE_NAME,
            'clone.is_flexclone': 'true',
            'svm.name': 'fake_svm',
        }

        self.client.create_volume_clone(
            fake.SHARE_NAME,
            fake.PARENT_SHARE_NAME,
            fake.PARENT_SNAPSHOT_NAME,
            split=split)

        if split:
            self.client.split_volume_clone.assert_called_once_with(
                fake.SHARE_NAME)
        else:
            self.assertFalse(self.client.split_volume_clone.called)

        self.client.send_request.assert_called_once_with(
            '/storage/volumes', 'post', body=body)

    def test_quiesce_snapmirror_vol(self):
        mock__quiesce_snapmirror = self.mock_object(
            self.client, '_quiesce_snapmirror')

        self.client.quiesce_snapmirror_vol(fake.SM_SOURCE_VSERVER,
                                           fake.SM_SOURCE_VOLUME,
                                           fake.SM_DEST_VSERVER,
                                           fake.SM_DEST_VOLUME)

        mock__quiesce_snapmirror.assert_called_once_with(
            source_vserver=fake.SM_SOURCE_VSERVER,
            source_volume=fake.SM_SOURCE_VOLUME,
            dest_vserver=fake.SM_DEST_VSERVER,
            dest_volume=fake.SM_DEST_VOLUME)

    def test__quiesce_snapmirror(self):
        fake_snapmirror = fake.REST_GET_SNAPMIRRORS_RESPONSE
        fake_uuid = fake_snapmirror[0]['uuid']
        fake_body = {'state': 'paused'}

        self.mock_object(self.client, 'send_request')

        mock_get_snap = self.mock_object(
            self.client, '_get_snapmirrors',
            mock.Mock(return_value=fake_snapmirror))

        self.client._quiesce_snapmirror()

        mock_get_snap.assert_called_once()
        self.client.send_request.assert_called_once_with(
            f'/snapmirror/relationships/{fake_uuid}', 'patch', body=fake_body)

    def test_break_snapmirror_vol(self):

        self.mock_object(self.client, '_break_snapmirror')

        self.client.break_snapmirror_vol(source_vserver=fake.SM_SOURCE_VSERVER,
                                         source_volume=fake.SM_SOURCE_VOLUME,
                                         dest_vserver=fake.SM_DEST_VSERVER,
                                         dest_volume=fake.SM_DEST_VOLUME)

        self.client._break_snapmirror.assert_called_once_with(
            source_vserver=fake.SM_SOURCE_VSERVER,
            source_volume=fake.SM_SOURCE_VOLUME,
            dest_vserver=fake.SM_DEST_VSERVER,
            dest_volume=fake.SM_DEST_VOLUME)

    def test__break_snapmirror(self):
        fake_snapmirror = fake.REST_GET_SNAPMIRRORS_RESPONSE
        fake_uuid = fake_snapmirror[0]['uuid']
        fake_body = {'state': 'broken_off'}

        self.mock_object(self.client, 'send_request')

        mock_get_snap = self.mock_object(
            self.client, '_get_snapmirrors',
            mock.Mock(return_value=fake_snapmirror))

        self.client._break_snapmirror()

        mock_get_snap.assert_called_once()
        self.client.send_request.assert_called_once_with(
            f'/snapmirror/relationships/{fake_uuid}', 'patch', body=fake_body)

    def test_resume_snapmirror_vol(self):
        mock = self.mock_object(self.client, '_resume_snapmirror')
        self.client.resume_snapmirror_vol(fake.SM_SOURCE_VSERVER,
                                          fake.SM_SOURCE_VOLUME,
                                          fake.SM_DEST_VSERVER,
                                          fake.SM_DEST_VOLUME)
        mock.assert_called_once_with(
            source_vserver=fake.SM_SOURCE_VSERVER,
            dest_vserver=fake.SM_DEST_VSERVER,
            source_volume=fake.SM_SOURCE_VOLUME,
            dest_volume=fake.SM_DEST_VOLUME)

    def test_resync_snapmirror_vol(self):
        mock = self.mock_object(self.client, '_resync_snapmirror')
        self.client.resync_snapmirror_vol(fake.SM_SOURCE_VSERVER,
                                          fake.SM_SOURCE_VOLUME,
                                          fake.SM_DEST_VSERVER,
                                          fake.SM_DEST_VOLUME)
        mock.assert_called_once_with(
            source_vserver=fake.SM_SOURCE_VSERVER,
            dest_vserver=fake.SM_DEST_VSERVER,
            source_volume=fake.SM_SOURCE_VOLUME,
            dest_volume=fake.SM_DEST_VOLUME)

    @ddt.data('async', 'sync')
    def test__resume_snapmirror(self, snapmirror_policy):
        api_response = copy.deepcopy(fake.REST_GET_SNAPMIRRORS_RESPONSE)
        api_response[0]['policy-type'] = snapmirror_policy
        mock_snapmirror = self.mock_object(
            self.client, '_get_snapmirrors',
            mock.Mock(return_value=api_response))
        mock_request = self.mock_object(self.client, 'send_request')

        snapmirror_uuid = fake.FAKE_UUID

        body_resync = {}
        if snapmirror_policy == 'async':
            body_resync['state'] = 'snapmirrored'
        elif snapmirror_policy == 'sync':
            body_resync['state'] = 'in_sync'

        self.client._resume_snapmirror(fake.SM_SOURCE_PATH, fake.SM_DEST_PATH)

        mock_request.assert_called_once_with('/snapmirror/relationships/' +
                                             snapmirror_uuid, 'patch',
                                             body=body_resync,
                                             wait_on_accepted=False)

        mock_snapmirror.assert_called_once_with(
            source_path=fake.SM_SOURCE_PATH,
            dest_path=fake.SM_DEST_PATH,
            source_vserver=None,
            source_volume=None,
            dest_vserver=None,
            dest_volume=None,
            enable_tunneling=None,
            list_destinations_only=None)

    def test__resync_snapmirror(self):
        mock = self.mock_object(self.client, '_resume_snapmirror')
        self.client._resume_snapmirror(fake.SM_SOURCE_PATH,
                                       fake.SM_DEST_PATH)
        mock.assert_called_once_with(fake.SM_SOURCE_PATH, fake.SM_DEST_PATH)

    def test_add_nfs_export_rule(self):

        mock_get_nfs_export_rule_indices = self.mock_object(
            self.client, '_get_nfs_export_rule_indices',
            mock.Mock(return_value=[]))
        mock_add_nfs_export_rule = self.mock_object(
            self.client, '_add_nfs_export_rule')
        mock_update_nfs_export_rule = self.mock_object(
            self.client, '_update_nfs_export_rule')
        auth_methods = ['sys']

        self.client.add_nfs_export_rule(fake.EXPORT_POLICY_NAME,
                                        fake.IP_ADDRESS,
                                        False,
                                        auth_methods)

        mock_get_nfs_export_rule_indices.assert_called_once_with(
            fake.EXPORT_POLICY_NAME, fake.IP_ADDRESS)
        mock_add_nfs_export_rule.assert_called_once_with(
            fake.EXPORT_POLICY_NAME, fake.IP_ADDRESS, False, auth_methods)
        self.assertFalse(mock_update_nfs_export_rule.called)

    def test_set_qos_policy_group_for_volume(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        mock_get_volume = self.mock_object(
            self.client, '_get_volume_by_args',
            mock.Mock(return_value=volume))

        mock_send_request = self.mock_object(
            self.client, 'send_request')

        self.client.set_qos_policy_group_for_volume(
            volume['name'], fake.QOS_POLICY_GROUP_NAME)

        mock_get_volume.assert_called_once_with(vol_name=volume['name'])

        body = {'qos.policy.name': fake.QOS_POLICY_GROUP_NAME}
        mock_send_request.assert_called_once_with(
            f'/storage/volumes/{volume["uuid"]}', 'patch', body=body)

    def test__update_snapmirror(self):
        api_response = copy.deepcopy(fake.REST_GET_SNAPMIRRORS_RESPONSE)
        mock_snapmirror = self.mock_object(
            self.client, '_get_snapmirrors',
            mock.Mock(return_value=api_response))
        mock_sr = self.mock_object(self.client, 'send_request')
        self.client._update_snapmirror(fake.SM_SOURCE_PATH,
                                       fake.SM_DEST_PATH,
                                       fake.SM_SOURCE_VSERVER,
                                       fake.SM_DEST_VSERVER,
                                       fake.SM_SOURCE_VOLUME,
                                       fake.SM_DEST_VOLUME)
        mock_sr.assert_called_once()
        mock_snapmirror.assert_called_once_with(
            source_path=fake.SM_SOURCE_PATH,
            dest_path=fake.SM_DEST_PATH,
            source_vserver=fake.SM_SOURCE_VSERVER,
            source_volume=fake.SM_SOURCE_VOLUME,
            dest_vserver=fake.SM_DEST_VSERVER,
            dest_volume=fake.SM_DEST_VOLUME,
            enable_tunneling=None,
            list_destinations_only=None)

    def test_get_cluster_name(self):
        """Get all available cluster nodes."""

        return_value = fake.FAKE_GET_CLUSTER_NODE_VERSION_REST

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))
        test_result = self.client.get_cluster_name()

        self.client.send_request.assert_called_once_with(
            '/cluster', 'get', enable_tunneling=False
        )

        expected_result = return_value.get('name')

        self.assertEqual(test_result, expected_result)

    @ddt.data(True, False)
    def test_check_volume_clone_split_completed(self, clone):
        mock__get_volume_by_args = self.mock_object(
            self.client, '_get_volume_by_args',
            mock.Mock(return_value={'clone': {'is_flexclone': clone}}))

        res = self.client.check_volume_clone_split_completed(
            fake.VOLUME_NAMES[0])

        mock__get_volume_by_args.assert_called_once_with(
            vol_name=fake.VOLUME_NAMES[0], fields='clone.is_flexclone')
        self.assertEqual(not clone, res)

    def test_rehost_volume(self):
        self.mock_object(self.client, 'send_request')
        self.client.rehost_volume("fake_vol", "fake_svm", "fake_svm_2")
        body = {
            "vserver": "fake_svm",
            "volume": "fake_vol",
            "destination_vserver": "fake_svm_2"
            }
        self.client.send_request.assert_called_once_with(
            "/private/cli/volume/rehost", 'post', body=body)

    def test_get_net_options(self):

        res = self.client.get_net_options()

        self.assertTrue(res['ipv6-enabled'])

    def test_set_qos_adaptive_policy_group_for_volume(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        mock_get_volume = self.mock_object(
            self.client, '_get_volume_by_args',
            mock.Mock(return_value=volume))

        mock_send_request = self.mock_object(
            self.client, 'send_request')

        self.client.set_qos_adaptive_policy_group_for_volume(
            volume['name'], fake.QOS_POLICY_GROUP_NAME)

        mock_get_volume.assert_called_once_with(vol_name=volume['name'])

        body = {'qos.policy.name': fake.QOS_POLICY_GROUP_NAME}
        mock_send_request.assert_called_once_with(
            f'/storage/volumes/{volume["uuid"]}', 'patch', body=body)

    def test__list_vservers(self):
        api_response = fake.VSERVER_DATA_LIST_RESPONSE_REST
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))
        result = self.client._list_vservers()
        query = {
            'fields': 'name',
        }
        self.client.send_request.assert_has_calls([
            mock.call('/svm/svms', 'get', query=query,
                      enable_tunneling=False)])
        self.assertListEqual(
            [fake.VSERVER_NAME, fake.VSERVER_NAME_2], result)

    def test_list_vservers_not_found(self):
        api_response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))
        result = self.client._list_vservers()
        self.assertListEqual([], result)

    def test_get_ems_log_destination_vserver(self):
        mock_list_vservers = self.mock_object(
            self.client,
            '_list_vservers',
            mock.Mock(return_value=[fake.VSERVER_NAME]))
        result = self.client._get_ems_log_destination_vserver()
        mock_list_vservers.assert_called_once_with()
        self.assertEqual(fake.VSERVER_NAME, result)

    def test_get_ems_log_destination_vserver_not_found(self):
        mock_list_vservers = self.mock_object(
            self.client,
            '_list_vservers',
            mock.Mock(return_value=[]))

        self.assertRaises(exception.NotFound,
                          self.client._get_ems_log_destination_vserver)

        mock_list_vservers.assert_called_once_with()

    def test_send_ems_log_message(self):

        message_dict = {
            'computer-name': '25-dev-vm',
            'event-source': 'Cinder driver NetApp_iSCSI_Cluster_direct',
            'app-version': '20.1.0.dev|vendor|Linux-5.4.0-120-generic-x86_64',
            'category': 'provisioning',
            'log-level': '5',
            'auto-support': 'false',
            'event-id': '1',
            'event-description':
                '{"pools": {"vserver": "vserver_name",'
                + '"aggregates": [], "flexvols": ["flexvol_01"]}}'
        }

        body = {
            'computer_name': message_dict['computer-name'],
            'event_source': message_dict['event-source'],
            'app_version': message_dict['app-version'],
            'category': message_dict['category'],
            'severity': 'notice',
            'autosupport_required': message_dict['auto-support'] == 'true',
            'event_id': message_dict['event-id'],
            'event_description': message_dict['event-description'],
        }

        self.mock_object(self.client, '_get_ems_log_destination_vserver',
                         mock.Mock(return_value='vserver_name'))
        self.mock_object(self.client, 'send_request')

        self.client.send_ems_log_message(message_dict)

        self.client.send_request.assert_called_once_with(
            '/support/ems/application-logs', 'post', body=body)

    @ddt.data('cp_phase_times', 'domain_busy')
    def test_get_performance_counter_info(self, counter_name):

        response1 = fake.PERF_COUNTER_LIST_INFO_WAFL_RESPONSE_REST
        response2 = fake.PERF_COUNTER_TABLE_ROWS_WAFL

        object_name = 'wafl'

        mock_send_request = self.mock_object(
            self.client, 'send_request',
            mock.Mock(side_effect=[response1, response2]))

        result = self.client.get_performance_counter_info(object_name,
                                                          counter_name)

        expected = {
            'name': 'cp_phase_times',
            'base-counter': 'total_cp_msecs',
            'labels': fake.PERF_COUNTER_TOTAL_CP_MSECS_LABELS_RESULT,
        }

        query1 = {
            'counter_schemas.name': counter_name,
            'fields': 'counter_schemas.*'
        }

        query2 = {
            'counters.name': counter_name,
            'fields': 'counters.*'
        }

        if counter_name == 'domain_busy':
            expected['name'] = 'domain_busy'
            expected['labels'] = (
                fake.PERF_COUNTER_TOTAL_CP_MSECS_LABELS_REST)
            query1['counter_schemas.name'] = 'domain_busy_percent'
            query2['counters.name'] = 'domain_busy_percent'

        self.assertEqual(expected, result)

        mock_send_request.assert_has_calls([
            mock.call(f'/cluster/counter/tables/{object_name}',
                      'get', query=query1),
            mock.call(f'/cluster/counter/tables/{object_name}/rows',
                      'get', query=query2, enable_tunneling=False),
        ])

    def test_get_performance_counter_info_not_found_rows(self):
        response1 = fake.PERF_COUNTER_LIST_INFO_WAFL_RESPONSE_REST
        response2 = fake.NO_RECORDS_RESPONSE_REST

        object_name = 'wafl'
        counter_name = 'cp_phase_times'

        self.mock_object(
            self.client, 'send_request',
            mock.Mock(side_effect=[response1, response2]))

        result = self.client.get_performance_counter_info(object_name,
                                                          counter_name)

        expected = {
            'name': 'cp_phase_times',
            'base-counter': 'total_cp_msecs',
            'labels': [],
        }
        self.assertEqual(expected, result)

    def test_get_performance_instance_uuids(self):
        response = fake.PERF_COUNTER_TABLE_ROWS_WAFL

        mock_send_request = self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=response))

        object_name = 'wafl'
        result = self.client.get_performance_instance_uuids(
            object_name, fake.NODE_NAME)

        expected = [fake.NODE_NAME + ':wafl']
        self.assertEqual(expected, result)

        query = {
            'id': fake.NODE_NAME + ':*',
        }
        mock_send_request.assert_called_once_with(
            f'/cluster/counter/tables/{object_name}/rows',
            'get', query=query, enable_tunneling=False)

    def test_get_performance_counters(self):
        response = fake.PERF_GET_INSTANCES_PROCESSOR_RESPONSE_REST

        mock_send_request = self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=response))

        instance_uuids = [
            fake.NODE_NAME + ':processor0',
            fake.NODE_NAME + ':processor1',
        ]
        object_name = 'processor'
        counter_names = ['domain_busy', 'processor_elapsed_time']
        rest_counter_names = ['domain_busy_percent', 'elapsed_time']
        result = self.client.get_performance_counters(object_name,
                                                      instance_uuids,
                                                      counter_names)

        expected = fake.PERF_COUNTERS_PROCESSOR_EXPECTED
        self.assertEqual(expected, result)

        query = {
            'id': '|'.join(instance_uuids),
            'counters.name': '|'.join(rest_counter_names),
            'fields': 'id,counter_table.name,counters.*',
        }

        mock_send_request.assert_called_once_with(
            f'/cluster/counter/tables/{object_name}/rows',
            'get', query=query)

    def test__get_deleted_nfs_export_policies(self):

        api_response = fake.DELETED_EXPORT_POLICY_GET_ITER_RESPONSE_REST
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client._get_deleted_nfs_export_policies()

        query = {
            'name': 'deleted_manila_*',
            'fields': 'name,svm.name',
        }

        self.assertSequenceEqual(fake.DELETED_EXPORT_POLICIES, result)
        self.client.send_request.assert_has_calls([
            mock.call('/protocols/nfs/export-policies',
                      'get', query=query)])

    def test_prune_deleted_nfs_export_policies(self):
        self.mock_object(self.client, '_get_deleted_nfs_export_policies',
                         mock.Mock(return_value=fake.DELETED_EXPORT_POLICIES))
        self.mock_object(self.client, 'delete_nfs_export_policy')

        self.client.prune_deleted_nfs_export_policies()

        self.assertTrue(self.client.delete_nfs_export_policy.called)

        self.client.delete_nfs_export_policy.assert_has_calls([
            mock.call(fake.DELETED_EXPORT_POLICIES[fake.VSERVER_NAME][0]),
            mock.call(fake.DELETED_EXPORT_POLICIES[fake.VSERVER_NAME][1]),
            mock.call(fake.DELETED_EXPORT_POLICIES[fake.VSERVER_NAME_2][0]),
        ])

    def test_prune_deleted_nfs_export_policies_api_error(self):
        self.mock_object(self.client,
                         '_get_deleted_nfs_export_policies',
                         mock.Mock(return_value=fake.DELETED_EXPORT_POLICIES))
        self.mock_object(self.client,
                         'delete_nfs_export_policy',
                         self._mock_api_error())

        self.client.prune_deleted_nfs_export_policies()

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

    def test_get_nfs_config_default(self):
        api_response = fake.NFS_CONFIG_DEFAULT_RESULT_REST
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_nfs_config_default(['tcp-max-xfer-size',
                                                     'udp-max-xfer-size'])
        expected = {
            'tcp-max-xfer-size': '65536',
            'udp-max-xfer-size': '32768',
        }
        self.assertEqual(expected, result)

        query = {'fields': 'transport.*'}
        self.client.send_request.assert_called_once_with(
            '/protocols/nfs/services/', 'get', query=query)

    def test_get_kerberos_service_principal_name(self):

        spn = self.client._get_kerberos_service_principal_name(
            fake.KERBEROS_SECURITY_SERVICE, fake.VSERVER_NAME
        )
        self.assertEqual(fake.KERBEROS_SERVICE_PRINCIPAL_NAME, spn)

    def test_get_cifs_server_name(self):

        expected_return = 'FAKE-VSE-SERVER'

        cifs_server = self.client._get_cifs_server_name(fake.VSERVER_NAME)

        self.assertEqual(expected_return, cifs_server)

    def test_list_network_interfaces(self):

        api_response = fake.GENERIC_NETWORK_INTERFACES_GET_REPONSE
        expected_result = [fake.LIF_NAME]

        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))

        fake_query = {
            'fields': 'name'
        }

        result = self.client.list_network_interfaces()

        self.client.send_request.assert_has_calls([
            mock.call('/network/ip/interfaces', 'get', query=fake_query)])
        self.assertEqual(expected_result, result)

    def test_create_kerberos_realm(self):

        fake_security = fake.KERBEROS_SECURITY_SERVICE

        fake_body = {
            'comment': '',
            'kdc.ip': fake_security['server'],
            'kdc.port': '88',
            'kdc.vendor': 'other',
            'name': fake_security['domain'].upper(),
        }

        self.mock_object(self.client, 'send_request')

        self.client.create_kerberos_realm(fake.KERBEROS_SECURITY_SERVICE)

        self.client.send_request.assert_called_once_with(
            '/protocols/nfs/kerberos/realms', 'post', body=fake_body)

    def test_configure_kerberos(self):

        fake_api_response = fake.NFS_LIFS_REST
        fake_security = fake.KERBEROS_SECURITY_SERVICE
        fake_keberos_name = fake.KERBEROS_SERVICE_PRINCIPAL_NAME

        fake_body = {
            'password': fake_security['password'],
            'user': fake_security['user'],
            'interface.name': fake.LIF_NAME,
            'enabled': True,
            'spn': fake_keberos_name
        }

        self.mock_object(self.client, 'configure_dns')
        self_get_kerberos = self.mock_object(
            self.client, '_get_kerberos_service_principal_name',
            mock.Mock(return_value=fake_keberos_name))
        self.mock_object(self.client, 'get_network_interfaces',
                         mock.Mock(return_value=fake_api_response))
        self.mock_object(self.client, 'send_request')

        self.client.configure_kerberos(fake.KERBEROS_SECURITY_SERVICE,
                                       fake.VSERVER_NAME)

        self.client.configure_dns.assert_called_once_with(
            fake.KERBEROS_SECURITY_SERVICE, vserver_name=fake.VSERVER_NAME)
        self_get_kerberos.assert_called_once_with(
            fake.KERBEROS_SECURITY_SERVICE, fake.VSERVER_NAME)
        self.client.get_network_interfaces.assert_called_once_with()
        self.client.send_request.assert_has_calls([
            mock.call('/protocols/nfs/kerberos/interfaces/fake_uuid_1',
                      'patch', body=fake_body),
            mock.call('/protocols/nfs/kerberos/interfaces/fake_uuid_2',
                      'patch', body=fake_body),
            mock.call('/protocols/nfs/kerberos/interfaces/fake_uuid_3',
                      'patch', body=fake_body)
        ])

    @ddt.data(fake.CIFS_SECURITY_SERVICE, fake.CIFS_SECURITY_SERVICE_3)
    def test_configure_active_directory(self, security_service):

        fake_security = copy.deepcopy(security_service)

        fake_body1 = {
            'ad_domain.user': fake_security['user'],
            'ad_domain.password': fake_security['password'],
            'force': 'true',
            'name': 'FAKE-VSE-SERVER',
            'ad_domain.fqdn': fake_security['domain'],
        }

        self.mock_object(self.client, 'configure_dns')
        self.mock_object(self.client, 'set_preferred_dc')
        self.mock_object(self.client, '_get_cifs_server_name',
                         mock.Mock(return_value='FAKE-VSE-SERVER'))
        self.mock_object(self.client, 'send_request')

        self.client.configure_active_directory(fake_security,
                                               fake.VSERVER_NAME)

        self.client.configure_dns.assert_called_once_with(
            fake_security, vserver_name=fake.VSERVER_NAME)
        self.client.set_preferred_dc.assert_called_once_with(
            fake_security, fake.VSERVER_NAME)
        self.client._get_cifs_server_name.assert_called_once_with(
            fake.VSERVER_NAME)

        if fake_security['ou'] is not None:
            fake_body1['ad_domain.organizational_unit'] = fake_security['ou']
            fake_body2 = fake_body1

            self.client.send_request.assert_called_once_with(
                '/protocols/cifs/services', 'post', body=fake_body2)
        else:
            self.client.send_request.assert_called_once_with(
                '/protocols/cifs/services', 'post', body=fake_body1)

    def test__create_ldap_client_ad(self):
        mock_dns = self.mock_object(self.client, 'configure_dns')
        mock_sr = self.mock_object(self.client, 'send_request')
        security_service = {
            'domain': 'fake_domain',
            'user': 'fake_user',
            'ou': 'fake_ou',
            'dns_ip': 'fake_ip',
            'password': 'fake_password'
        }

        ad_domain = security_service.get('domain')
        body = {
            'port': '389',
            'schema': 'MS-AD-BIS',
            'bind_dn': (security_service.get('user') + '@' + ad_domain),
            'bind_password': security_service.get('password'),
            'svm.name': fake.VSERVER_NAME,
            'base_dn': security_service.get('ou'),
            'ad_domain': security_service.get('domain'),
        }

        self.client._create_ldap_client(security_service,
                                        vserver_name=fake.VSERVER_NAME)
        mock_dns.assert_called_once_with(security_service)
        mock_sr.assert_called_once_with('/name-services/ldap', 'post',
                                        body=body)

    def test__create_ldap_client_linux(self):
        mock_dns = self.mock_object(self.client, 'configure_dns')
        mock_sr = self.mock_object(self.client, 'send_request')
        security_service = {
            'server': 'fake_server',
            'user': 'fake_user',
            'ou': 'fake_ou',
            'dns_ip': 'fake_ip'
        }

        body = {
            'port': '389',
            'schema': 'RFC-2307',
            'bind_dn': security_service.get('user'),
            'bind_password': security_service.get('password'),
            'svm.name': fake.VSERVER_NAME,
            'base_dn': security_service.get('ou'),
            'servers': [security_service.get('server')]
        }

        self.client._create_ldap_client(security_service,
                                        vserver_name=fake.VSERVER_NAME)
        mock_dns.assert_called_once_with(security_service)
        mock_sr.assert_called_once_with('/name-services/ldap', 'post',
                                        body=body)

    def test_configure_dns_already_present(self):
        dns_config = {
            'domains': [fake.KERBEROS_SECURITY_SERVICE['domain']],
            'dns-ips': [fake.KERBEROS_SECURITY_SERVICE['dns_ip']],
        }
        self.mock_object(self.client, 'get_dns_config',
                         mock.Mock(return_value=dns_config))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=fake.FAKE_VOL_MOVE_STATUS))

        security_service = copy.deepcopy(fake.KERBEROS_SECURITY_SERVICE)
        self.client.configure_dns(security_service)

        net_dns_create_args = {
            'domains': [security_service['domain']],
            'servers': [security_service['dns_ip']],
        }

        uuid = fake.FAKE_VOL_MOVE_STATUS['records'][0]['uuid']
        self.client.send_request.assert_has_calls([
            mock.call('/svm/svms', 'get',
                      query={'name': None, 'fields': 'uuid'}),
            mock.call(f'/name-services/dns/{uuid}', 'patch',
                      body=net_dns_create_args)])

    def test_configure_dns_for_active_directory(self):

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=fake.FAKE_VOL_MOVE_STATUS))
        self.mock_object(self.client, 'get_dns_config',
                         mock.Mock(return_value={}))

        security_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE)
        self.client.configure_dns(security_service)

        net_dns_create_args = {
            'domains': [security_service['domain']],
            'servers': [security_service['dns_ip']],
        }

        self.client.send_request.assert_has_calls([
            mock.call('/svm/svms', 'get',
                      query={'name': None, 'fields': 'uuid'}),
            mock.call('/name-services/dns', 'post', body=net_dns_create_args)])

    def test_configure_dns_multiple_dns_ip(self):

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=fake.FAKE_VOL_MOVE_STATUS))
        self.mock_object(self.client, 'get_dns_config',
                         mock.Mock(return_value={}))
        mock_dns_ips = '10.0.0.5, 10.0.0.6, 10.0.0.7'
        security_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE)
        security_service['dns_ip'] = mock_dns_ips

        args_dns = {'domains': [security_service['domain']],
                    'servers': ['10.0.0.5',
                                '10.0.0.6',
                                '10.0.0.7']}
        self.client.configure_dns(security_service)

        self.client.send_request.assert_has_calls([
            mock.call('/svm/svms', 'get',
                      query={'name': None, 'fields': 'uuid'}),
            mock.call('/name-services/dns', 'post', body=args_dns)])

    def test_configure_dns_for_kerberos(self):

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=fake.FAKE_VOL_MOVE_STATUS))
        self.mock_object(self.client, 'get_dns_config',
                         mock.Mock(return_value={}))

        security_service = copy.deepcopy(fake.KERBEROS_SECURITY_SERVICE)
        self.client.configure_dns(security_service)

        net_dns_create_args = {
            'domains': [security_service['domain']],
            'servers': [security_service['dns_ip']],
        }

        self.client.send_request.assert_has_calls([
            mock.call('/svm/svms', 'get',
                      query={'name': None, 'fields': 'uuid'}),
            mock.call('/name-services/dns', 'post', body=net_dns_create_args)])

    def test_configure_dns_api_error(self):
        self.mock_object(self.client, 'send_request', self._mock_api_error())
        self.mock_object(self.client, 'get_dns_config',
                         mock.Mock(return_value={}))
        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value={}))

        self.assertRaises(exception.NetAppException,
                          self.client.configure_dns,
                          copy.deepcopy(fake.KERBEROS_SECURITY_SERVICE))

    def test_get_dns_config_no_response(self):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=netapp_api.api.NaApiError))
        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value={}))
        self.assertRaises(exception.NetAppException,
                          self.client.get_dns_config)

    def test_get_dns_config(self):
        api_response = fake.DNS_REST_RESPONSE
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))
        fake_uuid = fake.FAKE_VOL_MOVE_STATUS['records'][0]['svm']['uuid']
        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake_uuid))

        result = self.client.get_dns_config()

        expected_result = {
            'dns-state': 'true',
            'domains': ['example.com', 'example2.example3.com'],
            'dns-ips': ['10.224.65.20', '2001:db08:a0b:12f0::1']
        }
        self.assertEqual(expected_result, result)
        self.client.send_request.assert_called_once_with(
            f'/name-services/dns/{fake_uuid}', 'get')

    @ddt.data(fake.LDAP_AD_SECURITY_SERVICE, fake.CIFS_SECURITY_SERVICE_3,
              fake.KERBEROS_SECURITY_SERVICE)
    def test_setup_security_services(self, security_service):
        fake_response = fake.FAKE_GET_CLUSTER_NODE_VERSION_REST
        mock_request = self.mock_object(self.client, 'send_request',
                                        mock.Mock(return_value=fake_response))
        self.mock_object(self.client, 'configure_ldap')
        self.mock_object(self.client, 'configure_active_directory')
        self.mock_object(self.client, 'configure_cifs_options')
        self.mock_object(self.client, 'create_kerberos_realm')
        self.mock_object(self.client, 'configure_kerberos')

        ss_copy = copy.deepcopy(security_service)
        self.client.setup_security_services([ss_copy], self.client,
                                            'fake_vservername')
        uuid = fake_response.get('records')[0].get('uuid')
        body = {
            'nsswitch.namemap': ['ldap', 'files'],
            'nsswitch.group': ['ldap', 'files'],
            'nsswitch.netgroup': ['ldap', 'files'],
            'nsswitch.passwd': ['ldap', 'files'],
        }
        mock_request.assert_has_calls([
            mock.call('/svm/svms', 'get',
                      query={'name': 'fake_vservername', 'fields': 'uuid'}),
            mock.call(f'/svm/svms/{uuid}', 'patch', body=body)])

    def test_modify_ldap_ad(self):
        fake_svm_uuid = fake.FAKE_UUID
        mock_svm_uuid = self.mock_object(self.client,
                                         '_get_unique_svm_by_name',
                                         mock.Mock(return_value=fake_svm_uuid))
        mock_sr = self.mock_object(self.client, 'send_request')
        security_service = {
            'domain': 'fake_domain',
            'user': 'fake_user',
            'ou': 'fake_ou',
            'dns_ip': 'fake_ip',
            'password': 'fake_password'
        }

        ad_domain = security_service.get('domain')
        body = {
            'port': '389',
            'schema': 'MS-AD-BIS',
            'bind_dn': (security_service.get('user') + '@' + ad_domain),
            'bind_password': security_service.get('password'),
            'base_dn': security_service.get('ou'),
            'ad_domain': security_service.get('domain'),
        }

        self.client.modify_ldap(security_service, None)
        mock_svm_uuid.assert_called_once_with(None)
        mock_sr.assert_called_once_with(f'/name-services/ldap/{fake_svm_uuid}',
                                        'patch', body=body)

    def test_modify_ldap_linux(self):
        fake_svm_uuid = fake.FAKE_UUID
        mock_svm_uuid = self.mock_object(self.client,
                                         '_get_unique_svm_by_name',
                                         mock.Mock(return_value=fake_svm_uuid))
        mock_sr = self.mock_object(self.client, 'send_request')
        security_service = {
            'server': 'fake_server',
            'user': 'fake_user',
            'ou': 'fake_ou',
            'dns_ip': 'fake_ip'
        }

        body = {
            'port': '389',
            'schema': 'RFC-2307',
            'bind_dn': security_service.get('user'),
            'bind_password': security_service.get('password'),
            'base_dn': security_service.get('ou'),
            'servers': [security_service.get('server')]
        }

        self.client.modify_ldap(security_service, None)
        mock_svm_uuid.assert_called_once_with(None)
        mock_sr.assert_called_once_with(f'/name-services/ldap/{fake_svm_uuid}',
                                        'patch', body=body)

    def test_update_kerberos_realm(self):
        self.mock_object(self.client,
                         '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake.FAKE_UUID))
        fake_uuid = fake.FAKE_UUID
        self.mock_object(self.client, 'send_request')
        self.client.update_kerberos_realm(fake.KERBEROS_SECURITY_SERVICE)
        fake_domain = fake.KERBEROS_SECURITY_SERVICE['domain']
        body = {
            'kdc-ip': fake.KERBEROS_SECURITY_SERVICE['server'],
        }

        self.client.send_request.assert_has_calls([
            mock.call(
                f'/protocols/nfs/kerberos/realms/{fake_uuid}/{fake_domain}',
                'patch', body=body)])

    def test__get_unique_svm_by_name(self):
        response = fake.SVMS_LIST_SIMPLE_RESPONSE_REST
        svm = fake.SVM_ITEM_SIMPLE_RESPONSE_REST['uuid']

        fake_query = {
            'name': fake.VSERVER_NAME,
            'fields': 'uuid'
        }

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))

        result = self.client._get_unique_svm_by_name(
            fake.VSERVER_NAME)

        self.client.send_request.assert_called_once_with(
            '/svm/svms', 'get', query=fake_query)

        self.assertEqual(svm, result)

    def test_update_dns_configuration(self):
        dns_config = {
            'domains': [fake.KERBEROS_SECURITY_SERVICE['domain']],
            'dns-ips': [fake.KERBEROS_SECURITY_SERVICE['dns_ip']],
        }

        body = {
            'domains': [fake.KERBEROS_SECURITY_SERVICE['domain']],
            'servers': [fake.KERBEROS_SECURITY_SERVICE['dns_ip']]
        }

        fake_uuid = 'fake_uuid'

        self.mock_object(self.client, 'get_dns_config',
                         mock.Mock(return_value=dns_config))

        self.mock_object(self.client,
                         '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake_uuid))

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=fake.FAKE_VOL_MOVE_STATUS))

        self.client.configure_dns(fake.KERBEROS_SECURITY_SERVICE)
        body = {
            'domains': [fake.KERBEROS_SECURITY_SERVICE['domain']],
            'servers': [fake.KERBEROS_SECURITY_SERVICE['dns_ip']]
        }

        self.client.send_request.assert_called_once_with(
            f'/name-services/dns/{fake_uuid}', 'patch', body=body)

    def test_remove_preferred_dcs(self):
        svm_uuid = copy.deepcopy(fake.FAKE_UUID)
        fqdn = copy.deepcopy(fake.PREFERRED_DC_REST.get('fqdn'))
        server_ip = copy.deepcopy(fake.PREFERRED_DC_REST.get('server_ip'))
        fake_response = copy.deepcopy(fake.PREFERRED_DC_REST)
        fake_ss = copy.deepcopy(fake.LDAP_AD_SECURITY_SERVICE)
        self.mock_object(self.client, 'send_request',
                                      mock.Mock(return_value=fake_response))
        self.client.remove_preferred_dcs(fake_ss, svm_uuid)
        self.client.send_request.has_calls([
            mock.call(f'/protocols/cifs/domains/{svm_uuid}/'
                      f'preferred-domain-controllers/', 'get'),
            mock.call(f'/protocols/cifs/domains/{svm_uuid}/'
                      f'preferred-domain-controllers/{fqdn}/{server_ip}',
                      'delete', query=fqdn)
        ])

    def test_remove_preferred_dcs_api_error(self):
        fake_response = copy.deepcopy(fake.PREFERRED_DC_REST)
        fake_ss = copy.deepcopy(fake.LDAP_AD_SECURITY_SERVICE)
        self.mock_object(self.client, 'send_request',
                                      mock.Mock(return_value=fake_response))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=netapp_api.api.NaApiError))
        self.assertRaises(netapp_api.api.NaApiError,
                          self.client.remove_preferred_dcs,
                          fake_ss, fake.FAKE_UUID)

    def test_set_preferred_dc(self):
        fake_ss = copy.deepcopy(fake.LDAP_AD_SECURITY_SERVICE_WITH_SERVER)
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake.FAKE_UUID))

        self.client.set_preferred_dc(fake_ss, fake.VSERVER_NAME)

        self.client._get_unique_svm_by_name.assert_called_once_with(
            fake.VSERVER_NAME)

        query = {
            'fqdn': fake_ss['domain'],
            'skip_config_validation': 'false',
            'server_ip': ['10.10.10.1']
        }
        self.client.send_request.assert_called_once_with(
            f'/protocols/cifs/domains/{fake.FAKE_UUID}'
            '/preferred-domain-controllers', 'post', query=query)

    @ddt.data(None, 'cluster_name')
    def test_create_vserver_peer(self, cluster_name):

        self.mock_object(self.client, 'send_request')

        self.client.create_vserver_peer(fake.VSERVER_NAME,
                                        fake.VSERVER_PEER_NAME,
                                        peer_cluster_name=cluster_name)

        body = {
            'svm.name': fake.VSERVER_NAME,
            'peer.svm.name': fake.VSERVER_PEER_NAME,
            'applications': ['snapmirror'],
        }
        if cluster_name:
            body['peer.cluster.name'] = cluster_name

        self.client.send_request.assert_has_calls([
            mock.call('/svm/peers', 'post', body=body,
                      enable_tunneling=False)])

    def test__get_svm_peer_uuid(self):
        response = {
            "records": [{
                "uuid": "fake-vserver-uuid",
                "name": fake.VSERVER_NAME,
                "svm": {
                    "name": fake.VSERVER_NAME,
                },
                "peer": {
                    "svm": {
                        "name": fake.VSERVER_PEER_NAME,
                        }
                }
            }],
        }
        expected_result = "fake-vserver-uuid"
        return_value = response['records'][0]['uuid']
        self.mock_object(self.client, '_get_svm_peer_uuid',
                         mock.Mock(return_value=return_value))

        result = self.client._get_svm_peer_uuid(
            fake.VSERVER_NAME, fake.VSERVER_PEER_NAME)

        self.client._get_svm_peer_uuid.assert_called_once_with(
            fake.VSERVER_NAME, fake.VSERVER_PEER_NAME)

        self.assertEqual(expected_result, result)

    def test_accept_vserver_peer(self):

        fake_resp = {
            'records': [{'uuid': 'fake-vserver-uuid'}],
            'num_records': 1,
        }

        self.mock_object(
            self.client, 'send_request',
            mock.Mock(side_effect=[fake_resp, None]))
        self.client.accept_vserver_peer(
            fake.VSERVER_NAME, fake.VSERVER_PEER_NAME)

        body = {'state': 'peered'}

        uuid = "fake-vserver-uuid"
        self.client.send_request.assert_has_calls([
            mock.call(f'/svm/peers/{uuid}', 'patch', body=body,
                      enable_tunneling=False)])

    def test_get_vserver_peers(self):
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=fake.FAKE_PEER_GET_RESPONSE))

        result = self.client.get_vserver_peers(
            vserver_name=fake.VSERVER_NAME,
            peer_vserver_name=fake.VSERVER_NAME_2)

        query = {
            'name': fake.VSERVER_NAME_2,
            'svm.name': fake.VSERVER_NAME
        }
        query['fields'] = 'uuid,svm.name,peer.svm.name,state,peer.cluster.name'
        self.client.send_request.assert_has_calls([
            mock.call('/svm/peers', 'get', query=query)])

        expected = [{
            'uuid': fake.FAKE_UUID,
            'vserver': fake.VSERVER_NAME,
            'peer-vserver': fake.VSERVER_NAME_2,
            'peer-state': fake.VSERVER_PEER_STATE,
            'peer-cluster': fake.CLUSTER_NAME
        }]
        self.assertEqual(expected, result)

    def test_get_vserver_peers_not_found(self):

        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=fake.NO_RECORDS_RESPONSE_REST))

        result = self.client.get_vserver_peers(
            vserver_name=fake.VSERVER_NAME,
            peer_vserver_name=fake.VSERVER_NAME_2)

        self.assertEqual([], result)
        self.assertTrue(self.client.send_request.called)

    def test_delete_vserver_peer(self):

        self.mock_object(self.client, 'get_vserver_peers',
                         mock.Mock(return_value=fake.FAKE_VSERVER_PEERS))

        self.mock_object(self.client, 'send_request')

        self.client.delete_vserver_peer(fake.VSERVER_NAME,
                                        fake.VSERVER_PEER_NAME)

        self.client.get_vserver_peers.assert_called_once_with(
            fake.VSERVER_NAME, fake.VSERVER_PEER_NAME)
        self.client.send_request.assert_called_once_with(
            '/svm/peers/fake_uuid', 'delete', enable_tunneling=False)

    @ddt.data({'tcp-max-xfer-size': 10000}, {}, None)
    def test_enable_nfs(self, nfs_config):
        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake.FAKE_UUID))
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client,
                         '_enable_nfs_protocols')
        self.mock_object(self.client,
                         '_configure_nfs')
        self.mock_object(self.client,
                         '_create_default_nfs_export_rules')

        self.mock_object(self.client, '_enable_nfs_protocols')

        self.client.enable_nfs(fake.NFS_VERSIONS, nfs_config)
        body = {
            'svm.uuid': fake.FAKE_UUID,
            'enabled': 'true'
        }

        self.client.send_request.assert_called_once_with(
            '/protocols/nfs/services/', 'post', body=body)
        self.client._get_unique_svm_by_name.assert_called_once_with()
        self.client._enable_nfs_protocols.assert_called_once_with(
            fake.NFS_VERSIONS, fake.FAKE_UUID)
        if nfs_config:
            self.client._configure_nfs.assert_called_once_with(nfs_config,
                                                               fake.FAKE_UUID)
        else:
            self.client._configure_nfs.assert_not_called()
        self.client._create_default_nfs_export_rules.assert_called_once_with()

    @ddt.data((True, True, True), (True, False, False), (False, True, True))
    @ddt.unpack
    def test_enable_nfs_protocols(self, v3, v40, v41):

        self.mock_object(self.client, 'send_request')

        versions = []
        if v3:
            versions.append('nfs3')
        if v40:
            versions.append('nfs4.0')
        if v41:
            versions.append('nfs4.1')

        self.client._enable_nfs_protocols(versions, fake.FAKE_UUID)

        body = {
            'protocol.v3_enabled': 'true' if v3 else 'false',
            'protocol.v40_enabled': 'true' if v40 else 'false',
            'protocol.v41_enabled': 'true' if v41 else 'false',
            'showmount_enabled': 'true',
            'windows.v3_ms_dos_client_enabled': 'true',
            'protocol.v3_features.connection_drop': 'false',
            'protocol.v3_features.ejukebox_enabled': 'false',
        }
        self.client.send_request.assert_called_once_with(
            f'/protocols/nfs/services/{fake.FAKE_UUID}',
            'patch', body=body)

    def test_configure_nfs(self):
        self.mock_object(self.client, 'send_request')

        fake_nfs = {
            'tcp-max-xfer-size': 10000,
        }
        self.client._configure_nfs(fake_nfs, fake.FAKE_UUID)

        body = {
            'transport.tcp_max_transfer_size': 10000
        }
        self.client.send_request.assert_called_once_with(
            f'/protocols/nfs/services/{fake.FAKE_UUID}',
            'patch', body=body)

    def test__create_default_nfs_export_rules(self):

        class CopyingMock(mock.Mock):
            def __call__(self, *args, **kwargs):
                args = copy.deepcopy(args)
                kwargs = copy.deepcopy(kwargs)
                return super(CopyingMock, self).__call__(*args, **kwargs)

        self.mock_object(self.client, 'send_request', CopyingMock())

        fake_uuid = fake.FAKE_UUID

        mock_id = self.mock_object(self.client, 'get_unique_export_policy_id',
                                   mock.Mock(return_value=fake_uuid))

        self.client._create_default_nfs_export_rules()

        body = {
            'clients': [{
                'match': '0.0.0.0/0'
            }],
            'ro_rule': [
                'any',
            ],
            'rw_rule': [
                'never'
            ],
        }
        body2 = body.copy()
        body2['clients'] = [{
            'match': '::/0'
        }]

        mock_id.assert_called_once_with('default')
        self.client.send_request.assert_has_calls([
            mock.call(f'/protocols/nfs/export-policies/{fake_uuid}/rules',
                      "post", body=body),
            mock.call(f'/protocols/nfs/export-policies/{fake_uuid}/rules',
                      "post", body=body2)])

    def test_get_node_data_ports(self):
        self.mock_object(
            self.client, 'send_request', mock.Mock(
                side_effect=[fake.REST_ETHERNET_PORTS,
                             fake.REST_MGMT_INTERFACES]))
        self.mock_object(
            self.client, '_sort_data_ports_by_speed', mock.Mock(
                return_value=fake.REST_SPEED_SORTED_PORTS))

        test_result = self.client.get_node_data_ports(fake.NODE_NAME)

        fake_query = {
            'node.name': fake.NODE_NAME,
            'state': 'up',
            'type': 'physical',
            'fields': 'node.name,speed,name'
        }

        query_interfaces = {
            'service_policy.name': 'default-management',
            'fields': 'location.port.name'
        }

        self.client.send_request.assert_has_calls([
            mock.call('/network/ethernet/ports', 'get', query=fake_query),
            mock.call('/network/ip/interfaces', 'get',
                      query=query_interfaces, enable_tunneling=False),
        ])
        self.client._sort_data_ports_by_speed.assert_called_once_with(
            fake.REST_SPEED_NOT_SORTED_PORTS)
        self.assertEqual(fake.REST_SPEED_SORTED_PORTS, test_result)

    def test_list_node_data_ports(self):

        expected_resulted = ['e0d', 'e0c', 'e0b']

        mock_ports = (
            self.mock_object(self.client, 'get_node_data_ports', mock.Mock(
                             return_value=fake.REST_SPEED_SORTED_PORTS)))

        test_result = self.client.list_node_data_ports(fake.NODE_NAME)

        mock_ports.assert_called_once_with(fake.NODE_NAME)
        self.assertEqual(test_result, expected_resulted)

    def test_create_ipspace(self):
        fake_body = {'name': fake.IPSPACE_NAME}

        self.mock_object(self.client, 'send_request')

        self.client.create_ipspace(fake.IPSPACE_NAME)

        self.client.send_request.assert_called_once_with(
            '/network/ipspaces', 'post', body=fake_body)

    def test_get_ipspace_name_for_vlan_port(self):

        fake_query = {
            'node.name': fake.NODE_NAME,
            'name': fake.VLAN_PORT,
            'fields': 'broadcast_domain.ipspace.name',
        }

        expected_result = "Default"

        self.mock_object(
            self.client, 'send_request', mock.Mock(
                return_value=fake.REST_ETHERNET_PORTS))

        test_result = self.client.get_ipspace_name_for_vlan_port(
            fake.NODE_NAME, fake.PORT, fake.VLAN)

        self.client.send_request.assert_called_once_with(
            '/network/ethernet/ports/', 'get', query=fake_query)

        self.assertEqual(test_result, expected_result)

    def test__create_broadcast_domain(self):

        fake_body = {
            'ipspace.name': fake.IPSPACE_NAME,
            'name': fake.BROADCAST_DOMAIN,
            'mtu': fake.MTU,
        }

        self.mock_object(self.client, 'send_request')

        self.client._create_broadcast_domain(fake.BROADCAST_DOMAIN,
                                             fake.IPSPACE_NAME,
                                             fake.MTU)

        self.client.send_request.assert_called_once_with(
            '/network/ethernet/broadcast-domains', 'post', body=fake_body)

    def test_ensure_broadcast_domain_for_port_domain_match(self):

        port_info = {
            'ipspace': fake.IPSPACE_NAME,
            'broadcast-domain': fake.BROADCAST_DOMAIN,
        }
        self.mock_object(self.client,
                         '_get_broadcast_domain_for_port',
                         mock.Mock(return_value=port_info))
        self.mock_object(self.client,
                         '_broadcast_domain_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.client, '_create_broadcast_domain')
        self.mock_object(self.client, '_modify_broadcast_domain')
        self.mock_object(self.client, '_add_port_to_broadcast_domain')

        self.client._ensure_broadcast_domain_for_port(
            fake.NODE_NAME, fake.PORT, fake.MTU, ipspace=fake.IPSPACE_NAME)

        self.client._get_broadcast_domain_for_port.assert_called_once_with(
            fake.NODE_NAME, fake.PORT)
        self.client._modify_broadcast_domain.assert_called_once_with(
            fake.BROADCAST_DOMAIN, fake.IPSPACE_NAME, fake.MTU)
        self.assertFalse(self.client._broadcast_domain_exists.called)
        self.assertFalse(self.client._create_broadcast_domain.called)
        self.assertFalse(self.client._add_port_to_broadcast_domain.called)

    @ddt.data(fake.IPSPACE_NAME, client_cmode.DEFAULT_IPSPACE)
    def test_ensure_broadcast_domain_for_port_other_domain(self, ipspace):

        port_info = {
            'ipspace': ipspace,
            'broadcast-domain': 'other_domain',
        }
        self.mock_object(self.client,
                         '_get_broadcast_domain_for_port',
                         mock.Mock(return_value=port_info))
        self.mock_object(self.client,
                         '_broadcast_domain_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.client, '_create_broadcast_domain')
        self.mock_object(self.client, '_modify_broadcast_domain')
        self.mock_object(self.client, '_add_port_to_broadcast_domain')

        self.client._ensure_broadcast_domain_for_port(
            fake.NODE_NAME, fake.PORT, ipspace=fake.IPSPACE_NAME, mtu=fake.MTU)

        self.client._get_broadcast_domain_for_port.assert_called_once_with(
            fake.NODE_NAME, fake.PORT)
        self.client._broadcast_domain_exists.assert_called_once_with(
            fake.BROADCAST_DOMAIN, fake.IPSPACE_NAME)
        self.assertFalse(self.client._create_broadcast_domain.called)
        self.client._modify_broadcast_domain.assert_called_once_with(
            fake.BROADCAST_DOMAIN, fake.IPSPACE_NAME, fake.MTU)
        self.client._add_port_to_broadcast_domain.assert_called_once_with(
            fake.NODE_NAME, fake.PORT, fake.BROADCAST_DOMAIN,
            fake.IPSPACE_NAME)

    def test_ensure_broadcast_domain_for_port_no_domain(self):

        port_info = {
            'ipspace': fake.IPSPACE_NAME,
            'broadcast-domain': None,
        }
        self.mock_object(self.client,
                         '_get_broadcast_domain_for_port',
                         mock.Mock(return_value=port_info))
        self.mock_object(self.client,
                         '_broadcast_domain_exists',
                         mock.Mock(return_value=False))
        self.mock_object(self.client, '_create_broadcast_domain')
        self.mock_object(self.client, '_modify_broadcast_domain')
        self.mock_object(self.client, '_add_port_to_broadcast_domain')

        self.client._ensure_broadcast_domain_for_port(
            fake.NODE_NAME, fake.PORT, ipspace=fake.IPSPACE_NAME, mtu=fake.MTU)

        self.client._get_broadcast_domain_for_port.assert_called_once_with(
            fake.NODE_NAME, fake.PORT)
        self.client._broadcast_domain_exists.assert_called_once_with(
            fake.BROADCAST_DOMAIN, fake.IPSPACE_NAME)
        self.client._create_broadcast_domain.assert_called_once_with(
            fake.BROADCAST_DOMAIN, fake.IPSPACE_NAME, fake.MTU)
        self.assertFalse(self.client._modify_broadcast_domain.called)
        self.client._add_port_to_broadcast_domain.assert_called_once_with(
            fake.NODE_NAME, fake.PORT, fake.BROADCAST_DOMAIN,
            fake.IPSPACE_NAME)

    def test__add_port_to_broadcast_domain(self):
        query = {
            'name': fake.PORT,
            'node.name': fake.NODE_NAME,
        }
        body = {
            'broadcast_domain.ipspace.name': fake.IPSPACE_NAME,
            'broadcast_domain.name': fake.BROADCAST_DOMAIN,
        }

        self.mock_object(self.client, 'send_request')
        self.client._add_port_to_broadcast_domain(fake.NODE_NAME,
                                                  fake.PORT,
                                                  fake.BROADCAST_DOMAIN,
                                                  fake.IPSPACE_NAME)

        self.client.send_request.assert_called_once_with(
            '/network/ethernet/ports/', 'patch', query=query, body=body)

    def test__add_port_to_broadcast_domain_exists(self):
        query = {
            'name': fake.PORT,
            'node.name': fake.NODE_NAME,
        }
        body = {
            'broadcast_domain.ipspace.name': fake.IPSPACE_NAME,
            'broadcast_domain.name': fake.BROADCAST_DOMAIN,
        }
        self.mock_object(
            self.client, 'send_request', self._mock_api_error(
                code=netapp_api.EREST_FAIL_ADD_PORT_BROADCAST))

        self.client._add_port_to_broadcast_domain(fake.NODE_NAME,
                                                  fake.PORT,
                                                  fake.BROADCAST_DOMAIN,
                                                  fake.IPSPACE_NAME)

        self.client.send_request.assert_called_once_with(
            '/network/ethernet/ports/', 'patch', query=query, body=body)
        self.assertEqual(1, client_cmode_rest.LOG.debug.call_count)

    def test__add_port_to_broadcast_domain_exception(self):
        self.mock_object(self.client, 'send_request',
                         self._mock_api_error())
        self.assertRaises(
            exception.NetAppException,
            self.client._add_port_to_broadcast_domain,
            fake.NODE_NAME, fake.PORT, fake.BROADCAST_DOMAIN,
            fake.IPSPACE_NAME)

    def test_rename_vserver(self):
        svm_uuid = fake.SVM_ITEM_SIMPLE_RESPONSE_REST["uuid"]
        body = {
            'name': fake.VSERVER_NAME_2
        }

        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value=svm_uuid))
        self.mock_object(self.client, 'send_request')

        self.client.rename_vserver(fake.VSERVER_NAME, fake.VSERVER_NAME_2)

        self.client._get_unique_svm_by_name.assert_called_once_with(
            fake.VSERVER_NAME)
        self.client.send_request.assert_called_once_with(
            f'/svm/svms/{svm_uuid}', 'patch', body=body)

    def test_create_network_interface(self):
        api_response = copy.deepcopy(fake.SERVICE_POLICIES_REST)
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(side_effect=[api_response, None, None]))

        self.client.create_network_interface(fake.IP_ADDRESS,
                                             fake.NETMASK,
                                             fake.NODE_NAME,
                                             fake.VLAN_PORT,
                                             fake.VSERVER_NAME,
                                             fake.LIF_NAME)
        query = {
            'name': 'default-data-files',
            'svm.name': fake.VSERVER_NAME,
            'fields': 'uuid,name,services,svm.name'
        }

        policy = copy.deepcopy(fake.SERVICE_POLICIES_REST['records'][0])
        uuid = policy['uuid']

        policy['services'].append('data_nfs')
        policy['services'].append('data_cifs')
        body1 = {'services': policy['services']}

        body2 = {
            'ip.address': fake.IP_ADDRESS,
            'ip.netmask': fake.NETMASK,
            'enabled': 'true',
            'service_policy.name': 'default-data-files',
            'location.home_node.name': fake.NODE_NAME,
            'location.home_port.name': fake.VLAN_PORT,
            'name': fake.LIF_NAME,
            'svm.name': fake.VSERVER_NAME,
        }

        self.client.send_request.assert_has_calls([
            mock.call('/network/ip/service-policies/', 'get', query=query),
            mock.call(f'/network/ip/service-policies/{uuid}',
                      'patch', body=body1),
            mock.call('/network/ip/interfaces', 'post', body=body2)
        ])

    def test_create_vserver(self):
        mock = self.mock_object(self.client, '_create_vserver')
        self.mock_object(self.client, '_modify_security_cert',
                         mock.Mock(return_value=[]))
        self.client.create_vserver(fake.VSERVER_NAME, None, None,
                                   [fake.SHARE_AGGREGATE_NAME],
                                   fake.IPSPACE_NAME,
                                   fake.SECURITY_CERT_DEFAULT_EXPIRE_DAYS)
        mock.assert_called_once_with(fake.VSERVER_NAME,
                                     [fake.SHARE_AGGREGATE_NAME],
                                     fake.IPSPACE_NAME,
                                     name_server_switch=['files'])
        self.client._modify_security_cert.assert_called_once_with(
            fake.VSERVER_NAME,
            fake.SECURITY_CERT_DEFAULT_EXPIRE_DAYS)

    def test__modify_security_cert(self):
        api_response = copy.deepcopy(fake.SECURITY_CERT_GET_RESPONSE_REST)
        api_response2 = copy.deepcopy(fake.SECURITY_CERT_POST_RESPONSE_REST)
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(side_effect=[api_response, api_response2, None, None]))

        query = {
            'common-name': fake.VSERVER_NAME,
            'ca': fake.VSERVER_NAME,
            'type': 'server',
            'svm.name': fake.VSERVER_NAME,
        }
        old_cert_info = copy.deepcopy(
            fake.SECURITY_CERT_GET_RESPONSE_REST['records'][0])
        old_cert_uuid = old_cert_info['uuid']

        body1 = {
            'common-name': fake.VSERVER_NAME,
            'type': 'server',
            'svm.name': fake.VSERVER_NAME,
            'expiry_time': 'P' + str(
                fake.SECURITY_CERT_LARGE_EXPIRE_DAYS) + 'DT',
        }
        query1 = {
            'return_records': 'true'
        }
        new_cert_info = copy.deepcopy(
            fake.SECURITY_CERT_POST_RESPONSE_REST['records'][0])
        new_cert_uuid = new_cert_info['uuid']
        new_svm_uuid = new_cert_info['svm']['uuid']
        body2 = {
            'certificate': {
                'uuid': new_cert_uuid,
            },
            'client_enabled': 'false',
        }

        self.client._modify_security_cert(
            fake.VSERVER_NAME,
            fake.SECURITY_CERT_LARGE_EXPIRE_DAYS)

        self.client.send_request.assert_has_calls([
            mock.call('/security/certificates', 'get', query=query),
            mock.call('/security/certificates', 'post', body=body1,
                      query=query1),
            mock.call(f'/svm/svms/{new_svm_uuid}', 'patch', body=body2),
            mock.call(f'/security/certificates/{old_cert_uuid}', 'delete'),
        ])

    def test__broadcast_domain_exists(self):
        response = fake.FAKE_GET_BROADCAST_DOMAIN
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))
        query = {
            'ipspace.name': fake.IPSPACE_NAME,
            'name': fake.BROADCAST_DOMAIN,
        }
        result = self.client._broadcast_domain_exists(fake.BROADCAST_DOMAIN,
                                                      fake.IPSPACE_NAME)
        self.client.send_request.assert_called_once_with(
            '/network/ethernet/broadcast-domains',
            'get', query=query)
        self.assertTrue(result)

    def test___delete_port_by_ipspace_and_broadcast_domain(self):
        self.mock_object(self.client, 'send_request')
        query = {
            'broadcast_domain.ipspace.name': fake.IPSPACE_NAME,
            'broadcast_domain.name': fake.BROADCAST_DOMAIN,
            'name': fake.PORT
        }
        self.client._delete_port_by_ipspace_and_broadcast_domain(
            fake.PORT,
            fake.BROADCAST_DOMAIN,
            fake.IPSPACE_NAME)
        self.client.send_request.assert_called_once_with(
            '/network/ethernet/ports/', 'delete',
            query=query)

    def test_get_broadcast_domain_for_port(self):

        self.mock_object(self.client, 'send_request', mock.Mock(
            return_value=fake.REST_ETHERNET_PORTS))

        query = {
            'node.name': fake.NODE_NAME,
            'name': fake.PORT,
            'fields': 'broadcast_domain.name,broadcast_domain.ipspace.name'
        }

        result = self.client._get_broadcast_domain_for_port(fake.NODE_NAME,
                                                            fake.PORT)

        expected = {
            'broadcast-domain': "fake_domain_1",
            'ipspace': "Default",
        }
        self.client.send_request.assert_has_calls([
            mock.call('/network/ethernet/ports', 'get', query=query)])
        self.assertEqual(expected, result)

    def test_modify_broadcast_domain(self):

        self.mock_object(self.client, 'send_request')

        result = self.client._modify_broadcast_domain(fake.BROADCAST_DOMAIN,
                                                      fake.IPSPACE_NAME,
                                                      fake.MTU)

        query = {
            'name': fake.BROADCAST_DOMAIN
        }

        body = {
            'ipspace.name': fake.IPSPACE_NAME,
            'mtu': fake.MTU,
        }
        self.assertIsNone(result)
        self.client.send_request.assert_called_once_with(
            '/network/ethernet/broadcast-domains', 'patch', body=body,
            query=query)

    @ddt.data(fake.NO_RECORDS_RESPONSE,
              fake.SVMS_LIST_SIMPLE_RESPONSE_REST)
    def test_get_vserver_info(self, api_response):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_vserver_info(fake.VSERVER_NAME)

        query = {
            'name': fake.VSERVER_NAME,
            'fields': 'state,subtype'
        }
        self.client.send_request.assert_called_once_with(
            '/svm/svms', 'get', query=query)
        if api_response == fake.NO_RECORDS_RESPONSE:
            self.assertIsNone(result)
        else:
            self.assertDictEqual(fake.VSERVER_INFO, result)

    def test_get_nfs_config(self):
        api_response = fake.NFS_CONFIG_RESULT_REST
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_nfs_config(['tcp-max-xfer-size',
                                            'udp-max-xfer-size'],
                                            fake.VSERVER_NAME)
        expected = {
            'tcp-max-xfer-size': '65536',
            'udp-max-xfer-size': '32768',
        }
        self.assertEqual(expected, result)

        query = {'fields': 'transport.*', 'svm.name': 'fake_vserver'}
        self.client.send_request.assert_called_once_with(
            '/protocols/nfs/services/', 'get', query=query)

    def test_get_vserver_ipspace(self):

        self.client.features.add_feature('IPSPACES')
        api_response = fake.REST_VSERVER_GET_IPSPACE_NAME_RESPONSE
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_vserver_ipspace(fake.VSERVER_NAME)

        query = {
            'name': fake.VSERVER_NAME,
            'fields': 'ipspace.name'
        }
        expected = fake.IPSPACE_NAME
        self.client.send_request.assert_has_calls([
            mock.call('/svm/svms', 'get', query=query)])
        self.assertEqual(expected, result)

    def test_get_vserver_ipspace_not_found(self):
        api_response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))
        result = self.client.get_vserver_ipspace(fake.VSERVER_NAME)
        self.assertIsNone(result)

    def test_get_vserver_ipspace_exception(self):
        self.mock_object(self.client, 'send_request',
                         self._mock_api_error())
        self.assertRaises(exception.NetAppException,
                          self.client.get_vserver_ipspace,
                          fake.VSERVER_NAME)

    def test_get_snapmirror_policies(self):
        api_response = fake.GET_SNAPMIRROR_POLICIES_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))
        result_elem = [fake.SNAPMIRROR_POLICY_NAME]

        result = self.client.get_snapmirror_policies(
            fake.VSERVER_NAME)

        query = {
            'svm.name': fake.VSERVER_NAME,
            'fields': 'name'
        }

        self.client.send_request.assert_called_once_with(
            '/snapmirror/policies', 'get', query=query)
        self.assertEqual(result_elem, result)

    def test_delete_snapmirror_policy(self):
        api_response = fake.GET_SNAPMIRROR_POLICIES_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))

        self.client.delete_snapmirror_policy('fake_policy')

        query = {}
        query['name'] = 'fake_policy'
        query['fields'] = 'uuid,name'
        uuid = fake.FAKE_UUID
        self.client.send_request.assert_has_calls([
            mock.call('/snapmirror/policies', 'get', query=query),
            mock.call(f'/snapmirror/policies/{uuid}', 'delete')
        ])

    def test_delete_snapmirror_policy_exception(self):
        api_response = fake.GET_SNAPMIRROR_POLICIES_REST
        api_error = netapp_api.api.NaApiError()
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=[api_response, api_error]))
        self.assertRaises(netapp_api.api.NaApiError,
                          self.client.delete_snapmirror_policy,
                          'fake_policy')

    def test_delete_snapmirror_policy_no_records(self):
        api_response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))

        self.client.delete_snapmirror_policy('fake_policy')

        query = {}
        query['name'] = 'fake_policy'
        query['fields'] = 'uuid,name'
        self.client.send_request.assert_called_once_with(
            '/snapmirror/policies', 'get', query=query)

    def test_delete_vserver_one_volume(self):
        self.mock_object(self.client, 'get_vserver_info',
                         mock.Mock(return_value=fake.VSERVER_INFO))
        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake.FAKE_UUID))
        self.mock_object(self.client, 'get_vserver_root_volume_name',
                         mock.Mock(return_value=fake.ROOT_VOLUME_NAME))
        self.mock_object(self.client, 'get_vserver_volume_count',
                         mock.Mock(return_value=1))
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'offline_volume')
        self.mock_object(self.client, 'delete_volume')
        self.mock_object(self.client, '_terminate_vserver_services')

        self.client.delete_vserver(fake.VSERVER_NAME, self.client,
                                   fake.CIFS_SECURITY_SERVICE)

        self.client.offline_volume.assert_called_with(fake.ROOT_VOLUME_NAME)
        self.client.delete_volume.assert_called_with(fake.ROOT_VOLUME_NAME)
        self.client._terminate_vserver_services(
            fake.VSERVER_NAME, self.client, fake.CIFS_SECURITY_SERVICE)

        svm_uuid = fake.FAKE_UUID
        self.client.send_request.assert_has_calls([
            mock.call(f'/svm/svms/{svm_uuid}', 'delete')])

    def test_delete_vserver_one_volume_already_offline(self):

        self.mock_object(self.client,
                         'get_vserver_info',
                         mock.Mock(return_value=fake.VSERVER_INFO))
        self.mock_object(self.client,
                         '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake.FAKE_UUID))
        self.mock_object(self.client,
                         'get_vserver_root_volume_name',
                         mock.Mock(return_value=fake.ROOT_VOLUME_NAME))
        self.mock_object(self.client,
                         'get_vserver_volume_count',
                         mock.Mock(return_value=1))
        self.mock_object(self.client,
                         'offline_volume',
                         self._mock_api_error(
                             code=netapp_api.EREST_ENTRY_NOT_FOUND))
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'delete_volume')

        self.client.delete_vserver(fake.VSERVER_NAME,
                                   self.client)

        self.client.offline_volume.assert_called_with(
            fake.ROOT_VOLUME_NAME)
        self.client.delete_volume.assert_called_with(
            fake.ROOT_VOLUME_NAME)

        svm_uuid = fake.FAKE_UUID
        self.client.send_request.assert_has_calls([
            mock.call(f'/svm/svms/{svm_uuid}', 'delete')])
        self.assertEqual(1, client_cmode_rest.LOG.error.call_count)

    def test_delete_vserver_one_volume_api_error(self):

        self.mock_object(self.client,
                         'get_vserver_info',
                         mock.Mock(return_value=fake.VSERVER_INFO))
        self.mock_object(self.client,
                         '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake.FAKE_UUID))
        self.mock_object(self.client,
                         'get_vserver_root_volume_name',
                         mock.Mock(return_value=fake.ROOT_VOLUME_NAME))
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client,
                         'get_vserver_volume_count',
                         mock.Mock(return_value=1))
        self.mock_object(self.client,
                         'offline_volume',
                         self._mock_api_error())
        self.mock_object(self.client, 'delete_volume')

        self.assertRaises(netapp_api.api.NaApiError,
                          self.client.delete_vserver,
                          fake.VSERVER_NAME,
                          self.client)

    def test_delete_vserver_multiple_volumes(self):

        self.mock_object(self.client,
                         'get_vserver_info',
                         mock.Mock(return_value=fake.VSERVER_INFO))
        self.mock_object(self.client,
                         '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake.FAKE_UUID))
        self.mock_object(self.client,
                         'get_vserver_root_volume_name',
                         mock.Mock(return_value=fake.ROOT_VOLUME_NAME))
        self.mock_object(self.client,
                         'get_vserver_volume_count',
                         mock.Mock(return_value=2))

        self.assertRaises(exception.NetAppException,
                          self.client.delete_vserver,
                          fake.VSERVER_NAME,
                          self.client)

    def test_delete_vserver_not_found(self):

        self.mock_object(self.client,
                         'get_vserver_info',
                         mock.Mock(return_value=None))
        self.mock_object(self.client,
                         '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake.FAKE_UUID))

        self.client.delete_vserver(fake.VSERVER_NAME,
                                   self.client)

        self.assertEqual(1, client_cmode_rest.LOG.error.call_count)

    def test_get_vserver_volume_count(self):
        fake_response = fake.VOLUME_GET_ITER_RESPONSE_REST_PAGE
        mock_request = self.mock_object(self.client, 'send_request',
                                        mock.Mock(return_value=fake_response))
        response = self.client.get_vserver_volume_count()

        self.assertEqual(response, 10)
        query = {'return_records': 'false'}
        mock_request.assert_called_once_with(
            '/storage/volumes', 'get', query=query)

    def test__terminate_vserver_services(self):

        fake_uuid = fake.FAKE_UUID

        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'disable_kerberos')
        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake_uuid))

        security_services = [
            copy.deepcopy(fake.CIFS_SECURITY_SERVICE),
            copy.deepcopy(fake.KERBEROS_SECURITY_SERVICE)
        ]
        self.client._terminate_vserver_services(
            fake.VSERVER_NAME, self.client, security_services)

        cifs_server_delete_body = {
            'ad_domain.password': security_services[0]['password'],
            'ad_domain.user': security_services[0]['user'],
        }
        self.client.send_request.assert_called_once_with(
            f'/protocols/cifs/services/{fake_uuid}', 'delete',
            body=cifs_server_delete_body)
        self.client.disable_kerberos.assert_called_once_with(
            security_services[1])

    def test_terminate_vserver_services_cifs_not_found(self):

        fake_uuid = fake.FAKE_UUID

        self.mock_object(
            self.client, 'send_request',
            self._mock_api_error(code=netapp_api.EREST_ENTRY_NOT_FOUND))
        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake_uuid))

        security_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE)
        self.client._terminate_vserver_services(fake.VSERVER_NAME,
                                                self.client,
                                                [security_service])

        cifs_server_delete_body = {
            'ad_domain.password': security_service['password'],
            'ad_domain.user': security_service['user'],
        }
        self.client.send_request.assert_called_once_with(
            f'/protocols/cifs/services/{fake_uuid}', 'delete',
            body=cifs_server_delete_body)
        self.assertEqual(1, client_cmode_rest.LOG.error.call_count)

    def test_terminate_vserver_services_api_error(self):

        fake_uuid = fake.FAKE_UUID
        side_effects = [netapp_api.api.NaApiError(code='fake'), None]

        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(side_effect=side_effects))
        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake_uuid))

        security_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE)
        self.client._terminate_vserver_services(fake.VSERVER_NAME,
                                                self.client,
                                                [security_service])

        cifs_server_delete_body = {
            'ad_domain.password': security_service['password'],
            'ad_domain.user': security_service['user'],
        }
        cifs_server_delete_force_body = {
            'ad_domain.password': security_service['password'],
            'ad_domain.user': security_service['user'],
            'force': True
        }

        self.client.send_request.assert_has_calls([
            mock.call(f'/protocols/cifs/services/{fake_uuid}', 'delete',
                      body=cifs_server_delete_body),
            mock.call(f'/protocols/cifs/services/{fake_uuid}', 'delete',
                      body=cifs_server_delete_force_body)])
        self.assertEqual(0, client_cmode_rest.LOG.error.call_count)

    def test_disable_kerberos(self):
        fake_api_response = fake.NFS_LIFS_REST
        api_error = self._mock_api_error(
            code=netapp_api.EREST_KERBEROS_IS_ENABLED_DISABLED)
        self.mock_object(self.client, 'get_network_interfaces',
                         mock.Mock(return_value=fake_api_response))
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(side_effect=[None, api_error, None]))

        self.client.disable_kerberos(fake.KERBEROS_SECURITY_SERVICE)

        kerberos_config_modify_body = {
            'password': fake.KERBEROS_SECURITY_SERVICE['password'],
            'user': fake.KERBEROS_SECURITY_SERVICE['user'],
            'interface.name': fake.LIF_NAME,
            'enabled': False,
        }

        self.client.send_request.assert_has_calls([
            mock.call('/protocols/nfs/kerberos/interfaces/fake_uuid_1',
                      'patch', body=kerberos_config_modify_body),
            mock.call('/protocols/nfs/kerberos/interfaces/fake_uuid_2',
                      'patch', body=kerberos_config_modify_body),
            mock.call('/protocols/nfs/kerberos/interfaces/fake_uuid_3',
                      'patch', body=kerberos_config_modify_body)
        ])
        self.client.get_network_interfaces.assert_called_once()

    def test_get_vserver_root_volume_name(self):
        response = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=response))
        self.client.get_vserver_root_volume_name(fake.VSERVER_NAME)
        self.client._get_volume_by_args.assert_called_once_with(
            vserver=fake.VSERVER_NAME, is_root=True)

    def test_ipspace_has_data_vservers(self):
        api_response = fake.REST_VSERVER_GET_IPSPACE_NAME_RESPONSE
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.ipspace_has_data_vservers(fake.IPSPACE_NAME)

        query = {'ipspace.name': fake.IPSPACE_NAME}
        self.client.send_request.assert_has_calls([
            mock.call('/svm/svms', 'get', query=query)])
        self.assertTrue(result)

    def test_ipspace_has_data_vservers_not_supported(self):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value='fake_response'))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=False))

        result = self.client.ipspace_has_data_vservers(fake.IPSPACE_NAME)

        self.assertFalse(result)
        query = {'ipspace.name': fake.IPSPACE_NAME}
        self.client.send_request.assert_called_once_with(
            '/svm/svms', 'get', query=query)
        self.client._has_records.assert_called_once_with('fake_response')

    def test_ipspace_has_data_vservers_not_found(self):
        api_response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.ipspace_has_data_vservers(fake.IPSPACE_NAME)

        self.assertFalse(result)

    def test_delete_vlan(self):
        self.mock_object(self.client, 'send_request')

        query = {
            'vlan.base_port.name': fake.PORT,
            'node.name': fake.NODE_NAME,
            'vlan.tag': fake.VLAN
        }

        self.client.delete_vlan(fake.NODE_NAME, fake.PORT, fake.VLAN)

        self.client.send_request.assert_has_calls([
            mock.call('/network/ethernet/ports/', 'delete', query=query)])

    def test_delete_vlan_not_found(self):
        self.mock_object(
            self.client, 'send_request',
            self._mock_api_error(code=netapp_api.EREST_ENTRY_NOT_FOUND))

        query = {
            'vlan.base_port.name': fake.PORT,
            'node.name': fake.NODE_NAME,
            'vlan.tag': fake.VLAN
        }

        self.client.delete_vlan(fake.NODE_NAME, fake.PORT, fake.VLAN)

        self.client.send_request.assert_has_calls([
            mock.call('/network/ethernet/ports/', 'delete', query=query)])
        self.assertEqual(1, client_cmode_rest.LOG.debug.call_count)

    def test_delete_vlan_still_used(self):
        self.mock_object(
            self.client, 'send_request',
            self._mock_api_error(code=netapp_api.EREST_PORT_IN_USE))

        query = {
            'vlan.base_port.name': fake.PORT,
            'node.name': fake.NODE_NAME,
            'vlan.tag': fake.VLAN
        }

        self.client.delete_vlan(fake.NODE_NAME, fake.PORT, fake.VLAN)

        self.client.send_request.assert_has_calls([
            mock.call('/network/ethernet/ports/', 'delete', query=query)])
        self.assertEqual(1, client_cmode_rest.LOG.debug.call_count)

    def test_delete_vlan_api_error(self):
        self.mock_object(self.client, 'send_request', self._mock_api_error())
        self.assertRaises(exception.NetAppException,
                          self.client.delete_vlan,
                          fake.NODE_NAME,
                          fake.PORT,
                          fake.VLAN)

    @ddt.data(None, fake.IPSPACE_NAME)
    def test_svm_migration_start(self, dest_ipspace):
        check_only = True
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value='fake_migration'))

        res = self.client.svm_migration_start(
            fake.CLUSTER_NAME, fake.VSERVER_NAME, fake.SHARE_AGGREGATE_NAMES,
            dest_ipspace=dest_ipspace, check_only=check_only)

        self.assertEqual('fake_migration', res)
        expected_body = {
            "auto_cutover": False,
            "auto_source_cleanup": True,
            "check_only": True,
            "source": {
                "cluster": {"name": fake.CLUSTER_NAME},
                "svm": {"name": fake.VSERVER_NAME},
            },
            "destination": {
                "volume_placement": {
                    "aggregates": fake.SHARE_AGGREGATE_NAMES,
                },
            },
        }
        if dest_ipspace is not None:
            ipspace_data = {
                "ipspace": {
                    "name": dest_ipspace,
                }
            }
            expected_body["destination"].update(ipspace_data)
        self.client.send_request.assert_called_once_with(
            '/svm/migrations', 'post', body=expected_body,
            wait_on_accepted=False)

    def test_get_migration_check_job_state(self):
        self.mock_object(self.client, 'get_job',
                         mock.Mock(return_value='fake_job'))

        res = self.client.get_migration_check_job_state(fake.JOB_ID)

        self.assertEqual('fake_job', res)
        self.client.get_job.assert_called_once_with(fake.JOB_ID)

    @ddt.data(netapp_api.api.ENFS_V4_0_ENABLED_MIGRATION_FAILURE,
              netapp_api.api.EVSERVER_MIGRATION_TO_NON_AFF_CLUSTER, 'none')
    def test_get_migration_check_job_state_raise_error(self, error_code):
        e = netapp_api.api.NaApiError(code=error_code)
        self.mock_object(self.client, 'get_job', mock.Mock(side_effect=e))

        self.assertRaises(
            exception.NetAppException,
            self.client.get_migration_check_job_state,
            fake.JOB_ID)

    def test_svm_migrate_complete(self):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value='fake_migration'))

        res = self.client.svm_migrate_complete(fake.FAKE_MIGRATION_POST_ID)

        self.assertEqual('fake_migration', res)
        expected_body = {
            "action": "cutover"
        }
        self.client.send_request.assert_called_once_with(
            f'/svm/migrations/{fake.FAKE_MIGRATION_POST_ID}', 'patch',
            body=expected_body, wait_on_accepted=False)

    def test_svm_migrate_cancel(self):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value='fake_migration'))

        res = self.client.svm_migrate_cancel(fake.FAKE_MIGRATION_POST_ID)

        self.assertEqual('fake_migration', res)
        self.client.send_request.assert_called_once_with(
            f'/svm/migrations/{fake.FAKE_MIGRATION_POST_ID}', 'delete',
            wait_on_accepted=False)

    def test_svm_migration_get(self):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value='fake_migration'))

        res = self.client.svm_migration_get(fake.FAKE_MIGRATION_POST_ID)

        self.assertEqual('fake_migration', res)
        self.client.send_request.assert_called_once_with(
            f'/svm/migrations/{fake.FAKE_MIGRATION_POST_ID}', 'get')

    def test_svm_migrate_pause(self):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value='fake_migration'))

        res = self.client.svm_migrate_pause(fake.FAKE_MIGRATION_POST_ID)

        self.assertEqual('fake_migration', res)
        expected_body = {
            "action": "pause"
        }
        self.client.send_request.assert_called_once_with(
            f'/svm/migrations/{fake.FAKE_MIGRATION_POST_ID}', 'patch',
            body=expected_body, wait_on_accepted=False)

    def test_delete_network_interface(self):
        self.mock_object(self.client, 'disable_network_interface')
        self.mock_object(self.client, 'send_request')

        self.client.delete_network_interface(fake.VSERVER_NAME, fake.LIF_NAME)

        self.client.disable_network_interface.assert_called_once_with(
            fake.VSERVER_NAME, fake.LIF_NAME)
        expected_query = {
            'svm.name': fake.VSERVER_NAME,
            'name': fake.LIF_NAME
        }
        self.client.send_request.assert_called_once_with(
            '/network/ip/interfaces', 'delete', query=expected_query)

    def test_disable_network_interface(self):
        self.mock_object(self.client, 'send_request')

        self.client.disable_network_interface(fake.VSERVER_NAME, fake.LIF_NAME)

        expected_body = {
            'enabled': 'false'
        }
        expected_query = {
            'svm.name': fake.VSERVER_NAME,
            'name': fake.LIF_NAME
        }
        self.client.send_request.assert_called_once_with(
            '/network/ip/interfaces', 'patch', body=expected_body,
            query=expected_query)

    def test__delete_port_and_broadcast_domain(self):

        domain = copy.deepcopy(fake.BROADCAST_DOMAIN)
        ipspace = copy.deepcopy(fake.GET_IPSPACES_RESPONSE)

        query = {'name': domain, 'ipspace.name': ipspace['ipspace']}

        response_broadcast = copy.deepcopy(
            fake.BROADCAST_DOMAIN_LIST_SIMPLE_RESPONSE_REST)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(side_effect=[response_broadcast, None]))

        self.mock_object(self.client,
                         '_delete_port_by_ipspace_and_broadcast_domain')

        self.client._delete_port_and_broadcast_domain(domain, ipspace)
        self.client.send_request.assert_has_calls([
            mock.call('/network/ethernet/broadcast-domains',
                      'delete', query=query)])

    def test_delete_ipspace(self):
        ipspace = copy.deepcopy(fake.IPSPACES[0])
        mock_del_brcst = self.mock_object(
            self.client, '_delete_port_and_broadcast_domains_for_ipspace')

        mock_send_request = self.mock_object(
            self.client, 'send_request')

        query = {'name': fake.IPSPACE_NAME}

        self.client.delete_ipspace(ipspace['ipspace'])

        mock_del_brcst.assert_called_once_with(fake.IPSPACE_NAME)

        mock_send_request.assert_called_once_with(
            '/network/ipspaces', 'delete', query=query)

    def test_get_ipspaces(self):
        expected = copy.deepcopy(fake.GET_IPSPACES_RESPONSE)
        sr_responses = [fake.IPSPACE_INFO,
                        fake.REST_SINGLE_PORT,
                        fake.SVMS_LIST_SIMPLE_RESPONSE_REST,
                        fake.FAKE_GET_BROADCAST_DOMAIN]
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=sr_responses))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))
        result = self.client.get_ipspaces(fake.IPSPACE_NAME)
        self.assertEqual(expected, result)

    def test_get_ipspaces_no_records(self):
        api_response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))
        result = self.client.get_ipspaces(fake.IPSPACE_NAME)
        self.assertEqual([], result)

    def test_delete_port_and_broadcast_domains_for_ipspace_not_found(self):

        self.mock_object(self.client,
                         'get_ipspaces',
                         mock.Mock(return_value=[]))
        self.mock_object(self.client, '_delete_port_and_broadcast_domain')

        self.client._delete_port_and_broadcast_domains_for_ipspace(
            fake.IPSPACE_NAME)

        self.client.get_ipspaces.assert_called_once_with(
            fake.IPSPACE_NAME)
        self.assertFalse(self.client._delete_port_and_broadcast_domain.called)

    def test_delete_port_and_broadcast_domains_for_ipspace(self):

        self.mock_object(self.client,
                         'get_ipspaces',
                         mock.Mock(return_value=fake.IPSPACES[0]))
        self.mock_object(self.client, '_delete_port_and_broadcast_domain')

        self.client._delete_port_and_broadcast_domains_for_ipspace(
            fake.IPSPACE_NAME)

        self.client.get_ipspaces.assert_called_once_with(
            fake.IPSPACE_NAME)
        self.client._delete_port_and_broadcast_domain.assert_called_once_with(
            fake.IPSPACES[0]['broadcast-domains'][0], fake.IPSPACES[0])

    @ddt.data(('10.10.10.0/24', '10.10.10.1', False),
              ('fc00::/7', 'fe80::1', False),
              ('0.0.0.0/0', '10.10.10.1', True),
              ('::/0', 'fe80::1', True))
    @ddt.unpack
    def test_create_route(self, subnet, gateway, omit_destination):

        address = None
        netmask = None
        destination = None if omit_destination else subnet
        if not destination:
            if ':' in gateway:
                destination = '::/0'
            else:
                destination = '0.0.0.0/0'

        if '/' in destination:
            address, netmask = destination.split('/')
        else:
            address = destination

        body = {
            'destination.address': address,
            'gateway': gateway,
        }

        if netmask:
            body['destination.netmask'] = netmask

        self.mock_object(self.client, 'send_request')

        self.client.create_route(gateway, destination=destination)

        self.client.send_request.assert_called_once_with(
            '/network/ip/routes', 'post', body=body)

    def test_create_route_duplicate(self):
        self.mock_object(client_cmode_rest.LOG, 'debug')
        self.mock_object(
            self.client, 'send_request',
            self._mock_api_error(code=netapp_api.EREST_DUPLICATE_ROUTE))

        self.client.create_route(fake.GATEWAY, destination=fake.SUBNET)

        body = {
            'destination.address': fake.SUBNET[:-3],
            'gateway': fake.GATEWAY,
            'destination.netmask': fake.SUBNET[-2:],
        }
        self.client.send_request.assert_called_once_with(
            '/network/ip/routes', 'post', body=body)
        self.assertEqual(1, client_cmode_rest.LOG.debug.call_count)

    def test_create_route_api_error(self):
        self.mock_object(client_cmode_rest.LOG, 'debug')
        self.mock_object(self.client, 'send_request', self._mock_api_error())

        body = {
            'destination.address': fake.SUBNET[:-3],
            'gateway': fake.GATEWAY,
            'destination.netmask': fake.SUBNET[-2:],
        }
        self.assertRaises(exception.NetAppException,
                          self.client.create_route,
                          fake.GATEWAY, destination=fake.SUBNET)
        self.client.send_request.assert_called_once_with(
            '/network/ip/routes', 'post', body=body)

    def test_create_route_without_gateway(self):
        self.mock_object(self.client, 'send_request')
        self.client.create_route(None, destination=fake.SUBNET)
        self.assertFalse(self.client.send_request.called)

    def test_network_interface_exists(self):
        api_response = fake.GENERIC_NETWORK_INTERFACES_GET_REPONSE
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))
        result = self.client.network_interface_exists(
            fake.VSERVER_NAME, fake.NODE_NAME, fake.PORT, fake.IP_ADDRESS,
            fake.NETMASK, fake.VLAN)
        query = {
            'ip.address': fake.IP_ADDRESS,
            'location.home_node.name': fake.NODE_NAME,
            'location.home_port.name': f'{fake.PORT}-{fake.VLAN}',
            'ip.netmask': fake.NETMASK,
            'svm.name': fake.VSERVER_NAME,
            'fields': 'name',
        }
        self.client.send_request.assert_called_once_with(
            '/network/ip/interfaces', 'get', query=query)
        self.assertTrue(result)

    def test_modify_active_directory_security_service(self):
        svm_uuid = fake.FAKE_UUID
        user_records = fake.FAKE_CIFS_LOCAL_USER.get('records')[0]
        sid = user_records.get('sid')
        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value=svm_uuid))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=[user_records,
                                                None, None]))
        self.mock_object(self.client, 'remove_preferred_dcs')
        self.mock_object(self.client, 'set_preferred_dc')
        new_security_service = {
            'user': 'new_user',
            'password': 'new_password',
            'server': 'fake_server'
        }

        current_security_service = {
            'server': 'fake_current_server'
        }
        keys = {'user', 'password', 'server'}

        self.client.modify_active_directory_security_service(
            fake.VSERVER_NAME, keys, new_security_service,
            current_security_service)

        self.client.send_request.assert_has_calls([
            mock.call(f'/protocols/cifs/local-users/{svm_uuid}', 'get'),
            mock.call(f'/protocols/cifs/local-users/{svm_uuid}/{sid}', 'patch',
                      query={'password': new_security_service['password']}),
            mock.call(f'/protocols/cifs/local-users/{svm_uuid}/{sid}', 'patch',
                      query={'name': new_security_service['user']})
        ])

    def test__create_vserver(self):
        mock_sr = self.mock_object(self.client, 'send_request')
        body = {
            'name': fake.VSERVER_NAME,
            'nsswitch.namemap': fake.FAKE_SERVER_SWITCH_NAME,
            'subtype': fake.FAKE_SUBTYPE,
            'ipspace.name': fake.IPSPACE_NAME,
            'aggregates': [{
                'name': fake.SHARE_AGGREGATE_NAME
            }]
        }

        self.client._create_vserver(fake.VSERVER_NAME,
                                    [fake.SHARE_AGGREGATE_NAME],
                                    fake.IPSPACE_NAME,
                                    fake.FAKE_SERVER_SWITCH_NAME,
                                    fake.FAKE_SUBTYPE)

        mock_sr.assert_called_once_with('/svm/svms', 'post', body=body)

    @ddt.data((f'/name-services/dns/{fake.FAKE_UUID}', 'patch',
               ['fake_domain'], ['fake_ip']),
              (f'/name-services/dns/{fake.FAKE_UUID}', 'delete', [], []),
              ('/name-services/dns', 'post', ['fake_domain'], ['fake_ip']))
    @ddt.unpack
    def test_update_dns_configuration_all_operations(self, endpoint,
                                                     operation, domains, ips):
        return_value = fake.FAKE_DNS_CONFIG if operation != 'post' else {}
        self.mock_object(self.client, 'get_dns_config',
                         mock.Mock(return_value=return_value))
        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake.FAKE_UUID))
        mock_sr = self.mock_object(self.client, 'send_request')
        body = {
            'domains': domains,
            'servers': ips
        }
        empty_dns_config = (not body['domains'] and not body['servers'])
        if empty_dns_config:
            body = {}
        self.client.update_dns_configuration(ips, domains)
        mock_sr.assert_called_once_with(endpoint, operation, body)

    @ddt.data(True, False)
    def test_delete_snapshot(self, ignore_owners):
        volume_id = fake.VOLUME.get('uuid')
        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=fake.VOLUME))
        response = fake.SNAPSHOTS_REST_RESPONSE
        snapshot_id = response.get('records')[0].get('uuid')
        mock_sr = self.mock_object(self.client, 'send_request',
                                   mock.Mock(return_value=response))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))
        query = {
            'name': fake.SNAPSHOT_NAME,
            'fields': 'uuid'
        }
        calls = [mock.call(f'/storage/volumes/{volume_id}/snapshots', 'get',
                           query=query)]
        if ignore_owners:
            query_cli = {
                'vserver': self.client.vserver,
                'volume': fake.VOLUME_NAMES[0],
                'snapshot': fake.SNAPSHOT_NAME,
                'ignore-owners': 'true'
            }
            calls.append(mock.call('/private/cli/snapshot', 'delete',
                                   query=query_cli))
        else:
            calls.append(mock.call(f'/storage/volumes/{volume_id}/'
                                   f'snapshots/{snapshot_id}', 'delete'))

        self.client.delete_snapshot(fake.VOLUME_NAMES[0], fake.SNAPSHOT_NAME,
                                    ignore_owners)
        mock_sr.assert_has_calls(calls)

    def test_volume_has_luns(self):
        mock_sr = self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))
        result = self.client.volume_has_luns(fake.VOLUME_NAMES[0])
        query = {
            'location.volume.name': fake.VOLUME_NAMES[0],
        }
        mock_sr.assert_called_once_with('/storage/luns/', 'get', query=query)
        self.assertTrue(result)

    @ddt.data(fake.VOLUME_JUNCTION_PATH, '')
    def test_volume_has_junctioned_volumes(self, junction_path):
        mock_sr = self.mock_object(self.client, 'send_request')
        return_records = True if junction_path else False
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=return_records))
        result = self.client.volume_has_junctioned_volumes(junction_path)
        if junction_path:
            query = {
                'nas.path': junction_path + '/*',
            }

            mock_sr.assert_called_once_with('/storage/volumes/', 'get',
                                            query=query)
            self.assertTrue(result)
        else:
            self.assertFalse(result)

    @ddt.data(fake.VOLUME_JUNCTION_PATH, '')
    def test_get_volume_at_junction_path(self, junction_path):
        response = fake.VOLUME_LIST_SIMPLE_RESPONSE_REST
        return_records = True if junction_path else False
        mock_sr = self.mock_object(self.client, 'send_request',
                                   mock.Mock(return_value=response))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=return_records))
        query = {
            'nas.path': junction_path,
            'fields': 'name'
        }

        result = self.client.get_volume_at_junction_path(junction_path)
        expected = {
            'name': response.get('records')[0].get('name')
        }

        if junction_path:
            mock_sr.assert_called_once_with('/storage/volumes/', 'get',
                                            query=query)
            self.assertEqual(expected, result)
        else:
            self.assertIsNone(result)

    def test_get_aggregate_for_volume(self):
        response = fake.FAKE_SVM_AGGREGATES.get('records')[0]
        mock_sr = self.mock_object(self.client, 'send_request',
                                   mock.Mock(return_value=response))
        result = self.client.get_aggregate_for_volume(fake.VOLUME_NAMES[0])
        expected = fake.SHARE_AGGREGATE_NAMES_LIST
        query = {
            'name': fake.VOLUME_NAMES[0],
            'fields': 'aggregates'
        }
        mock_sr.assert_called_once_with('/storage/volumes/', 'get',
                                        query=query)
        self.assertEqual(expected, result)

    def test_get_volume_to_manage(self):
        response = fake.FAKE_VOLUME_MANAGE
        mock_sr = self.mock_object(self.client, 'send_request',
                                   mock.Mock(return_value=response))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))
        expected = {
            'aggregate': fake.SHARE_AGGREGATE_NAME,
            'aggr-list': [],
            'junction-path': fake.VOLUME_JUNCTION_PATH,
            'name': fake.VOLUME_NAMES[0],
            'type': 'fake_type',
            'style': 'flex',
            'owning-vserver-name': fake.VSERVER_NAME,
            'size': fake.SHARE_SIZE,
            'qos-policy-group-name': fake.QOS_POLICY_GROUP_NAME
        }

        result = self.client.get_volume_to_manage(fake.SHARE_AGGREGATE_NAME,
                                                  fake.VOLUME_NAMES[0])
        query = {
            'name': fake.VOLUME_NAMES[0],
            'fields': 'name,aggregates.name,nas.path,name,type,style,'
                      'svm.name,qos.policy.name,space.size',
            'aggregates.name': fake.SHARE_AGGREGATE_NAME
        }
        mock_sr.assert_called_once_with('/storage/volumes', 'get',
                                        query=query)
        self.assertEqual(expected, result)

    def test_get_cifs_share_access(self):
        response = fake.FAKE_CIFS_RECORDS
        mock_sr = self.mock_object(self.client, 'send_request',
                                   mock.Mock(return_value=response))
        query = {
            'name': fake.SHARE_NAME
        }
        query_acls = {
            'fields': 'user_or_group,permission'
        }
        expected = {
            'Everyone': 'full_control',
            'root': 'no_access'
        }
        result = self.client.get_cifs_share_access(fake.SHARE_NAME)
        svm_uuid = response.get('records')[0].get('svm').get('uuid')
        mock_sr.assert_has_calls([
            mock.call('/protocols/cifs/shares', 'get', query=query),
            mock.call(f'/protocols/cifs/shares/{svm_uuid}/{fake.SHARE_NAME}/'
                      'acls', 'get', query=query_acls)
        ])
        self.assertEqual(expected, result)

    @ddt.data((netapp_api.EREST_LICENSE_NOT_INSTALLED, False),
              (netapp_api.EREST_SNAPSHOT_NOT_SPECIFIED, True))
    @ddt.unpack
    def test_check_snaprestore_license(self, code, expected):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error(code)))
        result = self.client.check_snaprestore_license()
        self.assertEqual(expected, result)
        body = {
            'restore_to.snapshot.name': ''
        }
        query = {
            'name': '*'
        }
        self.client.send_request.assert_called_once_with('/storage/volumes',
                                                         'patch',
                                                         body=body,
                                                         query=query)

    def test_check_snaprestore_license_error(self):
        self.mock_object(self.client, 'send_request')
        self.assertRaises(exception.NetAppException,
                          self.client.check_snaprestore_license)

    def test__sort_data_ports_by_speed(self):
        ports = fake.FAKE_PORTS
        result = self.client._sort_data_ports_by_speed(ports)
        expected = [{'speed': '4'},
                    {'speed': 'auto'},
                    {'speed': 'undef'},
                    {'speed': 'fake_speed'},
                    {'speed': ''}]
        self.assertEqual(expected, result)

    def test_create_port_and_broadcast_domain(self):
        self.mock_object(self.client, '_create_vlan')
        self.mock_object(self.client, '_ensure_broadcast_domain_for_port')
        res = self.client.create_port_and_broadcast_domain(fake.NODE_NAME,
                                                           fake.PORT,
                                                           fake.VLAN,
                                                           fake.MTU,
                                                           fake.IPSPACE_NAME)
        expected = f'{fake.PORT}-{fake.VLAN}'
        self.assertEqual(expected, res)

    @ddt.data(netapp_api.EREST_DUPLICATE_ENTRY, None)
    def test__create_vlan(self, code):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error(code)))
        if not(code):
            self.assertRaises(exception.NetAppException,
                              self.client._create_vlan,
                              fake.NODE_NAME,
                              fake.PORT,
                              fake.VLAN)

        else:
            self.client._create_vlan(fake.NODE_NAME, fake.PORT, fake.VLAN)
            body = {
                'vlan.base_port.name': fake.PORT,
                'node.name': fake.NODE_NAME,
                'vlan.tag': fake.VLAN,
                'type': 'vlan'
            }
            self.client.send_request.assert_called_once_with(
                '/network/ethernet/ports', 'post', body=body)

    @ddt.data(netapp_api.EREST_ENTRY_NOT_FOUND, None)
    def test_delete_fpolicy_event_error_not_found(self, code):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error(code)))
        if not(code):
            self.assertRaises(exception.NetAppException,
                              self.client.delete_fpolicy_event,
                              fake.SHARE_NAME, 'fake_event')
        else:
            self.client.delete_fpolicy_event(fake.SHARE_NAME, 'fake_event')
            self.assertEqual(1, client_cmode_rest.LOG.debug.call_count)

    @ddt.data(netapp_api.EREST_ENTRY_NOT_FOUND, None)
    def test_delete_fpolicy_policy_request_error(self, code):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error(code)))
        if not(code):
            self.assertRaises(exception.NetAppException,
                              self.client.delete_fpolicy_policy,
                              fake.SHARE_NAME, 'fake_policy')
        else:
            self.client.delete_fpolicy_policy(fake.SHARE_NAME, 'fake_policy')
            self.assertEqual(1, client_cmode_rest.LOG.debug.call_count)

    def test_modify_fpolicy_scope(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        svm_uuid = volume['svm']['uuid']
        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        mock_sr = self.mock_object(self.client, 'send_request')
        body = {
            'name': fake.FPOLICY_POLICY_NAME,
            'scope.include_shares': fake.SHARE_NAME,
            'scope.include_extension': 'fake_extension',
            'scope.exclude_extension': 'fake_extension'
        }
        self.client.modify_fpolicy_scope(fake.SHARE_NAME,
                                         fake.FPOLICY_POLICY_NAME,
                                         [fake.SHARE_NAME],
                                         ['fake_extension'],
                                         ['fake_extension'])
        mock_sr.assert_called_once_with(f'/protocols/fpolicy/{svm_uuid}/'
                                        'policies/', 'patch', body=body)

    def test_remove_cifs_share(self):
        response = fake.SVMS_LIST_SIMPLE_RESPONSE_REST
        svm_id = response.get('records')[0]['uuid']
        mock_sr = self.mock_object(self.client, 'send_request',
                                   mock.Mock(return_value=response))
        self.client.remove_cifs_share(fake.SHARE_NAME)
        query = {
            'name': self.client.vserver,
            'fields': 'uuid'
        }
        mock_sr.assert_has_calls([
            mock.call('/svm/svms', 'get', query=query),
            mock.call(f'/protocols/cifs/shares/{svm_id}'
                      f'/{fake.SHARE_NAME}', 'delete')])

    def test_qos_policy_group_get_error(self):
        code = netapp_api.EREST_NOT_AUTHORIZED
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error(code)))
        self.assertRaises(exception.NetAppException,
                          self.client.qos_policy_group_get,
                          fake.QOS_POLICY_GROUP_NAME)

    def test_qos_policy_group_get_not_found(self):
        response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))
        self.assertRaises(exception.NetAppException,
                          self.client.qos_policy_group_get,
                          fake.QOS_POLICY_GROUP_NAME)

    def test_remove_unused_qos_policy_groups_error(self):
        res_list = [fake.QOS_POLICY_GROUP_REST, netapp_api.api.NaApiError]
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=res_list))
        self.client.remove_unused_qos_policy_groups()
        self.assertEqual(1, client_cmode_rest.LOG.debug.call_count)

    def test_mount_volume_error(self):
        volume = fake.VOLUME_ITEM_SIMPLE_RESPONSE_REST
        code = netapp_api.EREST_SNAPMIRROR_INITIALIZING
        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(return_value=volume))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error(code)))
        self.assertRaises(netapp_api.api.NaApiError,
                          self.client.mount_volume,
                          fake.VOLUME_NAMES[0])

    def test_get_aggregate_for_volume_empty(self):
        response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))
        self.assertRaises(exception.NetAppException,
                          self.client.get_aggregate_for_volume,
                          fake.VOLUME_NAMES[0])

    def test_get_nfs_export_policy_for_volume_empty(self):
        response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=False))
        self.assertRaises(exception.NetAppException,
                          self.client.get_nfs_export_policy_for_volume,
                          fake.VOLUME_NAMES[0])

    def test_get_unique_export_policy_id_empty(self):
        response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=False))
        self.assertRaises(exception.NetAppException,
                          self.client.get_unique_export_policy_id,
                          fake.FPOLICY_POLICY_NAME)

    def test__remove_nfs_export_rules_error(self):
        self.mock_object(self.client, 'get_unique_export_policy_id',
                         mock.Mock(return_value=fake.FAKE_UUID))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error()))
        self.assertRaises(netapp_api.api.NaApiError,
                          self.client._remove_nfs_export_rules,
                          fake.FPOLICY_POLICY_NAME,
                          [1])

    def test_get_volume_move_status_error(self):
        response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=False))
        self.assertRaises(exception.NetAppException,
                          self.client.get_volume_move_status,
                          fake.VOLUME_NAMES[0],
                          fake.VSERVER_NAME)

    def test__set_snapmirror_state_error(self):
        self.mock_object(self.client, 'get_snapmirrors',
                         mock.Mock(return_value=[]))
        self.assertRaises(netapp_utils.NetAppDriverException,
                          self.client._set_snapmirror_state,
                          'fake_state', 'fake_source_path', 'fake_dest_path',
                          'fake_source_vserver', 'fake_source_volume',
                          'fake_dest_vserver', 'fake_dest_volume')

    def test__break_snapmirror_error(self):
        fake_snapmirror = fake.REST_GET_SNAPMIRRORS_RESPONSE
        self.mock_object(self.client, '_get_snapmirrors',
                         mock.Mock(return_value=fake_snapmirror))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error()))
        self.assertRaises(netapp_api.api.NaApiError,
                          self.client._break_snapmirror)

    def test__resync_snapmirror_no_parameter(self):
        mock_snap = self.mock_object(self.client, '_resume_snapmirror')
        self.client._resync_snapmirror()
        mock_snap.assert_called_once_with(None, None, None, None, None, None)

    def test_add_nfs_export_rule_with_rule_created(self):
        self.mock_object(self.client, '_get_nfs_export_rule_indices',
                         mock.Mock(return_value=[1]))
        update = self.mock_object(self.client, '_update_nfs_export_rule')
        remove = self.mock_object(self.client, '_remove_nfs_export_rules')
        self.client.add_nfs_export_rule(fake.FPOLICY_POLICY_NAME,
                                        'fake_client',
                                        True,
                                        'fake_auth')
        update.assert_called_once_with(fake.FPOLICY_POLICY_NAME,
                                       'fake_client', True, 1, 'fake_auth')
        remove.assert_called_once_with(fake.FPOLICY_POLICY_NAME, [])

    def test__update_snapmirror_no_snapmirrors(self):
        self.mock_object(self.client, '_get_snapmirrors',
                         mock.Mock(return_value=[]))
        self.assertRaises(netapp_utils.NetAppDriverException,
                          self.client._update_snapmirror)

    @ddt.data((netapp_api.EREST_SNAPMIRROR_NOT_INITIALIZED,
               'Another transfer is in progress'),
              (None, 'fake'))
    @ddt.unpack
    def test__update_snapmirror_error(self, code, message):
        snapmirrors = fake.REST_GET_SNAPMIRRORS_RESPONSE
        self.mock_object(self.client, '_get_snapmirrors',
                         mock.Mock(return_value=snapmirrors))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error(code,
                                                                    message)))
        self.assertRaises(netapp_api.api.NaApiError,
                          self.client._update_snapmirror)

    @ddt.data(netapp_api.EREST_DUPLICATE_ENTRY, None)
    def test_create_kerberos_realm_error(self, code):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error(code)))
        if code:
            self.client.create_kerberos_realm(fake.KERBEROS_SECURITY_SERVICE)
            self.assertEqual(1, client_cmode_rest.LOG.debug.call_count)
        else:
            self.assertRaises(exception.NetAppException,
                              self.client.create_kerberos_realm,
                              fake.KERBEROS_SECURITY_SERVICE)

    def test_configure_kerberos_error(self):
        self.mock_object(self.client, 'configure_dns')
        self.mock_object(self.client, '_get_kerberos_service_principal_name')
        self.mock_object(self.client, 'get_network_interfaces',
                         mock.Mock(return_value=[]))
        self.assertRaises(exception.NetAppException,
                          self.client.configure_kerberos,
                          fake.KERBEROS_SECURITY_SERVICE,
                          fake.VSERVER_NAME)

    def test_configure_ldap(self):
        mock_ldap = self.mock_object(self.client, '_create_ldap_client')
        self.client.configure_ldap(fake.LDAP_AD_SECURITY_SERVICE, 30,
                                   fake.VSERVER_NAME)
        mock_ldap.assert_called_once_with(fake.LDAP_AD_SECURITY_SERVICE,
                                          vserver_name=fake.VSERVER_NAME)

    def test_configure_active_directory_error(self):
        self.mock_object(self.client, 'configure_dns')
        self.mock_object(self.client, 'set_preferred_dc')
        self.mock_object(self.client, '_get_cifs_server_name')
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error()))
        self.assertRaises(exception.NetAppException,
                          self.client.configure_active_directory,
                          fake.LDAP_AD_SECURITY_SERVICE,
                          fake.VSERVER_NAME)

    def test__get_unique_svm_by_name_error(self):
        response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))
        self.assertRaises(exception.NetAppException,
                          self.client._get_unique_svm_by_name,
                          fake.VSERVER_NAME)

    def test_get_ontap_version_scoped(self):
        self.client.get_ontap_version = self.original_get_ontap_version
        e = netapp_api.api.NaApiError(code=netapp_api.EREST_NOT_AUTHORIZED)
        res_list = [e, fake.GET_VERSION_RESPONSE_REST]
        version = fake.GET_VERSION_RESPONSE_REST['records'][0]['version']
        expected = {
            'version': version['full'],
            'version-tuple': (9, 11, 1)
        }
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=res_list))
        result = self.client.get_ontap_version(self=self.client, cached=False)
        self.assertEqual(expected, result)

    def test_get_licenses_error(self):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error()))
        self.assertRaises(netapp_api.api.NaApiError,
                          self.client.get_licenses)

    def test__get_volume_by_args_error(self):
        res = fake.VOLUME_GET_ITER_RESPONSE_REST_PAGE
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=res))
        self.assertRaises(exception.NetAppException,
                          self.client._get_volume_by_args,
                          is_root=True)

    def test_get_aggregate_no_name(self):
        expected = {}
        result = self.client.get_aggregate('')
        self.assertEqual(expected, result)

    def test_get_aggregate_error(self):
        self.mock_object(self.client, '_get_aggregates',
                         mock.Mock(side_effect=self._mock_api_error()))
        result = self.client.get_aggregate(fake.SHARE_AGGREGATE_NAME)
        expected = {}
        self.assertEqual(expected, result)

    def test_get_node_for_aggregate_no_name(self):
        result = self.client.get_node_for_aggregate('')
        self.assertIsNone(result)

    @ddt.data(netapp_api.EREST_NOT_AUTHORIZED, None)
    def test_get_node_for_aggregate_error(self, code):
        self.mock_object(self.client, '_get_aggregates',
                         mock.Mock(side_effect=self._mock_api_error(code)))
        if code:
            r = self.client.get_node_for_aggregate(fake.SHARE_AGGREGATE_NAME)
            self.assertIsNone(r)
        else:
            self.assertRaises(netapp_api.api.NaApiError,
                              self.client.get_node_for_aggregate,
                              fake.SHARE_AGGREGATE_NAME)

    def test_get_vserver_aggregate_capabilities_no_response(self):
        response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))
        self.assertRaises(exception.NetAppException,
                          self.client.get_vserver_aggregate_capacities,
                          fake.SHARE_AGGREGATE_NAME)

    def test_get_vserver_aggregate_capacities_no_aggregate(self):
        response = fake.FAKE_AGGREGATES_RESPONSE
        share_name = fake.SHARE_AGGREGATE_NAME
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=response))
        res = self.client.get_vserver_aggregate_capacities(share_name)
        expected = {}
        self.assertEqual(expected, res)

    def test_rename_nfs_export_policy_error(self):
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=False))
        self.assertRaises(exception.NetAppException,
                          self.client.rename_nfs_export_policy,
                          'fake_policy_name',
                          'fake_new_policy_name')

    @ddt.data((False, exception.StorageResourceNotFound),
              (True, exception.NetAppException))
    @ddt.unpack
    def test_get_volume_error(self, records, exception):
        res = copy.deepcopy(fake.FAKE_VOLUME_MANAGE)
        res['num_records'] = 2
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=res))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=records))
        self.assertRaises(exception,
                          self.client.get_volume,
                          fake.VOLUME_NAMES[0])

    def test_get_volume_no_aggregate(self):
        res = copy.deepcopy(fake.FAKE_VOLUME_MANAGE)
        res.get('records')[0]['aggregates'] = []
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=res))
        fake_volume = res.get('records', [])[0]

        expected = {
            'aggregate': '',
            'aggr-list': [],
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
        result = self.client.get_volume(fake.VOLUME_NAMES[0])
        self.assertEqual(expected, result)

    def test_get_job_state_error(self):
        response = {
            'records': [fake.JOB_SUCCESSFUL_REST,
                        fake.JOB_SUCCESSFUL_REST]
        }
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=True))
        self.assertRaises(exception.NetAppException,
                          self.client.get_job_state,
                          fake.JOB_ID)

    def test_get_volume_efficiency_status_error(self):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error()))
        self.client.get_volume_efficiency_status(fake.VOLUME_NAMES[0])
        self.assertEqual(1, client_cmode_rest.LOG.error.call_count)

    def test_get_fpolicy_scopes_not_found(self):
        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(side_effect=exception.NetAppException))
        result = self.client.get_fpolicy_scopes(fake.SHARE_NAME)
        expected = []
        self.assertEqual(expected, result)

    def test_delete_fpolicy_policy_error(self):
        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(side_effect=exception.NetAppException))
        self.mock_object(self.client, 'send_request')
        res = self.client.delete_fpolicy_policy(fake.SHARE_NAME,
                                                fake.FPOLICY_POLICY_NAME)
        self.assertEqual(1, client_cmode_rest.LOG.debug.call_count)
        self.assertIsNone(res)

    def test_delete_fpolicy_event_error(self):
        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(side_effect=exception.NetAppException))
        self.mock_object(self.client, 'send_request')
        res = self.client.delete_fpolicy_event(fake.SHARE_NAME,
                                               fake.FPOLICY_EVENT_NAME)
        self.assertEqual(1, client_cmode_rest.LOG.debug.call_count)
        self.assertIsNone(res)

    def test_delete_nfs_export_policy_no_records(self):
        response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))
        res = self.client.delete_nfs_export_policy(fake.FPOLICY_POLICY_NAME)
        self.assertIsNone(res)

    def test_remove_cifs_share_not_found(self):
        response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))
        self.assertRaises(exception.NetAppException,
                          self.client.remove_cifs_share,
                          fake.SHARE_NAME)

    @ddt.data(netapp_api.EREST_ENTRY_NOT_FOUND, None)
    def test_remove_cifs_share_error(self, code):
        responses = [fake.SVMS_LIST_SIMPLE_RESPONSE_REST,
                     netapp_api.api.NaApiError(code=code)]
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=responses))
        if not(code):
            self.assertRaises(netapp_api.api.NaApiError,
                              self.client.remove_cifs_share,
                              fake.SHARE_NAME)
        else:
            result = self.client.remove_cifs_share(fake.SHARE_NAME)
            self.assertIsNone(result)

    def test_qos_policy_group_does_not_exists(self):
        self.mock_object(self.client, 'qos_policy_group_get',
                         mock.Mock(side_effect=exception.NetAppException))
        result = self.client.qos_policy_group_exists(fake.QOS_POLICY_GROUP)
        self.assertFalse(result)

    def test_qos_policy_group_rename_error(self):
        response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))
        self.assertRaises(exception.NetAppException,
                          self.client.qos_policy_group_rename,
                          fake.QOS_POLICY_GROUP_NAME,
                          'fake_new_qos_policy_group_name')

    def test_qos_policy_group_rename_same_name(self):
        res = self.client.qos_policy_group_rename(fake.QOS_POLICY_GROUP_NAME,
                                                  fake.QOS_POLICY_GROUP_NAME)
        self.assertIsNone(res)

    def test_qos_policy_group_modify_error(self):
        response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))
        self.assertRaises(exception.NetAppException,
                          self.client.qos_policy_group_modify,
                          fake.QOS_POLICY_GROUP_NAME,
                          fake.QOS_MAX_THROUGHPUT)

    def test_update_kerberos_realm_error(self):
        self.mock_object(self.client,
                         '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake.FAKE_UUID))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error()))
        self.assertRaises(exception.NetAppException,
                          self.client.update_kerberos_realm,
                          fake.KERBEROS_SECURITY_SERVICE)

    @ddt.data(('fake_domain', 'fake_server'), (None, None))
    @ddt.unpack
    def test_modify_ldap_error(self, domain, server):
        security_service = {
            'domain': domain,
            'server': server,
            'user': 'fake_user',
            'ou': 'fake_ou',
            'dns_ip': 'fake_ip',
            'password': 'fake_password'
        }
        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake.FAKE_UUID))
        self.mock_object(self.client, 'send_request')
        self.assertRaises(exception.NetAppException,
                          self.client.modify_ldap,
                          security_service,
                          fake.LDAP_AD_SECURITY_SERVICE)

    def test_update_dns_configuration_error(self):
        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake.FAKE_UUID))
        dns_config = {
            'domains': [fake.KERBEROS_SECURITY_SERVICE['domain']],
            'dns-ips': [fake.KERBEROS_SECURITY_SERVICE['dns_ip']],
        }
        self.mock_object(self.client, 'get_dns_config',
                         mock.Mock(return_value=dns_config))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error()))
        self.assertRaises(exception.NetAppException,
                          self.client.update_dns_configuration,
                          ['fake_ips'], ['fake_domain'])

    def test_remove_preferred_dcs_error(self):
        fake_response = [fake.PREFERRED_DC_REST,
                         netapp_api.api.NaApiError]
        self.mock_object(self.client, 'send_request',
                                      mock.Mock(side_effect=fake_response))
        self.assertRaises(exception.NetAppException,
                          self.client.remove_preferred_dcs,
                          fake.LDAP_AD_SECURITY_SERVICE,
                          fake.FAKE_UUID)

    def test_set_preferred_dc_error(self):
        security = copy.deepcopy(fake.LDAP_AD_SECURITY_SERVICE)
        security['server'] = 'fake_server'
        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value=fake.FAKE_UUID))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=self._mock_api_error()))
        self.assertRaises(exception.NetAppException,
                          self.client.set_preferred_dc,
                          security,
                          fake.VSERVER_NAME)

    def test_set_preferred_dc_no_server(self):
        result = self.client.set_preferred_dc(fake.LDAP_AD_SECURITY_SERVICE,
                                              fake.VSERVER_NAME)
        self.assertIsNone(result)

    def test__get_svm_peer_uuid_error(self):
        response = fake.NO_RECORDS_RESPONSE_REST
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=response))
        self.assertRaises(exception.NetAppException,
                          self.client._get_svm_peer_uuid,
                          fake.VSERVER_NAME,
                          fake.VSERVER_PEER_NAME)

    def test_create_vserver_dp_destination(self):
        mock_vserver = self.mock_object(self.client, '_create_vserver')
        self.client.create_vserver_dp_destination(fake.VSERVER_NAME,
                                                  fake.FAKE_AGGR_LIST,
                                                  fake.IPSPACE_NAME)
        mock_vserver.assert_called_once_with(fake.VSERVER_NAME,
                                             fake.FAKE_AGGR_LIST,
                                             fake.IPSPACE_NAME,
                                             subtype='dp_destination')

    @ddt.data(':', '.')
    def test_create_route_no_destination(self, gateway):
        mock_sr = self.mock_object(self.client, 'send_request')
        body = {
            'gateway': gateway,
            'destination.address': '::' if ":" in gateway else '0.0.0.0',
            'destination.netmask': '0'
        }
        self.client.create_route(gateway)
        mock_sr.assert_called_once_with('/network/ip/routes', 'post',
                                        body=body)

    def test_list_root_aggregates(self):
        return_value = fake.FAKE_ROOT_AGGREGATES_RESPONSE
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=return_value))

        result = self.client.list_root_aggregates()

        expected = [fake.SHARE_AGGREGATE_NAME]
        self.assertEqual(expected, result)

    @ddt.data(("fake_server", "fake_domain"), (None, None))
    @ddt.unpack
    def test__create_ldap_client_error(self, server, domain):
        security_service = {
            'server': server,
            'domain': domain,
            'user': 'fake_user',
            'ou': 'fake_ou',
            'dns_ip': 'fake_ip',
            'password': 'fake_password'
        }

        self.assertRaises(exception.NetAppException,
                          self.client._create_ldap_client,
                          security_service)

    @ddt.data(["password"], ["user"])
    def test__modify_active_directory_security_service_error(self, keys):
        svm_uuid = fake.FAKE_UUID
        user_records = fake.FAKE_CIFS_LOCAL_USER.get('records')[0]
        self.mock_object(self.client, '_get_unique_svm_by_name',
                         mock.Mock(return_value=svm_uuid))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=[user_records,
                                                netapp_api.api.NaApiError]))
        self.mock_object(self.client, 'remove_preferred_dcs')
        self.mock_object(self.client, 'set_preferred_dc')
        new_security_service = {
            'user': 'new_user',
            'password': 'new_password',
            'server': 'fake_server'
        }

        current_security_service = {
            'server': 'fake_current_server'
        }

        self.assertRaises(
            exception.NetAppException,
            self.client.modify_active_directory_security_service,
            fake.VSERVER_NAME,
            keys,
            new_security_service,
            current_security_service)

    def test_disable_kerberos_error(self):
        fake_api_response = fake.NFS_LIFS_REST
        api_error = self._mock_api_error()
        self.mock_object(self.client, 'get_network_interfaces',
                         mock.Mock(return_value=fake_api_response))
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(side_effect=api_error))

        self.assertRaises(exception.NetAppException,
                          self.client.disable_kerberos,
                          fake.LDAP_AD_SECURITY_SERVICE)

    def test_set_volume_snapdir_access_exception(self):
        fake_hide_snapdir = 'fake-snapdir'

        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(side_effect=exception.NetAppException))
        self.assertRaises(exception.SnapshotResourceNotFound,
                          self.client.set_volume_snapdir_access,
                          fake.VOLUME_NAMES[0],
                          fake_hide_snapdir)

    def test__get_broadcast_domain_for_port_exception(self):
        fake_response_empty = {
            "records": [{}]
        }
        self.mock_object(self.client, 'send_request', mock.Mock(
            return_value=fake_response_empty))

        self.assertRaises(exception.NetAppException,
                          self.client._get_broadcast_domain_for_port,
                          fake.NODE_NAME,
                          fake.PORT)

    def test__configure_nfs_exception(self):
        fake_nfs = {
            'udp-max-xfer-size': 10000,
            'tcp-max-xfer-size': 10000,
        }
        self.assertRaises(exception.NetAppException,
                          self.client._configure_nfs,
                          fake_nfs,
                          fake.FAKE_UUID)

    def test_get_snapshot_exception(self):
        self.mock_object(self.client, '_get_volume_by_args',
                         mock.Mock(side_effect=exception.NetAppException))
        self.assertRaises(exception.SnapshotResourceNotFound,
                          self.client.get_snapshot,
                          fake.VOLUME_NAMES[0],
                          fake.SNAPSHOT_NAME)

    def test_delete_snapshot_exception(self):
        self.mock_object(self.client,
                         '_get_volume_by_args',
                         mock.Mock(side_effect=exception.NetAppException))
        self.client.delete_snapshot(fake.VOLUME_NAMES[0], fake.SNAPSHOT_NAME,
                                    True)

        self.assertEqual(1, client_cmode_rest.LOG.warning.call_count)

    def test_set_nfs_export_policy_for_volume_exception(self):
        return_code = netapp_api.EREST_CANNOT_MODITY_OFFLINE_VOLUME
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(side_effect=self._mock_api_error(
                                   code=return_code)))
        self.client.set_nfs_export_policy_for_volume(
            fake.VOLUME_NAMES[0], fake.EXPORT_POLICY_NAME)

        self.assertEqual(1, client_cmode_rest.LOG.debug.call_count)

    def test__break_snapmirror_exception(self):
        fake_snapmirror = copy.deepcopy(fake.REST_GET_SNAPMIRRORS_RESPONSE)
        fake_snapmirror[0]['transferring-state'] = 'error'

        self.mock_object(
            self.client, '_get_snapmirrors',
            mock.Mock(return_value=fake_snapmirror))

        self.assertRaises(netapp_utils.NetAppDriverException,
                          self.client._break_snapmirror)

    def test_get_svm_volumes_total_size(self):
        expected = 1

        fake_query = {
            'svm.name': fake.VSERVER_NAME,
            'fields': 'size'
        }

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=fake.FAKE_GET_VOLUME))

        result = self.client.get_svm_volumes_total_size(fake.VSERVER_NAME)

        self.client.send_request.assert_called_once_with(
            '/storage/volumes/', 'get', query=fake_query)

        self.assertEqual(expected, result)
