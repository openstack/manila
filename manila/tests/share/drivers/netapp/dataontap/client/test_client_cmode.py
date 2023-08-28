# Copyright (c) 2014 Alex Meade.  All rights reserved.
# Copyright (c) 2015 Clinton Knight.  All rights reserved.
# Copyright (c) 2015 Tom Barron.  All rights reserved.
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
import hashlib
import time
from unittest import mock

import ddt
from oslo_log import log

from manila import exception
from manila.share.drivers.netapp.dataontap.client import api as netapp_api
from manila.share.drivers.netapp.dataontap.client import client_base
from manila.share.drivers.netapp.dataontap.client import client_cmode
from manila.share.drivers.netapp import utils as na_utils
from manila import test
from manila.tests.share.drivers.netapp.dataontap.client import fakes as fake


@ddt.ddt
class NetAppClientCmodeTestCase(test.TestCase):

    def setUp(self):
        super(NetAppClientCmodeTestCase, self).setUp()

        # Mock loggers as themselves to allow logger arg validation
        mock_logger = log.getLogger('mock_logger')
        self.mock_object(client_cmode.LOG,
                         'error',
                         mock.Mock(side_effect=mock_logger.error))
        self.mock_object(client_cmode.LOG,
                         'warning',
                         mock.Mock(side_effect=mock_logger.warning))
        self.mock_object(client_cmode.LOG,
                         'debug',
                         mock.Mock(side_effect=mock_logger.debug))

        self.mock_object(client_base.NetAppBaseClient,
                         'get_ontapi_version',
                         mock.Mock(return_value=(1, 20)))

        self.mock_object(client_base.NetAppBaseClient,
                         'get_system_version',
                         mock.Mock(return_value={
                             'version-tuple': (8, 3, 0),
                             'version': fake.VERSION,
                         }))

        self.client = client_cmode.NetAppCmodeClient(**fake.CONNECTION_INFO)
        self.client.connection = mock.MagicMock()

        self.vserver_client = client_cmode.NetAppCmodeClient(
            **fake.CONNECTION_INFO)
        self.vserver_client.set_vserver(fake.VSERVER_NAME)
        self.vserver_client.connection = mock.MagicMock()

    def _mock_api_error(self, code='fake', message='fake'):
        return mock.Mock(side_effect=netapp_api.NaApiError(code=code,
                                                           message=message))

    def test_init_features_ontapi_1_21(self):

        self.mock_object(client_base.NetAppBaseClient,
                         'get_ontapi_version',
                         mock.Mock(return_value=(1, 21)))

        self.client._init_features()

        self.assertFalse(self.client.features.BROADCAST_DOMAINS)
        self.assertFalse(self.client.features.IPSPACES)
        self.assertFalse(self.client.features.SUBNETS)
        self.assertFalse(self.client.features.FLEXVOL_ENCRYPTION)

    @ddt.data((1, 30), (1, 40), (2, 0))
    def test_init_features_ontapi_1_30(self, ontapi_version):

        self.mock_object(client_base.NetAppBaseClient,
                         'get_ontapi_version',
                         mock.Mock(return_value=ontapi_version))

        self.client._init_features()

        self.assertTrue(self.client.features.BROADCAST_DOMAINS)
        self.assertTrue(self.client.features.IPSPACES)
        self.assertTrue(self.client.features.SUBNETS)

    @ddt.data((1, 110), (2, 0))
    def test_init_features_ontap_1_110(self, ontapi_version):

        self.mock_object(client_base.NetAppBaseClient,
                         'get_ontapi_version',
                         mock.Mock(return_value=ontapi_version))

        self.client._init_features()

        self.assertTrue(self.client.features.BROADCAST_DOMAINS)
        self.assertTrue(self.client.features.IPSPACES)
        self.assertTrue(self.client.features.SUBNETS)
        self.assertTrue(self.client.features.FLEXVOL_ENCRYPTION)

    @ddt.data(((9, 1, 0), fake.VERSION_NO_DARE), ((8, 3, 2), fake.VERSION))
    @ddt.unpack
    def test_is_nve_supported_unsupported_release_or_platform(self, gen, ver):

        system_version = {'version-tuple': gen, 'version': ver}
        self.mock_object(client_base.NetAppBaseClient,
                         'get_system_version',
                         mock.Mock(return_value=system_version))
        self.mock_object(self.client,
                         'get_security_key_manager_nve_support',
                         mock.Mock(return_value=True))
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
        self.mock_object(client_base.NetAppBaseClient,
                         'get_system_version',
                         mock.Mock(return_value=system_version))
        self.mock_object(self.client,
                         'get_security_key_manager_nve_support',
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
        self.mock_object(client_base.NetAppBaseClient,
                         'get_system_version',
                         mock.Mock(return_value=system_version))
        self.mock_object(self.client,
                         'get_security_key_manager_nve_support',
                         mock.Mock(return_value=False))
        self.mock_object(self.client,
                         'list_cluster_nodes',
                         mock.Mock(return_value=fake.NODE_NAMES))

        result = self.client.is_nve_supported()

        self.assertFalse(result)

    def test_get_security_key_manager_nve_support_enabled(self):
        api_response = netapp_api.NaElement(
            fake.SECUTITY_KEY_MANAGER_NVE_SUPPORT_RESPONSE_TRUE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_security_key_manager_nve_support(
            fake.NODE_NAME)

        self.assertTrue(result)
        api_args = {'node': fake.NODE_NAME}
        self.client.send_request.assert_has_calls([
            mock.call('security-key-manager-volume-encryption-supported',
                      api_args)])

    def test_get_security_key_manager_nve_support_disabled(self):
        api_response = netapp_api.NaElement(
            fake.SECUTITY_KEY_MANAGER_NVE_SUPPORT_RESPONSE_FALSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_security_key_manager_nve_support(
            fake.NODE_NAME)

        self.assertFalse(result)
        api_args = {'node': fake.NODE_NAME}
        self.client.send_request.assert_has_calls([
            mock.call('security-key-manager-volume-encryption-supported',
                      api_args)])

    def test_get_security_key_manager_nve_support_disabled_no_license(self):
        self.mock_object(self.client,
                         'send_request',
                         self._mock_api_error())

        result = self.client.get_security_key_manager_nve_support(
            fake.NODE_NAME)

        self.assertFalse(result)

        api_args = {'node': fake.NODE_NAME}
        self.client.send_request.assert_has_calls([
            mock.call('security-key-manager-volume-encryption-supported',
                      api_args)])

    @ddt.data((True, True, True), (False, None, False))
    @ddt.unpack
    def test_send_volume_move_request_success(self, validation_only,
                                              encrypt_dst, fv_encryption):
        self.mock_object(self.client, 'features',
                         mock.Mock(FLEXVOL_ENCRYPTION=fv_encryption))
        self.client._send_volume_move_request(fake.ROOT_VOLUME_NAME,
                                              fake.NODE_VSERVER_NAME,
                                              fake.SHARE_AGGREGATE_NAME,
                                              validation_only=validation_only,
                                              encrypt_destination=encrypt_dst)

    @ddt.data((True, True, False))
    @ddt.unpack
    def test_send_volume_move_request_failure(self, validation_only,
                                              encrypt_dst, fv_encrypt):
        self.mock_object(self.client, 'features',
                         mock.Mock(FLEXVOL_ENCRYPTION=fv_encrypt))
        self.assertRaises(exception.NetAppException,
                          self.client._send_volume_move_request,
                          fake.ROOT_VOLUME_NAME,
                          fake.NODE_VSERVER_NAME,
                          fake.SHARE_AGGREGATE_NAME,
                          validation_only=validation_only,
                          encrypt_destination=encrypt_dst)

    def test_invoke_vserver_api(self):

        self.client._invoke_vserver_api('fake-api', 'fake_vserver')

        self.client.connection.set_vserver.assert_has_calls(
            [mock.call('fake_vserver')])
        self.client.connection.invoke_successfully.assert_has_calls(
            [mock.call('fake-api', True)])

    def test_has_records(self):
        self.assertTrue(self.client._has_records(
            netapp_api.NaElement(fake.VSERVER_GET_ITER_RESPONSE)))

    def test_has_records_not_found(self):
        self.assertFalse(self.client._has_records(
            netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)))

    @ddt.data((fake.VSERVER_GET_ITER_RESPONSE, 1),
              (fake.NO_RECORDS_RESPONSE, 0))
    @ddt.unpack
    def test_get_record_count(self, response, expected):

        api_response = netapp_api.NaElement(response)

        result = self.client._get_record_count(api_response)

        self.assertEqual(expected, result)

    def test_get_records_count_invalid(self):

        api_response = netapp_api.NaElement(
            fake.INVALID_GET_ITER_RESPONSE_NO_RECORDS)

        self.assertRaises(exception.NetAppException,
                          self.client._get_record_count,
                          api_response)

    def test_send_iter_request(self):

        api_responses = [
            netapp_api.NaElement(fake.STORAGE_DISK_GET_ITER_RESPONSE_PAGE_1),
            netapp_api.NaElement(fake.STORAGE_DISK_GET_ITER_RESPONSE_PAGE_2),
            netapp_api.NaElement(fake.STORAGE_DISK_GET_ITER_RESPONSE_PAGE_3),
        ]
        mock_send_request = self.mock_object(
            self.client, 'send_request',
            mock.Mock(side_effect=api_responses))

        storage_disk_get_iter_args = {
            'desired-attributes': {
                'storage-disk-info': {
                    'disk-name': None,
                }
            }
        }
        result = self.client.send_iter_request(
            'storage-disk-get-iter', api_args=storage_disk_get_iter_args,
            max_page_length=10)

        num_records = result.get_child_content('num-records')
        self.assertEqual('28', num_records)
        next_tag = result.get_child_content('next-tag')
        self.assertEqual('', next_tag)

        args1 = copy.deepcopy(storage_disk_get_iter_args)
        args1['max-records'] = 10
        args2 = copy.deepcopy(storage_disk_get_iter_args)
        args2['max-records'] = 10
        args2['tag'] = 'next_tag_1'
        args3 = copy.deepcopy(storage_disk_get_iter_args)
        args3['max-records'] = 10
        args3['tag'] = 'next_tag_2'

        mock_send_request.assert_has_calls([
            mock.call('storage-disk-get-iter', args1, enable_tunneling=True),
            mock.call('storage-disk-get-iter', args2, enable_tunneling=True),
            mock.call('storage-disk-get-iter', args3, enable_tunneling=True),
        ])

    def test_send_iter_request_single_page(self):

        api_response = netapp_api.NaElement(
            fake.STORAGE_DISK_GET_ITER_RESPONSE)
        mock_send_request = self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=api_response))

        storage_disk_get_iter_args = {
            'desired-attributes': {
                'storage-disk-info': {
                    'disk-name': None,
                }
            }
        }
        result = self.client.send_iter_request(
            'storage-disk-get-iter', api_args=storage_disk_get_iter_args,
            max_page_length=10)

        num_records = result.get_child_content('num-records')
        self.assertEqual('4', num_records)

        args = copy.deepcopy(storage_disk_get_iter_args)
        args['max-records'] = 10

        mock_send_request.assert_has_calls([
            mock.call('storage-disk-get-iter', args, enable_tunneling=True),
        ])

    def test_send_iter_request_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        mock_send_request = self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=api_response))

        result = self.client.send_iter_request('storage-disk-get-iter')

        num_records = result.get_child_content('num-records')
        self.assertEqual('0', num_records)

        args = {'max-records': client_cmode.DEFAULT_MAX_PAGE_LENGTH}

        mock_send_request.assert_has_calls([
            mock.call('storage-disk-get-iter', args, enable_tunneling=True),
        ])

    @ddt.data(fake.INVALID_GET_ITER_RESPONSE_NO_ATTRIBUTES,
              fake.INVALID_GET_ITER_RESPONSE_NO_RECORDS)
    def test_send_iter_request_invalid(self, fake_response):

        api_response = netapp_api.NaElement(fake_response)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(exception.NetAppException,
                          self.client.send_iter_request,
                          'storage-disk-get-iter')

    def test_set_vserver(self):
        self.client.set_vserver(fake.VSERVER_NAME)
        self.client.connection.set_vserver.assert_has_calls(
            [mock.call('fake_vserver')])

    def test_vserver_exists(self):

        api_response = netapp_api.NaElement(fake.VSERVER_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        vserver_get_args = {
            'query': {'vserver-info': {'vserver-name': fake.VSERVER_NAME}},
            'desired-attributes': {'vserver-info': {'vserver-name': None}}
        }

        result = self.client.vserver_exists(fake.VSERVER_NAME)

        self.client.send_iter_request.assert_has_calls([
            mock.call('vserver-get-iter', vserver_get_args,
                      enable_tunneling=False)])
        self.assertTrue(result)

    def test_vserver_exists_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.vserver_exists(fake.VSERVER_NAME)

        self.assertFalse(result)

    def test_create_vserver_no_ipspace(self):

        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client,
                         '_modify_security_cert',
                         mock.Mock())

        vserver_create_args = {
            'vserver-name': fake.VSERVER_NAME,
            'root-volume-security-style': 'unix',
            'root-volume-aggregate': fake.ROOT_VOLUME_AGGREGATE_NAME,
            'root-volume': fake.ROOT_VOLUME_NAME,
            'name-server-switch': {'nsswitch': 'file'}
        }
        vserver_modify_args = {
            'aggr-list': [{'aggr-name': aggr_name} for aggr_name
                          in fake.SHARE_AGGREGATE_NAMES],
            'vserver-name': fake.VSERVER_NAME
        }

        self.client.create_vserver(fake.VSERVER_NAME,
                                   fake.ROOT_VOLUME_AGGREGATE_NAME,
                                   fake.ROOT_VOLUME_NAME,
                                   fake.SHARE_AGGREGATE_NAMES,
                                   None,
                                   fake.SECURITY_CERT_LARGE_EXPIRE_DAYS)

        self.client.send_request.assert_has_calls([
            mock.call('vserver-create', vserver_create_args),
            mock.call('vserver-modify', vserver_modify_args)])
        self.client._modify_security_cert.assert_called_with(
            fake.VSERVER_NAME, fake.SECURITY_CERT_LARGE_EXPIRE_DAYS)

    def test_create_vserver_with_ipspace(self):

        self.client.features.add_feature('IPSPACES')
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client,
                         '_modify_security_cert',
                         mock.Mock())

        vserver_create_args = {
            'vserver-name': fake.VSERVER_NAME,
            'root-volume-security-style': 'unix',
            'root-volume-aggregate': fake.ROOT_VOLUME_AGGREGATE_NAME,
            'root-volume': fake.ROOT_VOLUME_NAME,
            'name-server-switch': {'nsswitch': 'file'},
            'ipspace': fake.IPSPACE_NAME,
        }
        vserver_modify_args = {
            'aggr-list': [{'aggr-name': aggr_name} for aggr_name
                          in fake.SHARE_AGGREGATE_NAMES],
            'vserver-name': fake.VSERVER_NAME
        }

        self.client.create_vserver(fake.VSERVER_NAME,
                                   fake.ROOT_VOLUME_AGGREGATE_NAME,
                                   fake.ROOT_VOLUME_NAME,
                                   fake.SHARE_AGGREGATE_NAMES,
                                   fake.IPSPACE_NAME,
                                   fake.SECURITY_CERT_LARGE_EXPIRE_DAYS)

        self.client.send_request.assert_has_calls([
            mock.call('vserver-create', vserver_create_args),
            mock.call('vserver-modify', vserver_modify_args)])
        self.client._modify_security_cert.assert_called_with(
            fake.VSERVER_NAME, fake.SECURITY_CERT_LARGE_EXPIRE_DAYS)

    def test__modify_security_cert(self):

        certificate_create_args = {
            'vserver': fake.VSERVER_NAME,
            'common-name': fake.VSERVER_NAME,
            'type': 'server',
            'expire-days': fake.SECURITY_CERT_LARGE_EXPIRE_DAYS,
        }

        self.mock_object(self.client, 'send_request')
        api_response = netapp_api.NaElement(fake.SECURITY_CERT_GET_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))
        certificate_get_args = {
            'query': {
                'certificate-info': {
                    'vserver': fake.VSERVER_NAME,
                    'common-name': fake.VSERVER_NAME,
                    'certificate-authority': fake.VSERVER_NAME,
                    'type': 'server',
                },
            },
            'desired-attributes': {
                'certificate-info': {
                    'serial-number': None,
                },
            },
        }

        certificate_delete_args = {
            'certificate-authority': fake.VSERVER_NAME,
            'common-name': fake.VSERVER_NAME,
            'serial-number': '12345',
            'type': 'server',
            'vserver': fake.VSERVER_NAME,
        }

        self.client._modify_security_cert(
            fake.VSERVER_NAME,
            fake.SECURITY_CERT_LARGE_EXPIRE_DAYS)

        self.client.send_request.assert_has_calls([
            mock.call(
                'security-certificate-create', certificate_create_args),
            mock.call(
                'security-certificate-delete', certificate_delete_args)])

        self.client.send_iter_request.assert_has_calls([
            mock.call('security-certificate-get-iter', certificate_get_args)])

    def test_create_vserver_dp_destination(self):

        self.client.features.add_feature('IPSPACES')
        self.mock_object(self.client, 'send_request')

        vserver_create_args = {
            'vserver-name': fake.VSERVER_NAME,
            'ipspace': fake.IPSPACE_NAME,
            'vserver-subtype': fake.VSERVER_TYPE_DP_DEST,
        }
        vserver_modify_args = {
            'aggr-list': [{'aggr-name': aggr_name} for aggr_name
                          in fake.SHARE_AGGREGATE_NAMES],
            'vserver-name': fake.VSERVER_NAME
        }

        self.client.create_vserver_dp_destination(
            fake.VSERVER_NAME,
            fake.SHARE_AGGREGATE_NAMES,
            fake.IPSPACE_NAME)

        self.client.send_request.assert_has_calls([
            mock.call('vserver-create', vserver_create_args),
            mock.call('vserver-modify', vserver_modify_args)])

    def test_create_vserver_ipspaces_not_supported(self):

        self.assertRaises(exception.NetAppException,
                          self.client.create_vserver,
                          fake.VSERVER_NAME,
                          fake.ROOT_VOLUME_AGGREGATE_NAME,
                          fake.ROOT_VOLUME_NAME,
                          fake.SHARE_AGGREGATE_NAMES,
                          fake.IPSPACE_NAME,
                          fake.SECURITY_CERT_LARGE_EXPIRE_DAYS)

    def test_get_vserver_root_volume_name(self):

        api_response = netapp_api.NaElement(
            fake.VSERVER_GET_ROOT_VOLUME_NAME_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        vserver_get_args = {
            'query': {'vserver-info': {'vserver-name': fake.VSERVER_NAME}},
            'desired-attributes': {'vserver-info': {'root-volume': None}}
        }

        result = self.client.get_vserver_root_volume_name(fake.VSERVER_NAME)

        self.client.send_iter_request.assert_has_calls([
            mock.call('vserver-get-iter', vserver_get_args)])
        self.assertEqual(fake.ROOT_VOLUME_NAME, result)

    def test_get_vserver_root_volume_name_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(exception.NetAppException,
                          self.client.get_vserver_root_volume_name,
                          fake.VSERVER_NAME)

    def test_get_vserver_ipspace(self):

        self.client.features.add_feature('IPSPACES')
        api_response = netapp_api.NaElement(
            fake.VSERVER_GET_IPSPACE_NAME_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_vserver_ipspace(fake.VSERVER_NAME)

        vserver_get_iter_args = {
            'query': {
                'vserver-info': {
                    'vserver-name': fake.VSERVER_NAME,
                },
            },
            'desired-attributes': {
                'vserver-info': {
                    'ipspace': None,
                },
            },
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('vserver-get-iter', vserver_get_iter_args)])
        self.assertEqual(fake.IPSPACE_NAME, result)

    def test_get_vserver_ipspace_not_supported(self):

        result = self.client.get_vserver_ipspace(fake.IPSPACE_NAME)

        self.assertIsNone(result)

    def test_get_vserver_ipspace_not_found(self):

        self.client.features.add_feature('IPSPACES')
        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(exception.NetAppException,
                          self.client.get_vserver_ipspace,
                          fake.IPSPACE_NAME)

    def test_ipspace_has_data_vservers(self):

        self.client.features.add_feature('IPSPACES')
        api_response = netapp_api.NaElement(fake.VSERVER_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.ipspace_has_data_vservers(fake.IPSPACE_NAME)

        vserver_get_iter_args = {
            'query': {
                'vserver-info': {
                    'ipspace': fake.IPSPACE_NAME,
                    'vserver-type': 'data'
                },
            },
            'desired-attributes': {
                'vserver-info': {
                    'vserver-name': None,
                },
            },
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('vserver-get-iter', vserver_get_iter_args)])
        self.assertTrue(result)

    def test_ipspace_has_data_vservers_not_supported(self):

        result = self.client.ipspace_has_data_vservers(fake.IPSPACE_NAME)

        self.assertFalse(result)

    def test_ipspace_has_data_vservers_not_found(self):

        self.client.features.add_feature('IPSPACES')
        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.ipspace_has_data_vservers(fake.IPSPACE_NAME)

        self.assertFalse(result)

    def test_list_vservers(self):

        api_response = netapp_api.NaElement(
            fake.VSERVER_DATA_LIST_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.list_vservers()

        vserver_get_iter_args = {
            'query': {
                'vserver-info': {
                    'vserver-type': 'data'
                }
            },
            'desired-attributes': {
                'vserver-info': {
                    'vserver-name': None
                }
            }
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('vserver-get-iter', vserver_get_iter_args)])
        self.assertListEqual([fake.VSERVER_NAME], result)

    def test_list_vservers_node_type(self):

        api_response = netapp_api.NaElement(
            fake.VSERVER_DATA_LIST_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.list_vservers(vserver_type='node')

        vserver_get_iter_args = {
            'query': {
                'vserver-info': {
                    'vserver-type': 'node'
                }
            },
            'desired-attributes': {
                'vserver-info': {
                    'vserver-name': None
                }
            }
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('vserver-get-iter', vserver_get_iter_args)])
        self.assertListEqual([fake.VSERVER_NAME], result)

    def test_list_vservers_not_found(self):

        api_response = netapp_api.NaElement(
            fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.list_vservers(vserver_type='data')

        self.assertListEqual([], result)

    def test_get_vserver_volume_count(self):

        api_response = netapp_api.NaElement(fake.VOLUME_COUNT_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_vserver_volume_count()

        self.assertEqual(2, result)

    def test_delete_vserver_no_volumes(self):

        self.mock_object(self.client,
                         'get_vserver_info',
                         mock.Mock(return_value=fake.VSERVER_INFO))
        self.mock_object(self.client,
                         'get_vserver_root_volume_name',
                         mock.Mock(return_value=fake.ROOT_VOLUME_NAME))
        self.mock_object(self.vserver_client,
                         'get_vserver_volume_count',
                         mock.Mock(return_value=0))
        self.mock_object(self.client, '_terminate_vserver_services')
        self.mock_object(self.client, 'send_request')

        self.client.delete_vserver(
            fake.VSERVER_NAME,
            self.vserver_client,
            security_services=[fake.CIFS_SECURITY_SERVICE])

        self.client._terminate_vserver_services.assert_called_with(
            fake.VSERVER_NAME, self.vserver_client,
            [fake.CIFS_SECURITY_SERVICE])

        vserver_destroy_args = {'vserver-name': fake.VSERVER_NAME}
        self.client.send_request.assert_has_calls([
            mock.call('vserver-destroy', vserver_destroy_args)])

    def test_delete_vserver_one_volume(self):

        self.mock_object(self.client,
                         'get_vserver_info',
                         mock.Mock(return_value=fake.VSERVER_INFO))
        self.mock_object(self.client,
                         'get_vserver_root_volume_name',
                         mock.Mock(return_value=fake.ROOT_VOLUME_NAME))
        self.mock_object(self.vserver_client,
                         'get_vserver_volume_count',
                         mock.Mock(return_value=1))
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.vserver_client, 'offline_volume')
        self.mock_object(self.vserver_client, 'delete_volume')

        self.client.delete_vserver(fake.VSERVER_NAME,
                                   self.vserver_client)

        self.vserver_client.offline_volume.assert_called_with(
            fake.ROOT_VOLUME_NAME)
        self.vserver_client.delete_volume.assert_called_with(
            fake.ROOT_VOLUME_NAME)

        vserver_destroy_args = {'vserver-name': fake.VSERVER_NAME}
        self.client.send_request.assert_has_calls([
            mock.call('vserver-destroy', vserver_destroy_args)])

    def test_delete_vserver_one_volume_already_offline(self):

        self.mock_object(self.client,
                         'get_vserver_info',
                         mock.Mock(return_value=fake.VSERVER_INFO))
        self.mock_object(self.client,
                         'get_vserver_root_volume_name',
                         mock.Mock(return_value=fake.ROOT_VOLUME_NAME))
        self.mock_object(self.vserver_client,
                         'get_vserver_volume_count',
                         mock.Mock(return_value=1))
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.vserver_client,
                         'offline_volume',
                         self._mock_api_error(code=netapp_api.EVOLUMEOFFLINE))

        self.mock_object(self.vserver_client, 'delete_volume')

        self.client.delete_vserver(fake.VSERVER_NAME,
                                   self.vserver_client)

        self.vserver_client.offline_volume.assert_called_with(
            fake.ROOT_VOLUME_NAME)
        self.vserver_client.delete_volume.assert_called_with(
            fake.ROOT_VOLUME_NAME)

        vserver_destroy_args = {'vserver-name': fake.VSERVER_NAME}
        self.client.send_request.assert_has_calls([
            mock.call('vserver-destroy', vserver_destroy_args)])
        self.assertEqual(1, client_cmode.LOG.error.call_count)

    def test_delete_vserver_one_volume_api_error(self):

        self.mock_object(self.client,
                         'get_vserver_info',
                         mock.Mock(return_value=fake.VSERVER_INFO))
        self.mock_object(self.client,
                         'get_vserver_root_volume_name',
                         mock.Mock(return_value=fake.ROOT_VOLUME_NAME))
        self.mock_object(self.vserver_client,
                         'get_vserver_volume_count',
                         mock.Mock(return_value=1))
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.vserver_client,
                         'offline_volume',
                         self._mock_api_error())
        self.mock_object(self.vserver_client, 'delete_volume')

        self.assertRaises(netapp_api.NaApiError,
                          self.client.delete_vserver,
                          fake.VSERVER_NAME,
                          self.vserver_client)

    def test_delete_vserver_multiple_volumes(self):

        self.mock_object(self.client,
                         'get_vserver_info',
                         mock.Mock(return_value=fake.VSERVER_INFO))
        self.mock_object(self.client,
                         'get_vserver_root_volume_name',
                         mock.Mock(return_value=fake.ROOT_VOLUME_NAME))
        self.mock_object(self.vserver_client,
                         'get_vserver_volume_count',
                         mock.Mock(return_value=2))

        self.assertRaises(exception.NetAppException,
                          self.client.delete_vserver,
                          fake.VSERVER_NAME,
                          self.vserver_client)

    def test_delete_vserver_not_found(self):

        self.mock_object(self.client,
                         'get_vserver_info',
                         mock.Mock(return_value=None))

        self.client.delete_vserver(fake.VSERVER_NAME,
                                   self.vserver_client)

        self.assertEqual(1, client_cmode.LOG.error.call_count)

    def test_terminate_vserver_services(self):

        self.mock_object(self.vserver_client, 'send_request')

        self.client._terminate_vserver_services(fake.VSERVER_NAME,
                                                self.vserver_client,
                                                [fake.CIFS_SECURITY_SERVICE])

        cifs_server_delete_args = {
            'admin-password': fake.CIFS_SECURITY_SERVICE['password'],
            'admin-username': fake.CIFS_SECURITY_SERVICE['user'],
        }
        self.vserver_client.send_request.assert_has_calls([
            mock.call('cifs-server-delete', cifs_server_delete_args)])

    def test_terminate_vserver_services_cifs_not_found(self):

        self.mock_object(self.vserver_client,
                         'send_request',
                         self._mock_api_error(
                             code=netapp_api.EOBJECTNOTFOUND))

        self.client._terminate_vserver_services(fake.VSERVER_NAME,
                                                self.vserver_client,
                                                [fake.CIFS_SECURITY_SERVICE])

        cifs_server_delete_args = {
            'admin-password': fake.CIFS_SECURITY_SERVICE['password'],
            'admin-username': fake.CIFS_SECURITY_SERVICE['user'],
        }
        self.vserver_client.send_request.assert_has_calls([
            mock.call('cifs-server-delete', cifs_server_delete_args)])
        self.assertEqual(1, client_cmode.LOG.error.call_count)

    def test_terminate_vserver_services_api_error(self):

        side_effects = [netapp_api.NaApiError(code='fake'), None]
        self.mock_object(self.vserver_client,
                         'send_request',
                         mock.Mock(side_effect=side_effects))

        self.client._terminate_vserver_services(fake.VSERVER_NAME,
                                                self.vserver_client,
                                                [fake.CIFS_SECURITY_SERVICE])

        cifs_server_delete_args = {
            'admin-password': fake.CIFS_SECURITY_SERVICE['password'],
            'admin-username': fake.CIFS_SECURITY_SERVICE['user'],
        }
        cifs_server_delete_force_args = {
            'force-account-delete': 'true',
        }
        self.vserver_client.send_request.assert_has_calls([
            mock.call('cifs-server-delete', cifs_server_delete_args),
            mock.call('cifs-server-delete', cifs_server_delete_force_args)])
        self.assertEqual(0, client_cmode.LOG.error.call_count)

    def test_list_cluster_nodes(self):

        api_response = netapp_api.NaElement(
            fake.SYSTEM_NODE_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.list_cluster_nodes()

        self.assertListEqual([fake.NODE_NAME], result)

    def test_list_cluster_nodes_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.list_cluster_nodes()

        self.assertListEqual([], result)

    def test_list_node_data_ports(self):

        self.mock_object(self.client,
                         'get_node_data_ports',
                         mock.Mock(return_value=fake.SPEED_SORTED_PORTS))

        result = self.client.list_node_data_ports(fake.NODE_NAME)

        self.assertSequenceEqual(fake.SPEED_SORTED_PORT_NAMES, result)

    def test_get_node_data_ports(self):

        api_response = netapp_api.NaElement(fake.NET_PORT_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_node_data_ports(fake.NODE_NAME)

        net_port_get_iter_args = {
            'query': {
                'net-port-info': {
                    'node': fake.NODE_NAME,
                    'link-status': 'up',
                    'port-type': 'physical|if_group',
                    'role': 'data',
                },
            },
            'desired-attributes': {
                'net-port-info': {
                    'port': None,
                    'node': None,
                    'operational-speed': None,
                    'ifgrp-port': None,
                },
            },
        }

        self.assertSequenceEqual(fake.SPEED_SORTED_PORTS, result)
        self.client.send_iter_request.assert_has_calls([
            mock.call('net-port-get-iter', net_port_get_iter_args)])

    def test_get_node_data_ports_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_node_data_ports(fake.NODE_NAME)

        self.assertSequenceEqual([], result)

    def test_sort_data_ports_by_speed(self):

        result = self.client._sort_data_ports_by_speed(
            fake.UNSORTED_PORTS_ALL_SPEEDS)

        self.assertSequenceEqual(fake.SORTED_PORTS_ALL_SPEEDS, result)

    def test_list_root_aggregates(self):

        api_response = netapp_api.NaElement(
            fake.AGGR_GET_ITER_ROOT_AGGR_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.list_root_aggregates()

        aggr_get_iter_args = {
            'desired-attributes': {
                'aggr-attributes': {
                    'aggregate-name': None,
                    'aggr-raid-attributes': {
                        'has-local-root': None,
                        'has-partner-root': None,
                    },
                },
            }
        }
        self.assertSequenceEqual(fake.ROOT_AGGREGATE_NAMES, result)
        self.client.send_iter_request.assert_has_calls([
            mock.call('aggr-get-iter', aggr_get_iter_args)])

    def test_list_non_root_aggregates(self):

        api_response = netapp_api.NaElement(
            fake.AGGR_GET_ITER_NON_ROOT_AGGR_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.list_non_root_aggregates()

        aggr_get_iter_args = {
            'query': {
                'aggr-attributes': {
                    'aggr-raid-attributes': {
                        'has-local-root': 'false',
                        'has-partner-root': 'false',
                    }
                },
            },
            'desired-attributes': {
                'aggr-attributes': {
                    'aggregate-name': None,
                },
            },
        }
        self.assertSequenceEqual(fake.SHARE_AGGREGATE_NAMES, result)
        self.client.send_iter_request.assert_has_calls([
            mock.call('aggr-get-iter', aggr_get_iter_args)])

    def test_list_aggregates(self):

        api_response = netapp_api.NaElement(fake.AGGR_GET_NAMES_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client._list_aggregates()

        aggr_get_iter_args = {
            'desired-attributes': {
                'aggr-attributes': {
                    'aggregate-name': None,
                },
            },
        }
        self.assertSequenceEqual(
            fake.ROOT_AGGREGATE_NAMES + fake.SHARE_AGGREGATE_NAMES, result)
        self.client.send_iter_request.assert_has_calls([
            mock.call('aggr-get-iter', aggr_get_iter_args)])

    def test_list_aggregates_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(exception.NetAppException,
                          self.client._list_aggregates)

    def test_list_vserver_aggregates(self):

        self.mock_object(self.vserver_client,
                         'get_vserver_aggregate_capacities',
                         mock.Mock(return_value=fake.VSERVER_AGGREGATES))

        result = self.vserver_client.list_vserver_aggregates()

        self.assertListEqual(list(fake.VSERVER_AGGREGATES.keys()), result)

    def test_list_vserver_aggregates_none_found(self):

        self.mock_object(self.vserver_client,
                         'get_vserver_aggregate_capacities',
                         mock.Mock(return_value={}))

        result = self.vserver_client.list_vserver_aggregates()

        self.assertListEqual([], result)

    def test_create_network_interface(self):

        self.mock_object(self.client, 'send_request')

        lif_create_args = {
            'address': fake.IP_ADDRESS,
            'administrative-status': 'up',
            'data-protocols': [
                {'data-protocol': 'nfs'},
                {'data-protocol': 'cifs'}
            ],
            'home-node': fake.NODE_NAME,
            'home-port': fake.VLAN_PORT,
            'netmask': fake.NETMASK,
            'interface-name': fake.LIF_NAME,
            'role': 'data',
            'vserver': fake.VSERVER_NAME,
        }
        self.client.create_network_interface(fake.IP_ADDRESS,
                                             fake.NETMASK,
                                             fake.NODE_NAME,
                                             fake.VLAN_PORT,
                                             fake.VSERVER_NAME,
                                             fake.LIF_NAME)

        self.client.send_request.assert_called_once_with(
            'net-interface-create', lif_create_args)

    @ddt.data((None, True), (fake.VLAN, True), (None, False),
              (fake.VLAN, False))
    @ddt.unpack
    def test_create_port_and_broadcast_domain(self, fake_vlan,
                                              broadcast_domains_supported):

        self.client.features.add_feature(
            'BROADCAST_DOMAINS', broadcast_domains_supported)

        mock_create_vlan = self.mock_object(
            self.client, '_create_vlan')
        mock_ensure_broadcast = self.mock_object(
            self.client, '_ensure_broadcast_domain_for_port')

        result = self.client.create_port_and_broadcast_domain(
            fake.NODE_NAME, fake.PORT, fake_vlan, fake.MTU, fake.IPSPACE_NAME)

        if fake_vlan:
            mock_create_vlan.assert_called_once_with(
                fake.NODE_NAME, fake.PORT, fake_vlan)

        fake_home_port_name = (
            f'{fake.PORT}-{fake_vlan}' if fake_vlan else fake.PORT)
        if broadcast_domains_supported:
            mock_ensure_broadcast.assert_called_once_with(
                fake.NODE_NAME, fake_home_port_name, fake.MTU,
                ipspace=fake.IPSPACE_NAME)

        self.assertEqual(fake_home_port_name, result)

    def test_create_vlan(self):

        self.mock_object(self.client, 'send_request')

        vlan_create_args = {
            'vlan-info': {
                'parent-interface': fake.PORT,
                'node': fake.NODE_NAME,
                'vlanid': fake.VLAN
            }
        }
        self.client._create_vlan(fake.NODE_NAME, fake.PORT, fake.VLAN)

        self.client.send_request.assert_has_calls([
            mock.call('net-vlan-create', vlan_create_args)])

    def test_create_vlan_already_present(self):

        self.mock_object(self.client,
                         'send_request',
                         self._mock_api_error(code=netapp_api.EDUPLICATEENTRY))

        vlan_create_args = {
            'vlan-info': {
                'parent-interface': fake.PORT,
                'node': fake.NODE_NAME,
                'vlanid': fake.VLAN
            }
        }
        self.client._create_vlan(fake.NODE_NAME, fake.PORT, fake.VLAN)

        self.client.send_request.assert_has_calls([
            mock.call('net-vlan-create', vlan_create_args)])
        self.assertEqual(1, client_cmode.LOG.debug.call_count)

    def test_create_vlan_api_error(self):

        self.mock_object(self.client, 'send_request', self._mock_api_error())

        self.assertRaises(exception.NetAppException,
                          self.client._create_vlan,
                          fake.NODE_NAME,
                          fake.PORT,
                          fake.VLAN)

    def test_delete_vlan(self):

        self.mock_object(self.client, 'send_request')

        vlan_delete_args = {
            'vlan-info': {
                'parent-interface': fake.PORT,
                'node': fake.NODE_NAME,
                'vlanid': fake.VLAN
            }
        }
        self.client.delete_vlan(fake.NODE_NAME, fake.PORT, fake.VLAN)

        self.client.send_request.assert_has_calls([
            mock.call('net-vlan-delete', vlan_delete_args)])

    def test_delete_vlan_still_used(self):

        self.mock_object(self.client,
                         'send_request',
                         self._mock_api_error(code=netapp_api.EAPIERROR,
                                              message='Port already has a '
                                              'lif bound. '))

        vlan_delete_args = {
            'vlan-info': {
                'parent-interface': fake.PORT,
                'node': fake.NODE_NAME,
                'vlanid': fake.VLAN
            }
        }
        self.client.delete_vlan(fake.NODE_NAME, fake.PORT, fake.VLAN)

        self.client.send_request.assert_has_calls([
            mock.call('net-vlan-delete', vlan_delete_args)])
        self.assertEqual(1, client_cmode.LOG.debug.call_count)

    def test_delete_vlan_api_error(self):

        self.mock_object(self.client, 'send_request', self._mock_api_error())

        self.assertRaises(exception.NetAppException,
                          self.client.delete_vlan,
                          fake.NODE_NAME,
                          fake.PORT,
                          fake.VLAN)

    @ddt.data(('10.10.10.0/24', '10.10.10.1', False),
              ('fc00::/7', 'fe80::1', False),
              ('0.0.0.0/0', '10.10.10.1', True),
              ('::/0', 'fe80::1', True))
    @ddt.unpack
    def test_create_route(self, subnet, gateway, omit_destination):
        api_response = netapp_api.NaElement(
            fake.NET_ROUTES_CREATE_RESPONSE)
        expected_api_args = {
            'destination': subnet,
            'gateway': gateway,
            'return-record': 'true',
        }
        self.mock_object(
            self.client, 'send_request', mock.Mock(return_value=api_response))

        destination = None if omit_destination else subnet
        self.client.create_route(gateway, destination=destination)

        self.client.send_request.assert_called_once_with(
            'net-routes-create', expected_api_args)

    def test_create_route_duplicate(self):
        self.mock_object(client_cmode.LOG, 'debug')
        expected_api_args = {
            'destination': fake.SUBNET,
            'gateway': fake.GATEWAY,
            'return-record': 'true',
        }
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(side_effect=self._mock_api_error(
                code=netapp_api.EAPIERROR, message='Duplicate route exists.')))

        self.client.create_route(fake.GATEWAY, destination=fake.SUBNET)

        self.client.send_request.assert_called_once_with(
            'net-routes-create', expected_api_args)
        self.assertEqual(1, client_cmode.LOG.debug.call_count)

    def test_create_route_api_error(self):
        expected_api_args = {
            'destination': fake.SUBNET,
            'gateway': fake.GATEWAY,
            'return-record': 'true',
        }
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(side_effect=self._mock_api_error()))

        self.assertRaises(exception.NetAppException,
                          self.client.create_route,
                          fake.GATEWAY, destination=fake.SUBNET)

        self.client.send_request.assert_called_once_with(
            'net-routes-create', expected_api_args)

    def test_create_route_without_gateway(self):
        self.mock_object(self.client, 'send_request')
        self.client.create_route(None, destination=fake.SUBNET)
        self.assertFalse(self.client.send_request.called)

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
        self.mock_object(self.client, '_remove_port_from_broadcast_domain')
        self.mock_object(self.client, '_add_port_to_broadcast_domain')

        self.client._ensure_broadcast_domain_for_port(
            fake.NODE_NAME, fake.PORT, ipspace=fake.IPSPACE_NAME, mtu=fake.MTU)

        self.client._get_broadcast_domain_for_port.assert_called_once_with(
            fake.NODE_NAME, fake.PORT)
        self.client._remove_port_from_broadcast_domain.assert_called_once_with(
            fake.NODE_NAME, fake.PORT, 'other_domain', ipspace)
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
        self.mock_object(self.client, '_remove_port_from_broadcast_domain')
        self.mock_object(self.client, '_add_port_to_broadcast_domain')

        self.client._ensure_broadcast_domain_for_port(
            fake.NODE_NAME, fake.PORT, ipspace=fake.IPSPACE_NAME, mtu=fake.MTU)

        self.client._get_broadcast_domain_for_port.assert_called_once_with(
            fake.NODE_NAME, fake.PORT)
        self.assertFalse(self.client._remove_port_from_broadcast_domain.called)
        self.client._broadcast_domain_exists.assert_called_once_with(
            fake.BROADCAST_DOMAIN, fake.IPSPACE_NAME)
        self.client._create_broadcast_domain.assert_called_once_with(
            fake.BROADCAST_DOMAIN, fake.IPSPACE_NAME, fake.MTU)
        self.assertFalse(self.client._modify_broadcast_domain.called)
        self.client._add_port_to_broadcast_domain.assert_called_once_with(
            fake.NODE_NAME, fake.PORT, fake.BROADCAST_DOMAIN,
            fake.IPSPACE_NAME)

    def test_get_broadcast_domain_for_port(self):

        api_response = netapp_api.NaElement(
            fake.NET_PORT_GET_ITER_BROADCAST_DOMAIN_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        net_port_get_iter_args = {
            'query': {
                'net-port-info': {
                    'node': fake.NODE_NAME,
                    'port': fake.PORT,
                },
            },
            'desired-attributes': {
                'net-port-info': {
                    'broadcast-domain': None,
                    'ipspace': None,
                },
            },
        }
        result = self.client._get_broadcast_domain_for_port(fake.NODE_NAME,
                                                            fake.PORT)

        expected = {
            'broadcast-domain': fake.BROADCAST_DOMAIN,
            'ipspace': fake.IPSPACE_NAME,
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('net-port-get-iter', net_port_get_iter_args)])
        self.assertEqual(expected, result)

    def test_get_broadcast_domain_for_port_port_not_found(self):

        api_response = netapp_api.NaElement(
            fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(exception.NetAppException,
                          self.client._get_broadcast_domain_for_port,
                          fake.NODE_NAME,
                          fake.PORT)

    def test_get_broadcast_domain_for_port_domain_not_found(self):

        api_response = netapp_api.NaElement(
            fake.NET_PORT_GET_ITER_BROADCAST_DOMAIN_MISSING_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client._get_broadcast_domain_for_port(fake.NODE_NAME,
                                                            fake.PORT)

        expected = {
            'broadcast-domain': None,
            'ipspace': fake.IPSPACE_NAME,
        }
        self.assertEqual(expected, result)

    def test_broadcast_domain_exists(self):

        api_response = netapp_api.NaElement(
            fake.NET_PORT_BROADCAST_DOMAIN_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client._broadcast_domain_exists(fake.BROADCAST_DOMAIN,
                                                      fake.IPSPACE_NAME)

        net_port_broadcast_domain_get_iter_args = {
            'query': {
                'net-port-broadcast-domain-info': {
                    'ipspace': fake.IPSPACE_NAME,
                    'broadcast-domain': fake.BROADCAST_DOMAIN,
                },
            },
            'desired-attributes': {
                'net-port-broadcast-domain-info': None,
            },
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('net-port-broadcast-domain-get-iter',
                      net_port_broadcast_domain_get_iter_args)])
        self.assertTrue(result)

    def test_broadcast_domain_exists_not_found(self):

        api_response = netapp_api.NaElement(
            fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client._broadcast_domain_exists(fake.BROADCAST_DOMAIN,
                                                      fake.IPSPACE_NAME)

        self.assertFalse(result)

    def test_create_broadcast_domain(self):

        self.mock_object(self.client, 'send_request')

        result = self.client._create_broadcast_domain(fake.BROADCAST_DOMAIN,
                                                      fake.IPSPACE_NAME,
                                                      fake.MTU)

        net_port_broadcast_domain_create_args = {
            'ipspace': fake.IPSPACE_NAME,
            'broadcast-domain': fake.BROADCAST_DOMAIN,
            'mtu': fake.MTU,
        }
        self.assertIsNone(result)
        self.client.send_request.assert_has_calls([
            mock.call('net-port-broadcast-domain-create',
                      net_port_broadcast_domain_create_args)])

    def test_modify_broadcast_domain(self):

        self.mock_object(self.client, 'send_request')

        result = self.client._modify_broadcast_domain(fake.BROADCAST_DOMAIN,
                                                      fake.IPSPACE_NAME,
                                                      fake.MTU)

        net_port_broadcast_domain_modify_args = {
            'ipspace': fake.IPSPACE_NAME,
            'broadcast-domain': fake.BROADCAST_DOMAIN,
            'mtu': fake.MTU,
        }
        self.assertIsNone(result)
        self.client.send_request.assert_called_once_with(
            'net-port-broadcast-domain-modify',
            net_port_broadcast_domain_modify_args)

    def test_delete_broadcast_domain(self):

        self.mock_object(self.client, 'send_request')

        result = self.client._delete_broadcast_domain(fake.BROADCAST_DOMAIN,
                                                      fake.IPSPACE_NAME)

        net_port_broadcast_domain_delete_args = {
            'ipspace': fake.IPSPACE_NAME,
            'broadcast-domain': fake.BROADCAST_DOMAIN,
        }
        self.assertIsNone(result)
        self.client.send_request.assert_has_calls([
            mock.call('net-port-broadcast-domain-destroy',
                      net_port_broadcast_domain_delete_args)])

    def test_delete_broadcast_domains_for_ipspace_not_found(self):

        self.mock_object(self.client,
                         'get_ipspaces',
                         mock.Mock(return_value=[]))
        self.mock_object(self.client, '_delete_broadcast_domain')

        self.client._delete_broadcast_domains_for_ipspace(fake.IPSPACE_NAME)

        self.client.get_ipspaces.assert_called_once_with(
            ipspace_name=fake.IPSPACE_NAME)
        self.assertFalse(self.client._delete_broadcast_domain.called)

    def test_delete_broadcast_domains_for_ipspace(self):

        self.mock_object(self.client,
                         'get_ipspaces',
                         mock.Mock(return_value=fake.IPSPACES))
        self.mock_object(self.client, '_delete_broadcast_domain')

        self.client._delete_broadcast_domains_for_ipspace(fake.IPSPACE_NAME)

        self.client.get_ipspaces.assert_called_once_with(
            ipspace_name=fake.IPSPACE_NAME)
        self.client._delete_broadcast_domain.assert_called_once_with(
            fake.IPSPACES[0]['broadcast-domains'][0], fake.IPSPACE_NAME)

    def test_add_port_to_broadcast_domain(self):

        self.mock_object(self.client, 'send_request')

        add_port_to_broadcast_domain_args = {
            'ipspace': fake.IPSPACE_NAME,
            'broadcast-domain': fake.BROADCAST_DOMAIN,
            'ports': {
                'net-qualified-port-name': ':'.join([fake.NODE_NAME,
                                                     fake.VLAN_PORT])
            }
        }
        result = self.client._add_port_to_broadcast_domain(
            fake.NODE_NAME, fake.VLAN_PORT, fake.BROADCAST_DOMAIN,
            fake.IPSPACE_NAME)

        self.assertIsNone(result)
        self.client.send_request.assert_has_calls([
            mock.call('net-port-broadcast-domain-add-ports',
                      add_port_to_broadcast_domain_args)])

    def test_add_port_to_broadcast_domain_already_present(self):

        self.mock_object(self.client, 'send_request', self._mock_api_error(
            code=netapp_api.
            E_VIFMGR_PORT_ALREADY_ASSIGNED_TO_BROADCAST_DOMAIN))

        result = self.client._add_port_to_broadcast_domain(
            fake.NODE_NAME, fake.VLAN_PORT, fake.BROADCAST_DOMAIN,
            fake.IPSPACE_NAME)

        self.assertIsNone(result)

    def test_add_port_to_broadcast_domain_api_error(self):

        self.mock_object(self.client, 'send_request', self._mock_api_error())

        self.assertRaises(exception.NetAppException,
                          self.client._add_port_to_broadcast_domain,
                          fake.NODE_NAME,
                          fake.VLAN_PORT,
                          fake.BROADCAST_DOMAIN,
                          fake.IPSPACE_NAME)

    def test_remove_port_from_broadcast_domain(self):

        self.mock_object(self.client, 'send_request')

        result = self.client._remove_port_from_broadcast_domain(
            fake.NODE_NAME, fake.VLAN_PORT, fake.BROADCAST_DOMAIN,
            fake.IPSPACE_NAME)

        net_port_broadcast_domain_remove_ports_args = {
            'ipspace': fake.IPSPACE_NAME,
            'broadcast-domain': fake.BROADCAST_DOMAIN,
            'ports': {
                'net-qualified-port-name': ':'.join([fake.NODE_NAME,
                                                     fake.VLAN_PORT])
            }
        }
        self.assertIsNone(result)
        self.client.send_request.assert_has_calls([
            mock.call('net-port-broadcast-domain-remove-ports',
                      net_port_broadcast_domain_remove_ports_args)])

    def test_network_interface_exists(self):

        api_response = netapp_api.NaElement(
            fake.NET_INTERFACE_GET_ONE_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        net_interface_get_args = {
            'query': {
                'net-interface-info': {
                    'address': fake.IP_ADDRESS,
                    'home-node': fake.NODE_NAME,
                    'home-port': fake.VLAN_PORT,
                    'netmask': fake.NETMASK,
                    'vserver': fake.VSERVER_NAME}
            },
            'desired-attributes': {
                'net-interface-info': {
                    'interface-name': None,
                }
            }
        }
        result = self.client.network_interface_exists(
            fake.VSERVER_NAME, fake.NODE_NAME, fake.PORT, fake.IP_ADDRESS,
            fake.NETMASK, fake.VLAN)

        self.client.send_iter_request.assert_has_calls([
            mock.call('net-interface-get-iter', net_interface_get_args)])
        self.assertTrue(result)

    def test_network_interface_exists_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        net_interface_get_args = {
            'query': {
                'net-interface-info': {
                    'address': fake.IP_ADDRESS,
                    'home-node': fake.NODE_NAME,
                    'home-port': fake.PORT,
                    'netmask': fake.NETMASK,
                    'vserver': fake.VSERVER_NAME}
            },
            'desired-attributes': {
                'net-interface-info': {
                    'interface-name': None,
                }
            }
        }
        result = self.client.network_interface_exists(
            fake.VSERVER_NAME, fake.NODE_NAME, fake.PORT, fake.IP_ADDRESS,
            fake.NETMASK, None)
        self.client.send_iter_request.assert_has_calls([
            mock.call('net-interface-get-iter', net_interface_get_args)])
        self.assertFalse(result)

    def test_list_network_interfaces(self):

        api_response = netapp_api.NaElement(
            fake.NET_INTERFACE_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        net_interface_get_args = {
            'desired-attributes': {
                'net-interface-info': {
                    'interface-name': None,
                }
            }
        }

        result = self.client.list_network_interfaces()

        self.client.send_iter_request.assert_has_calls([
            mock.call('net-interface-get-iter', net_interface_get_args)])
        self.assertSequenceEqual(fake.LIF_NAMES, result)

    def test_list_network_interfaces_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.list_network_interfaces()

        self.assertListEqual([], result)

    def test_get_network_interfaces(self):

        api_response = netapp_api.NaElement(
            fake.NET_INTERFACE_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_network_interfaces()

        self.client.send_iter_request.assert_has_calls([
            mock.call('net-interface-get-iter', None)])
        self.assertSequenceEqual(fake.LIFS, result)

    def test_get_network_interfaces_filtered_by_protocol(self):

        api_response = netapp_api.NaElement(
            fake.NET_INTERFACE_GET_ITER_RESPONSE_NFS)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_network_interfaces(protocols=['NFS'])

        net_interface_get_args = {
            'query': {
                'net-interface-info': {
                    'data-protocols': {
                        'data-protocol': 'nfs',
                    }
                }
            }
        }

        self.client.send_iter_request.assert_has_calls([
            mock.call('net-interface-get-iter', net_interface_get_args)])
        self.assertListEqual(fake.NFS_LIFS, result)

    def test_get_network_interfaces_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_network_interfaces()

        self.client.send_iter_request.assert_has_calls([
            mock.call('net-interface-get-iter', None)])
        self.assertListEqual([], result)

    def test_disable_network_interface(self):
        interface_name = fake.NETWORK_INTERFACES[0]['interface_name']
        vserver_name = fake.VSERVER_NAME
        expected_api_args = {
            'administrative-status': 'down',
            'interface-name': interface_name,
            'vserver': vserver_name,
        }

        self.mock_object(self.client, 'send_request')

        self.client.disable_network_interface(vserver_name, interface_name)

        self.client.send_request.assert_called_once_with(
            'net-interface-modify', expected_api_args)

    def test_delete_network_interface(self):
        interface_name = fake.NETWORK_INTERFACES[0]['interface_name']
        vserver_name = fake.VSERVER_NAME
        expected_api_args = {
            'interface-name': interface_name,
            'vserver': vserver_name,
        }

        self.mock_object(self.client, 'disable_network_interface')
        self.mock_object(self.client, 'send_request')

        self.client.delete_network_interface(vserver_name, interface_name)

        self.client.disable_network_interface.assert_called_once_with(
            vserver_name, interface_name)
        self.client.send_request.assert_called_once_with(
            'net-interface-delete', expected_api_args)

    def test_get_ipspaces(self):

        self.client.features.add_feature('IPSPACES')
        api_response = netapp_api.NaElement(
            fake.NET_IPSPACES_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_ipspaces(ipspace_name=fake.IPSPACE_NAME)

        net_ipspaces_get_iter_args = {
            'query': {
                'net-ipspaces-info': {
                    'ipspace': fake.IPSPACE_NAME,
                },
            },
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('net-ipspaces-get-iter', net_ipspaces_get_iter_args)])
        self.assertEqual(fake.IPSPACES, result)

    def test_get_ipspaces_not_found(self):

        self.client.features.add_feature('IPSPACES')
        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_ipspaces()

        net_ipspaces_get_iter_args = {}
        self.client.send_iter_request.assert_has_calls([
            mock.call('net-ipspaces-get-iter', net_ipspaces_get_iter_args)])
        self.assertEqual([], result)

    def test_get_ipspaces_not_supported(self):

        self.mock_object(self.client, 'send_iter_request')

        result = self.client.get_ipspaces()

        self.assertFalse(self.client.send_iter_request.called)
        self.assertEqual([], result)

    @ddt.data((fake.NET_IPSPACES_GET_ITER_RESPONSE, True),
              (fake.NO_RECORDS_RESPONSE, False))
    @ddt.unpack
    def test_ipspace_exists(self, api_response, expected):

        self.client.features.add_feature('IPSPACES')
        api_response = netapp_api.NaElement(api_response)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.ipspace_exists(fake.IPSPACE_NAME)

        net_ipspaces_get_iter_args = {
            'query': {
                'net-ipspaces-info': {
                    'ipspace': fake.IPSPACE_NAME,
                },
            },
            'desired-attributes': {
                'net-ipspaces-info': {
                    'ipspace': None,
                },
            },
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('net-ipspaces-get-iter', net_ipspaces_get_iter_args)])
        self.assertEqual(expected, result)

    def test_ipspace_exists_not_supported(self):

        result = self.client.ipspace_exists(fake.IPSPACE_NAME)

        self.assertFalse(result)

    def test_create_ipspace(self):

        self.mock_object(self.client, 'send_request')

        self.client.create_ipspace(fake.IPSPACE_NAME)

        net_ipspaces_create_args = {'ipspace': fake.IPSPACE_NAME}
        self.client.send_request.assert_has_calls([
            mock.call('net-ipspaces-create', net_ipspaces_create_args)])

    def test_delete_ipspace(self):

        mock_delete_broadcast_domains_for_ipspace = self.mock_object(
            self.client, '_delete_broadcast_domains_for_ipspace')
        self.mock_object(self.client, 'send_request')

        self.client.delete_ipspace(fake.IPSPACE_NAME)

        net_ipspaces_destroy_args = {'ipspace': fake.IPSPACE_NAME}
        mock_delete_broadcast_domains_for_ipspace.assert_called_once_with(
            fake.IPSPACE_NAME)
        self.client.send_request.assert_has_calls([
            mock.call('net-ipspaces-destroy', net_ipspaces_destroy_args)])

    def test_get_ipspace_name_for_vlan_port(self):
        self.client.features.add_feature('IPSPACES')
        api_response = netapp_api.NaElement(fake.NET_PORT_GET_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        ipspace = self.client.get_ipspace_name_for_vlan_port(
            fake.NODE_NAME, fake.PORT, fake.VLAN)

        port = '%(port)s-%(id)s' % {'port': fake.PORT, 'id': fake.VLAN}
        self.client.send_request.assert_called_once_with(
            'net-port-get',
            {'node': fake.NODE_NAME, 'port': port})
        self.assertEqual(fake.IPSPACE_NAME, ipspace)

    def test_get_ipspace_name_for_vlan_port_no_ipspace_feature(self):
        self.mock_object(self.client, 'send_request')

        ipspace = self.client.get_ipspace_name_for_vlan_port(
            fake.NODE_NAME, fake.PORT, fake.VLAN)

        self.client.send_request.assert_not_called()
        self.assertIsNone(ipspace)

    def test_get_ipspace_name_for_vlan_port_no_ipspace_found(self):
        self.client.features.add_feature('IPSPACES')
        self.mock_object(
            self.client,
            'send_request',
            self._mock_api_error(code=netapp_api.EOBJECTNOTFOUND))

        ipspace = self.client.get_ipspace_name_for_vlan_port(
            fake.NODE_NAME, fake.PORT, fake.VLAN)

        self.assertIsNone(ipspace)

    def test_get_ipspace_name_for_vlan_port_no_vlan(self):
        self.client.features.add_feature('IPSPACES')
        api_response = netapp_api.NaElement(fake.NET_PORT_GET_RESPONSE_NO_VLAN)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        ipspace = self.client.get_ipspace_name_for_vlan_port(
            fake.NODE_NAME, fake.PORT, None)

        self.client.send_request.assert_called_once_with(
            'net-port-get',
            {'node': fake.NODE_NAME, 'port': fake.PORT})
        self.assertEqual(fake.IPSPACE_NAME, ipspace)

    def test_get_ipspace_name_for_vlan_port_raises_api_error(self):
        self.client.features.add_feature('IPSPACES')
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(side_effect=self._mock_api_error()))

        self.assertRaises(netapp_api.NaApiError,
                          self.client.get_ipspace_name_for_vlan_port,
                          fake.NODE_NAME, fake.VLAN_PORT, None)

    def test_add_vserver_to_ipspace(self):

        self.mock_object(self.client, 'send_request')

        self.client.add_vserver_to_ipspace(fake.IPSPACE_NAME,
                                           fake.VSERVER_NAME)

        net_ipspaces_assign_vserver_args = {
            'ipspace': fake.IPSPACE_NAME,
            'vserver': fake.VSERVER_NAME
        }
        self.client.send_request.assert_has_calls([
            mock.call('net-ipspaces-assign-vserver',
                      net_ipspaces_assign_vserver_args)])

    def test_get_node_for_aggregate(self):

        api_response = netapp_api.NaElement(
            fake.AGGR_GET_NODE_RESPONSE).get_child_by_name(
            'attributes-list').get_children()
        self.mock_object(self.client,
                         '_get_aggregates',
                         mock.Mock(return_value=api_response))

        result = self.client.get_node_for_aggregate(fake.SHARE_AGGREGATE_NAME)

        desired_attributes = {
            'aggr-attributes': {
                'aggregate-name': None,
                'aggr-ownership-attributes': {
                    'home-name': None,
                },
            },
        }

        self.client._get_aggregates.assert_has_calls([
            mock.call(
                aggregate_names=[fake.SHARE_AGGREGATE_NAME],
                desired_attributes=desired_attributes)])

        self.assertEqual(fake.NODE_NAME, result)

    def test_get_node_for_aggregate_none_requested(self):

        result = self.client.get_node_for_aggregate(None)

        self.assertIsNone(result)

    def test_get_node_for_aggregate_api_not_found(self):

        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(side_effect=self._mock_api_error(
                             netapp_api.EAPINOTFOUND)))

        result = self.client.get_node_for_aggregate(fake.SHARE_AGGREGATE_NAME)

        self.assertIsNone(result)

    def test_get_node_for_aggregate_api_error(self):

        self.mock_object(self.client,
                         'send_iter_request',
                         self._mock_api_error())

        self.assertRaises(netapp_api.NaApiError,
                          self.client.get_node_for_aggregate,
                          fake.SHARE_AGGREGATE_NAME)

    def test_get_node_for_aggregate_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_node_for_aggregate(fake.SHARE_AGGREGATE_NAME)

        self.assertIsNone(result)

    def test_get_cluster_aggregate_capacities(self):

        api_response = netapp_api.NaElement(
            fake.AGGR_GET_SPACE_RESPONSE).get_child_by_name(
            'attributes-list').get_children()
        self.mock_object(self.client,
                         '_get_aggregates',
                         mock.Mock(return_value=api_response))

        result = self.client.get_cluster_aggregate_capacities(
            fake.SHARE_AGGREGATE_NAMES)

        desired_attributes = {
            'aggr-attributes': {
                'aggregate-name': None,
                'aggr-space-attributes': {
                    'size-available': None,
                    'size-total': None,
                    'size-used': None,
                }
            }
        }

        self.client._get_aggregates.assert_has_calls([
            mock.call(
                aggregate_names=fake.SHARE_AGGREGATE_NAMES,
                desired_attributes=desired_attributes)])

        expected = {
            fake.SHARE_AGGREGATE_NAMES[0]: {
                'available': 45670400,
                'total': 943718400,
                'used': 898048000,
            },
            fake.SHARE_AGGREGATE_NAMES[1]: {
                'available': 4267659264,
                'total': 7549747200,
                'used': 3282087936,
            },
        }
        self.assertDictEqual(expected, result)

    def test_get_cluster_aggregate_capacities_not_found(self):

        api_response = netapp_api.NaElement('none').get_children()
        self.mock_object(self.client,
                         '_get_aggregates',
                         mock.Mock(return_value=api_response))

        result = self.client.get_cluster_aggregate_capacities(
            fake.SHARE_AGGREGATE_NAMES)

        self.assertEqual({}, result)

    def test_get_cluster_aggregate_capacities_none_requested(self):

        result = self.client.get_cluster_aggregate_capacities([])

        self.assertEqual({}, result)

    def test_get_vserver_aggregate_capacities(self):

        api_response = netapp_api.NaElement(fake.VSERVER_GET_RESPONSE)
        self.mock_object(self.vserver_client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.vserver_client.get_vserver_aggregate_capacities()

        vserver_args = {
            'desired-attributes': {
                'vserver-info': {
                    'vserver-name': None,
                    'vserver-aggr-info-list': {
                        'vserver-aggr-info': {
                            'aggr-name': None,
                            'aggr-availsize': None
                        }
                    }
                }
            }
        }

        self.vserver_client.send_request.assert_has_calls([
            mock.call('vserver-get', vserver_args)])
        self.assertDictEqual(fake.VSERVER_AGGREGATES, result)

    def test_get_vserver_aggregate_capacities_partial_request(self):

        api_response = netapp_api.NaElement(fake.VSERVER_GET_RESPONSE)
        self.mock_object(self.vserver_client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.vserver_client.get_vserver_aggregate_capacities(
            fake.SHARE_AGGREGATE_NAMES[0])

        expected = {fake.SHARE_AGGREGATE_NAMES[0]:
                    fake.VSERVER_AGGREGATES[fake.SHARE_AGGREGATE_NAMES[0]]}
        self.assertDictEqual(expected, result)

    def test_get_vserver_aggregate_capacities_aggregate_not_found(self):

        api_response = netapp_api.NaElement(
            fake.VSERVER_GET_RESPONSE_NO_AGGREGATES)
        self.mock_object(self.vserver_client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.vserver_client.get_vserver_aggregate_capacities()

        self.assertDictEqual({}, result)
        self.assertEqual(1, client_cmode.LOG.warning.call_count)

    def test_get_vserver_aggregate_capacities_vserver_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.vserver_client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(exception.NetAppException,
                          self.vserver_client.get_vserver_aggregate_capacities)

    def test_get_vserver_aggregate_capacities_none_requested(self):

        result = self.client.get_vserver_aggregate_capacities([])

        self.assertEqual({}, result)

    def test_get_aggregates(self):

        api_response = netapp_api.NaElement(fake.AGGR_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client._get_aggregates()

        self.client.send_iter_request.assert_has_calls([
            mock.call('aggr-get-iter', {})])
        self.assertListEqual(
            [aggr.to_string() for aggr in api_response.get_child_by_name(
                'attributes-list').get_children()],
            [aggr.to_string() for aggr in result])

    def test_get_aggregates_with_filters(self):

        api_response = netapp_api.NaElement(fake.AGGR_GET_SPACE_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        desired_attributes = {
            'aggr-attributes': {
                'aggregate-name': None,
                'aggr-space-attributes': {
                    'size-total': None,
                    'size-available': None,
                }
            }
        }

        result = self.client._get_aggregates(
            aggregate_names=fake.SHARE_AGGREGATE_NAMES,
            desired_attributes=desired_attributes)

        aggr_get_iter_args = {
            'query': {
                'aggr-attributes': {
                    'aggregate-name': '|'.join(fake.SHARE_AGGREGATE_NAMES),
                }
            },
            'desired-attributes': desired_attributes
        }

        self.client.send_iter_request.assert_has_calls([
            mock.call('aggr-get-iter', aggr_get_iter_args)])
        self.assertListEqual(
            [aggr.to_string() for aggr in api_response.get_child_by_name(
                'attributes-list').get_children()],
            [aggr.to_string() for aggr in result])

    def test_get_aggregates_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client._get_aggregates()

        self.client.send_iter_request.assert_has_calls([
            mock.call('aggr-get-iter', {})])
        self.assertListEqual([], result)

    def test_get_performance_instance_uuids(self):

        api_response = netapp_api.NaElement(
            fake.PERF_OBJECT_INSTANCE_LIST_INFO_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_performance_instance_uuids(
            'system', fake.NODE_NAME)

        expected = [fake.NODE_NAME + ':kernel:system']
        self.assertEqual(expected, result)

        perf_object_instance_list_info_iter_args = {
            'objectname': 'system',
            'query': {
                'instance-info': {
                    'uuid': fake.NODE_NAME + ':*',
                }
            }
        }
        self.client.send_request.assert_called_once_with(
            'perf-object-instance-list-info-iter',
            perf_object_instance_list_info_iter_args)

    def test_get_performance_counter_info(self):

        api_response = netapp_api.NaElement(
            fake.PERF_OBJECT_COUNTER_LIST_INFO_WAFL_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_performance_counter_info('wafl',
                                                          'cp_phase_times')

        expected = {
            'name': 'cp_phase_times',
            'base-counter': 'total_cp_msecs',
            'labels': fake.PERF_OBJECT_COUNTER_TOTAL_CP_MSECS_LABELS,
        }
        self.assertEqual(expected, result)

        perf_object_counter_list_info_args = {'objectname': 'wafl'}
        self.client.send_request.assert_called_once_with(
            'perf-object-counter-list-info',
            perf_object_counter_list_info_args)

    def test_get_performance_counter_info_not_found(self):

        api_response = netapp_api.NaElement(
            fake.PERF_OBJECT_COUNTER_LIST_INFO_WAFL_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(exception.NotFound,
                          self.client.get_performance_counter_info,
                          'wafl',
                          'invalid')

    def test_get_performance_counters(self):

        api_response = netapp_api.NaElement(
            fake.PERF_OBJECT_GET_INSTANCES_SYSTEM_RESPONSE_CMODE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        instance_uuids = [
            fake.NODE_NAMES[0] + ':kernel:system',
            fake.NODE_NAMES[1] + ':kernel:system',
        ]
        counter_names = ['avg_processor_busy']
        result = self.client.get_performance_counters('system',
                                                      instance_uuids,
                                                      counter_names)

        expected = [
            {
                'avg_processor_busy': '5674745133134',
                'instance-name': 'system',
                'instance-uuid': instance_uuids[0],
                'node-name': fake.NODE_NAMES[0],
                'timestamp': '1453412013',
            }, {
                'avg_processor_busy': '4077649009234',
                'instance-name': 'system',
                'instance-uuid': instance_uuids[1],
                'node-name': fake.NODE_NAMES[1],
                'timestamp': '1453412013'
            },
        ]
        self.assertEqual(expected, result)

        perf_object_get_instances_args = {
            'objectname': 'system',
            'instance-uuids': [
                {'instance-uuid': instance_uuid}
                for instance_uuid in instance_uuids
            ],
            'counters': [
                {'counter': counter} for counter in counter_names
            ],
        }
        self.client.send_request.assert_called_once_with(
            'perf-object-get-instances', perf_object_get_instances_args)

    def test_setup_security_services_ldap(self):

        self.mock_object(self.client, 'send_request')
        self.mock_object(self.vserver_client, 'configure_ldap')

        self.client.setup_security_services([fake.LDAP_LINUX_SECURITY_SERVICE],
                                            self.vserver_client,
                                            fake.VSERVER_NAME)

        vserver_modify_args = {
            'name-mapping-switch': [
                {'nmswitch': 'ldap'},
                {'nmswitch': 'file'},
            ],
            'name-server-switch': [
                {'nsswitch': 'ldap'},
                {'nsswitch': 'file'},
            ],
            'vserver-name': fake.VSERVER_NAME
        }
        self.client.send_request.assert_has_calls([
            mock.call('vserver-modify', vserver_modify_args)])
        self.vserver_client.configure_ldap.assert_has_calls([
            mock.call(fake.LDAP_LINUX_SECURITY_SERVICE, timeout=30)])

    def test_setup_security_services_active_directory(self):

        self.mock_object(self.client, 'send_request')
        self.mock_object(self.vserver_client, 'configure_active_directory')
        self.mock_object(self.vserver_client, 'configure_cifs_options')

        self.client.setup_security_services([fake.CIFS_SECURITY_SERVICE],
                                            self.vserver_client,
                                            fake.VSERVER_NAME)

        vserver_modify_args = {
            'name-mapping-switch': [
                {'nmswitch': 'ldap'},
                {'nmswitch': 'file'},
            ],
            'name-server-switch': [
                {'nsswitch': 'ldap'},
                {'nsswitch': 'file'},
            ],
            'vserver-name': fake.VSERVER_NAME
        }
        self.client.send_request.assert_has_calls([
            mock.call('vserver-modify', vserver_modify_args)])
        self.vserver_client.configure_active_directory.assert_has_calls([
            mock.call(fake.CIFS_SECURITY_SERVICE, fake.VSERVER_NAME)])
        self.vserver_client.configure_cifs_options.assert_has_calls([
            mock.call(fake.CIFS_SECURITY_SERVICE)])

    def test_setup_security_services_kerberos(self):

        self.mock_object(self.client, 'send_request')
        self.mock_object(self.vserver_client, 'create_kerberos_realm')
        self.mock_object(self.vserver_client, 'configure_kerberos')

        self.client.setup_security_services([fake.KERBEROS_SECURITY_SERVICE],
                                            self.vserver_client,
                                            fake.VSERVER_NAME)

        vserver_modify_args = {
            'name-mapping-switch': [
                {'nmswitch': 'ldap'},
                {'nmswitch': 'file'},
            ],
            'name-server-switch': [
                {'nsswitch': 'ldap'},
                {'nsswitch': 'file'},
            ],
            'vserver-name': fake.VSERVER_NAME
        }
        self.client.send_request.assert_has_calls([
            mock.call('vserver-modify', vserver_modify_args)])
        self.vserver_client.create_kerberos_realm.assert_has_calls([
            mock.call(fake.KERBEROS_SECURITY_SERVICE)])
        self.vserver_client.configure_kerberos.assert_has_calls([
            mock.call(fake.KERBEROS_SECURITY_SERVICE, fake.VSERVER_NAME)])

    def test_setup_security_services_invalid(self):

        self.mock_object(self.client, 'send_request')

        self.assertRaises(exception.NetAppException,
                          self.client.setup_security_services,
                          [fake.INVALID_SECURITY_SERVICE],
                          self.vserver_client,
                          fake.VSERVER_NAME)

        vserver_modify_args = {
            'name-mapping-switch': [
                {'nmswitch': 'ldap'},
                {'nmswitch': 'file'},
            ],
            'name-server-switch': [
                {'nsswitch': 'ldap'},
                {'nsswitch': 'file'},
            ],
            'vserver-name': fake.VSERVER_NAME
        }
        self.client.send_request.assert_has_calls([
            mock.call('vserver-modify', vserver_modify_args)])

    @ddt.data({'tcp-max-xfer-size': 10000}, {}, None)
    def test_enable_nfs(self, nfs_config):

        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, '_enable_nfs_protocols')
        self.mock_object(self.client, '_create_default_nfs_export_rules')
        self.mock_object(self.client, '_configure_nfs')

        self.client.enable_nfs(fake.NFS_VERSIONS, nfs_config)

        self.client.send_request.assert_called_once_with('nfs-enable')
        self.client._enable_nfs_protocols.assert_called_once_with(
            fake.NFS_VERSIONS)
        self.client._create_default_nfs_export_rules.assert_called_once_with()
        if nfs_config:
            self.client._configure_nfs.assert_called_once_with(nfs_config)
        else:
            self.client._configure_nfs.assert_not_called()

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

        self.client._enable_nfs_protocols(versions)

        nfs_service_modify_args = {
            'is-nfsv3-enabled': 'true' if v3 else 'false',
            'is-nfsv40-enabled': 'true' if v40 else 'false',
            'is-nfsv41-enabled': 'true' if v41 else 'false',
            'showmount': 'true',
            'is-v3-ms-dos-client-enabled': 'true',
            'is-nfsv3-connection-drop-enabled': 'false',
            'enable-ejukebox': 'false',
        }
        self.client.send_request.assert_called_once_with(
            'nfs-service-modify', nfs_service_modify_args)

    def test_configure_nfs(self):
        fake_nfs = {
            'tcp-max-xfer-size': 10000,
        }
        self.mock_object(self.client, 'send_request')

        self.client._configure_nfs(fake_nfs)

        self.client.send_request.assert_called_once_with(
            'nfs-service-modify', fake_nfs)

    def test_create_default_nfs_export_rules(self):

        class CopyingMock(mock.Mock):
            def __call__(self, *args, **kwargs):
                args = copy.deepcopy(args)
                kwargs = copy.deepcopy(kwargs)
                return super(CopyingMock, self).__call__(*args, **kwargs)

        self.mock_object(self.client, 'send_request', CopyingMock())

        self.client._create_default_nfs_export_rules()

        export_rule_create_args = {
            'client-match': '0.0.0.0/0',
            'policy-name': 'default',
            'ro-rule': {
                'security-flavor': 'any'
            },
            'rw-rule': {
                'security-flavor': 'never'
            }
        }
        export_rule_create_args2 = export_rule_create_args.copy()
        export_rule_create_args2['client-match'] = '::/0'
        self.client.send_request.assert_has_calls([
            mock.call('export-rule-create', export_rule_create_args),
            mock.call('export-rule-create', export_rule_create_args2)])

    @ddt.data(fake.LDAP_LINUX_SECURITY_SERVICE, fake.LDAP_AD_SECURITY_SERVICE)
    def test_configure_ldap(self, sec_service):
        self.client.features.add_feature('LDAP_LDAP_SERVERS')

        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'configure_dns')

        self.client.configure_ldap(sec_service)

        config_name = hashlib.md5(
            sec_service['id'].encode("latin-1")).hexdigest()

        ldap_client_create_args = {
            'ldap-client-config': config_name,
            'tcp-port': '389',
            'bind-password': sec_service['password'],
        }

        if sec_service.get('domain'):
            ldap_client_create_args['schema'] = 'MS-AD-BIS'
            ldap_client_create_args['bind-dn'] = (
                sec_service['user'] + '@' + sec_service['domain'])
            ldap_client_create_args['ad-domain'] = sec_service['domain']
        else:
            ldap_client_create_args['schema'] = 'RFC-2307'
            ldap_client_create_args['bind-dn'] = sec_service['user']
            ldap_client_create_args['ldap-servers'] = [{
                'string': sec_service['server']
            }]

        if sec_service.get('ou'):
            ldap_client_create_args['base-dn'] = sec_service['ou']

        ldap_config_create_args = {
            'client-config': config_name,
            'client-enabled': 'true'
        }

        self.client.send_request.assert_has_calls([
            mock.call('ldap-client-create', ldap_client_create_args),
            mock.call('ldap-config-create', ldap_config_create_args)])

    @ddt.data({'server': None, 'domain': None},
              {'server': 'fake_server', 'domain': 'fake_domain'})
    @ddt.unpack
    def test_configure_ldap_invalid_parameters(self, server, domain):
        fake_ldap_sec_service = copy.deepcopy(fake.LDAP_AD_SECURITY_SERVICE)
        fake_ldap_sec_service['server'] = server
        fake_ldap_sec_service['domain'] = domain

        self.assertRaises(exception.NetAppException,
                          self.client.configure_ldap,
                          fake_ldap_sec_service)

    def test__enable_ldap_client_timeout(self):
        mock_warning_log = self.mock_object(client_cmode.LOG, 'warning')
        na_api_error = netapp_api.NaApiError(code=netapp_api.EAPIERROR)
        mock_send_request = self.mock_object(
            self.client, 'send_request', mock.Mock(side_effect=na_api_error))

        self.assertRaises(exception.NetAppException,
                          self.client._enable_ldap_client,
                          'fake_config_name',
                          timeout=6)

        self.assertEqual(2, mock_send_request.call_count)
        self.assertEqual(2, mock_warning_log.call_count)

    def test_configure_active_directory(self):

        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'configure_dns')
        self.mock_object(self.client, 'set_preferred_dc')

        self.client.configure_active_directory(fake.CIFS_SECURITY_SERVICE,
                                               fake.VSERVER_NAME)

        cifs_server = (fake.VSERVER_NAME[0:8] +
                       '-' +
                       fake.VSERVER_NAME[-6:]).replace('_', '-').upper()

        cifs_server_create_args = {
            'admin-username': fake.CIFS_SECURITY_SERVICE['user'],
            'admin-password': fake.CIFS_SECURITY_SERVICE['password'],
            'force-account-overwrite': 'true',
            'cifs-server': cifs_server,
            'organizational-unit': fake.CIFS_SECURITY_SERVICE['ou'],
            'domain': fake.CIFS_SECURITY_SERVICE['domain'],
        }

        self.client.configure_dns.assert_called_with(
            fake.CIFS_SECURITY_SERVICE)
        self.client.set_preferred_dc.assert_called_with(
            fake.CIFS_SECURITY_SERVICE)
        self.client.send_request.assert_has_calls([
            mock.call('cifs-server-create', cifs_server_create_args)])

    def test_configure_active_directory_with_ad_site(self):

        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'configure_dns')
        self.mock_object(self.client, 'set_preferred_dc')

        self.client.configure_active_directory(fake.CIFS_SECURITY_SERVICE_3,
                                               fake.VSERVER_NAME)

        cifs_server = (fake.VSERVER_NAME[0:8] +
                       '-' +
                       fake.VSERVER_NAME[-6:]).replace('_', '-').upper()

        cifs_server_create_args = {
            'admin-username': fake.CIFS_SECURITY_SERVICE_3['user'],
            'admin-password': fake.CIFS_SECURITY_SERVICE_3['password'],
            'force-account-overwrite': 'true',
            'cifs-server': cifs_server,
            'organizational-unit': fake.CIFS_SECURITY_SERVICE_3['ou'],
            'domain': fake.CIFS_SECURITY_SERVICE_3['domain'],
            'default-site': fake.CIFS_SECURITY_SERVICE_3['default_ad_site'],
        }

        self.client.configure_dns.assert_called_with(
            fake.CIFS_SECURITY_SERVICE_3)
        self.client.set_preferred_dc.assert_called_with(
            fake.CIFS_SECURITY_SERVICE_3)
        self.client.send_request.assert_has_calls([
            mock.call('cifs-server-create', cifs_server_create_args)])

    def test_configure_active_directory_api_error(self):

        self.mock_object(self.client, 'send_request', self._mock_api_error())
        self.mock_object(self.client, 'configure_dns')

        self.assertRaises(exception.NetAppException,
                          self.client.configure_active_directory,
                          fake.CIFS_SECURITY_SERVICE,
                          fake.VSERVER_NAME)

    def test_create_kerberos_realm(self):
        self.client.features.add_feature('KERBEROS_VSERVER')
        self.mock_object(self.client, 'send_request')

        self.client.create_kerberos_realm(fake.KERBEROS_SECURITY_SERVICE)

        kerberos_realm_create_args = {
            'admin-server-ip': fake.KERBEROS_SECURITY_SERVICE['server'],
            'admin-server-port': '749',
            'clock-skew': '5',
            'comment': '',
            'kdc-ip': fake.KERBEROS_SECURITY_SERVICE['server'],
            'kdc-port': '88',
            'kdc-vendor': 'other',
            'password-server-ip': fake.KERBEROS_SECURITY_SERVICE['server'],
            'password-server-port': '464',
            'realm': fake.KERBEROS_SECURITY_SERVICE['domain'].upper()
        }

        self.client.send_request.assert_has_calls([
            mock.call('kerberos-realm-create', kerberos_realm_create_args)])

    def test_create_kerberos_realm_already_present(self):
        self.client.features.add_feature('KERBEROS_VSERVER')
        self.mock_object(self.client,
                         'send_request',
                         self._mock_api_error(code=netapp_api.EDUPLICATEENTRY))

        self.client.create_kerberos_realm(fake.KERBEROS_SECURITY_SERVICE)

        kerberos_realm_create_args = {
            'admin-server-ip': fake.KERBEROS_SECURITY_SERVICE['server'],
            'admin-server-port': '749',
            'clock-skew': '5',
            'comment': '',
            'kdc-ip': fake.KERBEROS_SECURITY_SERVICE['server'],
            'kdc-port': '88',
            'kdc-vendor': 'other',
            'password-server-ip': fake.KERBEROS_SECURITY_SERVICE['server'],
            'password-server-port': '464',
            'realm': fake.KERBEROS_SECURITY_SERVICE['domain'].upper()
        }

        self.client.send_request.assert_has_calls([
            mock.call('kerberos-realm-create', kerberos_realm_create_args)])
        self.assertEqual(1, client_cmode.LOG.debug.call_count)

    def test_create_kerberos_realm_api_error(self):
        self.client.features.add_feature('KERBEROS_VSERVER')
        self.mock_object(self.client, 'send_request', self._mock_api_error())

        self.assertRaises(exception.NetAppException,
                          self.client.create_kerberos_realm,
                          fake.KERBEROS_SECURITY_SERVICE)

    def test_update_kerberos_realm(self):
        self.client.features.add_feature('KERBEROS_VSERVER')
        self.mock_object(self.client, 'send_request')

        self.client.update_kerberos_realm(fake.KERBEROS_SECURITY_SERVICE)

        kerberos_realm_create_args = {
            'admin-server-ip': fake.KERBEROS_SECURITY_SERVICE['server'],
            'kdc-ip': fake.KERBEROS_SECURITY_SERVICE['server'],
            'password-server-ip': fake.KERBEROS_SECURITY_SERVICE['server'],
            'realm': fake.KERBEROS_SECURITY_SERVICE['domain'].upper(),
        }

        self.client.send_request.assert_has_calls([
            mock.call('kerberos-realm-modify',
                      kerberos_realm_create_args)])

    def test_update_kerberos_realm_failure(self):
        self.client.features.add_feature('KERBEROS_VSERVER')
        self.mock_object(self.client, 'send_request', self._mock_api_error())

        self.assertRaises(exception.NetAppException,
                          self.client.update_kerberos_realm,
                          fake.KERBEROS_SECURITY_SERVICE)

        kerberos_realm_create_args = {
            'admin-server-ip': fake.KERBEROS_SECURITY_SERVICE['server'],
            'kdc-ip': fake.KERBEROS_SECURITY_SERVICE['server'],
            'password-server-ip': fake.KERBEROS_SECURITY_SERVICE['server'],
            'realm': fake.KERBEROS_SECURITY_SERVICE['domain'].upper(),
        }

        self.client.send_request.assert_has_calls([
            mock.call('kerberos-realm-modify',
                      kerberos_realm_create_args)])

    def test_configure_kerberos(self):
        self.client.features.add_feature('KERBEROS_VSERVER')
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'configure_dns')
        self.mock_object(self.client,
                         'list_network_interfaces',
                         mock.Mock(return_value=['lif1', 'lif2']))

        self.client.configure_kerberos(
            fake.KERBEROS_SECURITY_SERVICE, fake.VSERVER_NAME)

        spn = self.client._get_kerberos_service_principal_name(
            fake.KERBEROS_SECURITY_SERVICE, fake.VSERVER_NAME)

        kerberos_config_modify_args1 = {
            'admin-password': fake.KERBEROS_SECURITY_SERVICE['password'],
            'admin-user-name': fake.KERBEROS_SECURITY_SERVICE['user'],
            'interface-name': 'lif1',
            'is-kerberos-enabled': 'true',
            'service-principal-name': spn
        }
        kerberos_config_modify_args2 = {
            'admin-password': fake.KERBEROS_SECURITY_SERVICE['password'],
            'admin-user-name': fake.KERBEROS_SECURITY_SERVICE['user'],
            'interface-name': 'lif2',
            'is-kerberos-enabled': 'true',
            'service-principal-name': spn
        }

        self.client.configure_dns.assert_called_with(
            fake.KERBEROS_SECURITY_SERVICE)
        self.client.send_request.assert_has_calls([
            mock.call('kerberos-config-modify',
                      kerberos_config_modify_args1),
            mock.call('kerberos-config-modify',
                      kerberos_config_modify_args2)])

    def test_configure_kerberos_no_network_interfaces(self):
        self.client.features.add_feature('KERBEROS_VSERVER')
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'configure_dns')
        self.mock_object(self.client,
                         'list_network_interfaces',
                         mock.Mock(return_value=[]))

        self.assertRaises(exception.NetAppException,
                          self.client.configure_kerberos,
                          fake.KERBEROS_SECURITY_SERVICE,
                          fake.VSERVER_NAME)

        self.client.configure_dns.assert_called_with(
            fake.KERBEROS_SECURITY_SERVICE)

    def test_disable_kerberos(self):
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client,
                         'list_network_interfaces',
                         mock.Mock(return_value=['lif1', 'lif2']))

        self.client.disable_kerberos(fake.KERBEROS_SECURITY_SERVICE)

        kerberos_config_modify_args1 = {
            'admin-password': fake.KERBEROS_SECURITY_SERVICE['password'],
            'admin-user-name': fake.KERBEROS_SECURITY_SERVICE['user'],
            'interface-name': 'lif1',
            'is-kerberos-enabled': 'false',
        }
        kerberos_config_modify_args2 = {
            'admin-password': fake.KERBEROS_SECURITY_SERVICE['password'],
            'admin-user-name': fake.KERBEROS_SECURITY_SERVICE['user'],
            'interface-name': 'lif2',
            'is-kerberos-enabled': 'false',
        }

        self.client.send_request.assert_has_calls([
            mock.call('kerberos-config-modify',
                      kerberos_config_modify_args1),
            mock.call('kerberos-config-modify',
                      kerberos_config_modify_args2)])
        self.client.list_network_interfaces.assert_called_once()

    def test_disable_kerberos_already_disabled(self):
        self.mock_object(self.client, 'send_request',
                         self._mock_api_error(
                             code=netapp_api.EAPIERROR,
                             message='Kerberos is already disabled'))
        self.mock_object(self.client,
                         'list_network_interfaces',
                         mock.Mock(return_value=['lif1']))

        self.client.disable_kerberos(fake.KERBEROS_SECURITY_SERVICE)

        kerberos_config_modify_args = {
            'admin-password': fake.KERBEROS_SECURITY_SERVICE['password'],
            'admin-user-name': fake.KERBEROS_SECURITY_SERVICE['user'],
            'interface-name': 'lif1',
            'is-kerberos-enabled': 'false',
        }

        self.client.send_request.assert_called_once_with(
            'kerberos-config-modify', kerberos_config_modify_args)
        self.client.list_network_interfaces.assert_called_once()

    def test_is_kerberos_enabled(self):
        self.client.features.add_feature('KERBEROS_VSERVER')
        api_response = netapp_api.NaElement(
            fake.KERBEROS_CONFIG_GET_RESPONSE)
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))
        self.mock_object(self.client,
                         'list_network_interfaces',
                         mock.Mock(return_value=['lif1']))

        result = self.client.is_kerberos_enabled()

        kerberos_config_get_args = {
            'interface-name': 'lif1',
            'desired-attributes': {
                'kerberos-config-info': {
                    'is-kerberos-enabled': None,
                }
            }
        }

        self.assertTrue(result)
        self.client.send_request.assert_called_once_with(
            'kerberos-config-get', kerberos_config_get_args)
        self.client.list_network_interfaces.assert_called_once()

    def test_get_kerberos_service_principal_name(self):

        spn = self.client._get_kerberos_service_principal_name(
            fake.KERBEROS_SECURITY_SERVICE, fake.VSERVER_NAME
        )
        self.assertEqual(fake.KERBEROS_SERVICE_PRINCIPAL_NAME, spn)

    def test_configure_dns_for_active_directory(self):

        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'get_dns_config',
                         mock.Mock(return_value={}))

        self.client.configure_dns(fake.CIFS_SECURITY_SERVICE)

        net_dns_create_args = {
            'domains': [{'string': fake.CIFS_SECURITY_SERVICE['domain']}],
            'name-servers': [{
                'ip-address': fake.CIFS_SECURITY_SERVICE['dns_ip']
            }],
            'dns-state': 'enabled'
        }

        self.client.send_request.assert_has_calls([
            mock.call('net-dns-create', net_dns_create_args)])

    def test_configure_dns_multiple_dns_ip(self):

        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'get_dns_config',
                         mock.Mock(return_value={}))
        mock_dns_ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3']
        security_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE)
        security_service['dns_ip'] = ', '.join(mock_dns_ips)

        self.client.configure_dns(security_service)

        self.client.send_request.assert_called_once()

    def test_configure_dns_for_kerberos(self):

        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'get_dns_config',
                         mock.Mock(return_value={}))

        self.client.configure_dns(fake.KERBEROS_SECURITY_SERVICE)

        net_dns_create_args = {
            'domains': [{'string': fake.KERBEROS_SECURITY_SERVICE['domain']}],
            'name-servers': [{
                'ip-address': fake.KERBEROS_SECURITY_SERVICE['dns_ip']
            }],
            'dns-state': 'enabled'
        }

        self.client.send_request.assert_has_calls([
            mock.call('net-dns-create', net_dns_create_args)])

    def test_configure_dns_already_present(self):
        dns_config = {
            'dns-state': 'enabled',
            'domains': [fake.KERBEROS_SECURITY_SERVICE['domain']],
            'dns-ips': [fake.KERBEROS_SECURITY_SERVICE['dns_ip']],
        }
        self.mock_object(self.client, 'get_dns_config',
                         mock.Mock(return_value=dns_config))
        self.mock_object(self.client, 'send_request')

        self.client.configure_dns(fake.KERBEROS_SECURITY_SERVICE)

        net_dns_create_args = {
            'domains': [{'string': fake.KERBEROS_SECURITY_SERVICE['domain']}],
            'name-servers': [{
                'ip-address': fake.KERBEROS_SECURITY_SERVICE['dns_ip']
            }],
            'dns-state': 'enabled'
        }

        self.client.send_request.assert_has_calls([
            mock.call('net-dns-modify', net_dns_create_args)])

    def test_update_dns_configuration(self):
        fake_configured_dns = {
            'dns-state': 'enabled',
            'domains': ['fake_domain_2'],
            'dns-ips': ['fake_dns_ip_2']
        }
        self.mock_object(self.client, 'get_dns_config',
                         mock.Mock(return_value=fake_configured_dns))
        self.mock_object(self.client, 'send_request')

        self.client.configure_dns(fake.KERBEROS_SECURITY_SERVICE)
        domains = set()
        domains.add(fake_configured_dns['domains'][0])
        domains.add(fake.KERBEROS_SECURITY_SERVICE['domain'])

        dns_ips = set()
        dns_ips.add(fake_configured_dns['dns-ips'][0])
        dns_ips.add(fake.KERBEROS_SECURITY_SERVICE['dns_ip'])

        net_dns_create_args = {
            'domains': [{'string': domain} for domain in domains],
            'dns-state': 'enabled',
            'name-servers': [{'ip-address': dns_ip} for dns_ip in dns_ips]
        }

        self.client.send_request.assert_has_calls([
            mock.call('net-dns-modify', net_dns_create_args)])

    def test_configure_dns_api_error(self):

        self.mock_object(self.client, 'send_request', self._mock_api_error())
        self.mock_object(self.client, 'get_dns_config',
                         mock.Mock(return_value={}))

        self.assertRaises(exception.NetAppException,
                          self.client.configure_dns,
                          fake.KERBEROS_SECURITY_SERVICE)

    def test_get_dns_configuration(self):
        api_response = netapp_api.NaElement(
            fake.DNS_CONFIG_GET_RESPONSE)
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_dns_config()

        expected_result = {
            'dns-state': 'enabled',
            'domains': ['fake_domain.com'],
            'dns-ips': ['fake_dns_1', 'fake_dns_2']
        }
        self.assertEqual(expected_result, result)
        self.client.send_request.assert_called_once_with('net-dns-get', {})

    @ddt.data(
        {
            'server': '',
            'check_feature': False
        },
        {
            'server': ['10.0.0.2', '10.0.0.3'],
            'check_feature': False
        },
        {
            'server': '10.0.0.1',
            'check_feature': False
        },
        {
            'server': '10.0.0.1',
            'check_feature': True
        }
    )
    @ddt.unpack
    def test_set_preferred_dc(self, server, check_feature):
        if check_feature:
            self.client.features.add_feature('CIFS_DC_ADD_SKIP_CHECK')

        self.mock_object(self.client, 'send_request')
        security_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE)
        security_service['server'] = ', '.join(server)

        self.client.set_preferred_dc(security_service)

        if server == '':
            self.client.send_request.assert_not_called()
        else:
            preferred_dc_add_args = {
                'domain': fake.CIFS_SECURITY_SERVICE['domain'],
                'preferred-dc': [{'string': dc_ip} for dc_ip in server]
            }

            if check_feature:
                preferred_dc_add_args['skip-config-validation'] = 'false'

            self.client.send_request.assert_has_calls([
                mock.call('cifs-domain-preferred-dc-add',
                          preferred_dc_add_args)])

    def test_set_preferred_dc_api_error(self):

        self.mock_object(self.client, 'send_request', self._mock_api_error())
        security_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE)
        security_service['server'] = 'fake_server'

        self.assertRaises(exception.NetAppException,
                          self.client.set_preferred_dc,
                          security_service)

    def test_remove_preferred_dcs(self):
        self.mock_object(self.client, 'send_request')
        security_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE)

        self.client.remove_preferred_dcs(security_service)

        preferred_dc_add_args = {
            'domain': security_service['domain'],
        }
        self.client.send_request.assert_has_calls([
            mock.call('cifs-domain-preferred-dc-remove',
                      preferred_dc_add_args)])

    def test_remove_preferred_dcs_error(self):
        self.mock_object(self.client, 'send_request', self._mock_api_error())
        security_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE)

        self.assertRaises(exception.NetAppException,
                          self.client.remove_preferred_dcs,
                          security_service)

        preferred_dc_add_args = {
            'domain': security_service['domain'],
        }
        self.client.send_request.assert_has_calls([
            mock.call('cifs-domain-preferred-dc-remove',
                      preferred_dc_add_args)])

    @ddt.data(True, False)
    def test_create_volume(self, set_max_files):
        self.client.features.add_feature('ADAPTIVE_QOS')
        self.mock_object(self.client, 'set_volume_max_files')
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'update_volume_efficiency_attributes')
        self.mock_object(
            self.client, '_get_create_volume_api_args',
            mock.Mock(return_value={}))

        self.client.create_volume(
            fake.SHARE_AGGREGATE_NAME, fake.SHARE_NAME, 100,
            max_files=fake.MAX_FILES if set_max_files else None)

        volume_create_args = {
            'containing-aggr-name': fake.SHARE_AGGREGATE_NAME,
            'size': '100g',
            'volume': fake.SHARE_NAME,
        }

        self.client._get_create_volume_api_args.assert_called_once_with(
            fake.SHARE_NAME, False, None, None, None, 'rw', None, False, None)
        self.client.send_request.assert_called_with('volume-create',
                                                    volume_create_args)
        (self.client.update_volume_efficiency_attributes.
            assert_called_once_with(fake.SHARE_NAME, False, False))
        if set_max_files:
            self.client.set_volume_max_files.assert_called_once_with(
                fake.SHARE_NAME, fake.MAX_FILES)
        else:
            self.client.set_volume_max_files.assert_not_called()

    @ddt.data(True, False)
    def test_create_volume_thin_provisioned(self, thin_provisioned):

        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'update_volume_efficiency_attributes')

        self.client.create_volume(
            fake.SHARE_AGGREGATE_NAME, fake.SHARE_NAME, 100,
            thin_provisioned=thin_provisioned)

        volume_create_args = {
            'containing-aggr-name': fake.SHARE_AGGREGATE_NAME,
            'size': '100g',
            'volume': fake.SHARE_NAME,
            'volume-type': 'rw',
            'junction-path': '/%s' % fake.SHARE_NAME,
            'space-reserve': ('none' if thin_provisioned else 'volume'),
            'encrypt': 'false'
        }

        self.client.send_request.assert_called_once_with('volume-create',
                                                         volume_create_args)

    def test_create_volume_adaptive_not_supported(self):

        self.client.features.add_feature('ADAPTIVE_QOS', supported=False)
        self.mock_object(self.client, 'send_request')
        self.assertRaises(exception.NetAppException,
                          self.client.create_volume,
                          fake.SHARE_AGGREGATE_NAME,
                          fake.SHARE_NAME,
                          100,
                          adaptive_qos_policy_group='fake')
        self.client.send_request.assert_not_called()

    @ddt.data(True, False)
    def test_create_volume_async(self, auto_provisioned):
        api_response = netapp_api.NaElement(fake.ASYNC_OPERATION_RESPONSE)
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))
        self.mock_object(
            self.client, '_get_create_volume_api_args',
            mock.Mock(return_value={}))

        result = self.client.create_volume_async(
            [fake.SHARE_AGGREGATE_NAME], fake.SHARE_NAME, 1,
            auto_provisioned=auto_provisioned)

        volume_create_args = {
            'size': 1073741824,
            'volume-name': fake.SHARE_NAME,
        }
        if auto_provisioned:
            volume_create_args['auto-provision-as'] = 'flexgroup'
        else:
            volume_create_args['aggr-list'] = [
                {'aggr-name': fake.SHARE_AGGREGATE_NAME}]

        expected_result = {
            'jobid': '123',
            'error-code': None,
            'error-message': None,
        }

        self.client._get_create_volume_api_args.assert_called_once_with(
            fake.SHARE_NAME, False, None, None, None, 'rw', None, False, None)
        self.client.send_request.assert_called_with('volume-create-async',
                                                    volume_create_args)
        self.assertEqual(expected_result, result)

    def test_create_volume_async_adaptive_not_supported(self):

        self.client.features.add_feature('ADAPTIVE_QOS', supported=False)
        self.mock_object(self.client, 'send_request')
        self.assertRaises(exception.NetAppException,
                          self.client.create_volume_async,
                          [fake.SHARE_AGGREGATE_NAME],
                          fake.SHARE_NAME,
                          100,
                          adaptive_qos_policy_group='fake')
        self.client.send_request.assert_not_called()

    def test_get_create_volume_api_args_with_extra_specs(self):

        self.client.features.add_feature('FLEXVOL_ENCRYPTION')
        volume_type = 'rw'
        thin_provisioned = False
        snapshot_policy = 'default'
        language = 'en-US'
        reserve = 15
        qos_name = 'fake_qos'
        encrypt = True
        qos_adaptive_name = 'fake_adaptive_qos'

        result_api_args = self.client._get_create_volume_api_args(
            fake.SHARE_NAME, thin_provisioned, snapshot_policy, language,
            reserve, volume_type, qos_name, encrypt, qos_adaptive_name)

        expected_api_args = {
            'volume-type': volume_type,
            'junction-path': '/fake_share',
            'space-reserve': 'volume',
            'snapshot-policy': snapshot_policy,
            'language-code': language,
            'percentage-snapshot-reserve': str(reserve),
            'qos-policy-group-name': qos_name,
            'qos-adaptive-policy-group-name': qos_adaptive_name,
            'encrypt': 'true',
        }
        self.assertEqual(expected_api_args, result_api_args)

    def test_get_create_volume_api_args_no_extra_specs(self):

        self.client.features.add_feature('FLEXVOL_ENCRYPTION')
        volume_type = 'dp'
        thin_provisioned = False
        snapshot_policy = None
        language = None
        reserve = None
        qos_name = None
        encrypt = False
        qos_adaptive_name = None

        result_api_args = self.client._get_create_volume_api_args(
            fake.SHARE_NAME, thin_provisioned, snapshot_policy, language,
            reserve, volume_type, qos_name, encrypt, qos_adaptive_name)

        expected_api_args = {
            'volume-type': volume_type,
            'space-reserve': 'volume',
            'encrypt': 'false'
        }
        self.assertEqual(expected_api_args, result_api_args)

    def test_get_create_volume_api_args_encrypted_not_supported(self):

        encrypt = True
        self.assertRaises(exception.NetAppException,
                          self.client._get_create_volume_api_args,
                          fake.SHARE_NAME, True, 'default', 'en-US',
                          15, 'rw', 'fake_qos', encrypt, 'fake_qos_adaptive')

    def test_is_flexvol_encrypted_unsupported(self):

        self.client.features.add_feature('FLEXVOL_ENCRYPTION', supported=False)

        result = self.client.is_flexvol_encrypted(fake.SHARE_NAME,
                                                  fake.VSERVER_NAME)

        self.assertFalse(result)

    def test_is_flexvol_encrypted_no_records_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.is_flexvol_encrypted(fake.SHARE_NAME,
                                                  fake.VSERVER_NAME)

        self.assertFalse(result)

    def test_is_flexvol_encrypted(self):

        self.client.features.add_feature('FLEXVOL_ENCRYPTION', supported=True)
        api_response = netapp_api.NaElement(
            fake.GET_VOLUME_FOR_ENCRYPTED_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.is_flexvol_encrypted(fake.SHARE_NAME,
                                                  fake.VSERVER_NAME)

        volume_get_iter_args = {
            'query': {
                'volume-attributes': {
                    'encrypt': 'true',
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME,
                        'owning-vserver-name': fake.VSERVER_NAME,
                    }
                }
            },
            'desired-attributes': {
                'volume-attributes': {
                    'encrypt': None,
                }
            }
        }

        self.client.send_iter_request.assert_called_once_with(
            'volume-get-iter', volume_get_iter_args)

        self.assertTrue(result)

    def test_is_flexvol_encrypted_8_x_system_version_response(self):

        self.client.features.add_feature('FLEXVOL_ENCRYPTION', supported=True)
        api_response = netapp_api.NaElement(
            fake.GET_VOLUME_FOR_ENCRYPTED_OLD_SYS_VERSION_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.is_flexvol_encrypted(fake.SHARE_NAME,
                                                  fake.VSERVER_NAME)

        volume_get_iter_args = {
            'query': {
                'volume-attributes': {
                    'encrypt': 'true',
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME,
                        'owning-vserver-name': fake.VSERVER_NAME,
                    }
                }
            },
            'desired-attributes': {
                'volume-attributes': {
                    'encrypt': None,
                }
            }
        }

        self.client.send_iter_request.assert_called_once_with(
            'volume-get-iter', volume_get_iter_args)

        self.assertFalse(result)

    def test_enable_dedup(self):

        self.mock_object(self.client, 'send_request')

        self.client.enable_dedup(fake.SHARE_NAME)

        sis_enable_args = {'path': '/vol/%s' % fake.SHARE_NAME}

        self.client.send_request.assert_called_once_with('sis-enable',
                                                         sis_enable_args)

    def test_disable_dedup(self):

        self.mock_object(self.client, 'send_request')

        self.client.disable_dedup(fake.SHARE_NAME)

        sis_disable_args = {'path': '/vol/%s' % fake.SHARE_NAME}

        self.client.send_request.assert_called_once_with('sis-disable',
                                                         sis_disable_args)

    def test_enable_compression(self):

        self.mock_object(self.client, 'send_request')

        self.client.enable_compression(fake.SHARE_NAME)

        sis_set_config_args = {
            'path': '/vol/%s' % fake.SHARE_NAME,
            'enable-compression': 'true'
        }

        self.client.send_request.assert_called_once_with('sis-set-config',
                                                         sis_set_config_args)

    def test_disable_compression(self):

        self.mock_object(self.client, 'send_request')

        self.client.disable_compression(fake.SHARE_NAME)

        sis_set_config_args = {
            'path': '/vol/%s' % fake.SHARE_NAME,
            'enable-compression': 'false'
        }

        self.client.send_request.assert_called_once_with('sis-set-config',
                                                         sis_set_config_args)

    def test_enable_dedupe_async(self):
        self.mock_object(self.client.connection, 'send_request')

        self.client.enable_dedupe_async(fake.SHARE_NAME)

        sis_enable_args = {'volume-name': fake.SHARE_NAME}

        self.client.connection.send_request.assert_called_once_with(
            'sis-enable-async', sis_enable_args)

    def test_disable_dedupe_async(self):

        self.mock_object(self.client.connection, 'send_request')

        self.client.disable_dedupe_async(fake.SHARE_NAME)

        sis_enable_args = {'volume-name': fake.SHARE_NAME}

        self.client.connection.send_request.assert_called_once_with(
            'sis-disable-async', sis_enable_args)

    def test_enable_compression_async(self):
        self.mock_object(self.client.connection, 'send_request')

        self.client.enable_compression_async(fake.SHARE_NAME)

        sis_set_config_args = {
            'volume-name': fake.SHARE_NAME,
            'enable-compression': 'true'
        }

        self.client.connection.send_request.assert_called_once_with(
            'sis-set-config-async', sis_set_config_args)

    def test_disable_compression_async(self):
        self.mock_object(self.client.connection, 'send_request')

        self.client.disable_compression_async(fake.SHARE_NAME)

        sis_set_config_args = {
            'volume-name': fake.SHARE_NAME,
            'enable-compression': 'false'
        }

        self.client.connection.send_request.assert_called_once_with(
            'sis-set-config-async', sis_set_config_args)

    def test_get_volume_efficiency_status(self):

        api_response = netapp_api.NaElement(fake.SIS_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_volume_efficiency_status(fake.SHARE_NAME)

        sis_get_iter_args = {
            'query': {
                'sis-status-info': {
                    'path': '/vol/%s' % fake.SHARE_NAME,
                },
            },
            'desired-attributes': {
                'sis-status-info': {
                    'state': None,
                    'is-compression-enabled': None,
                },
            },
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('sis-get-iter', sis_get_iter_args)])

        expected = {'dedupe': True, 'compression': True}
        self.assertDictEqual(expected, result)

    def test_get_volume_efficiency_status_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_volume_efficiency_status(fake.SHARE_NAME)

        expected = {'dedupe': False, 'compression': False}
        self.assertDictEqual(expected, result)

    def test_set_volume_max_files(self):

        self.mock_object(self.client, 'send_request')

        self.client.set_volume_max_files(fake.SHARE_NAME, fake.MAX_FILES)

        volume_modify_iter_api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME,
                    },
                },
            },
            'attributes': {
                'volume-attributes': {
                    'volume-inode-attributes': {
                        'files-total': fake.MAX_FILES,
                    },
                },
            },
        }

        self.client.send_request.assert_called_once_with(
            'volume-modify-iter', volume_modify_iter_api_args)

    def test_set_volume_name(self):

        self.mock_object(self.client, 'send_request')

        self.client.set_volume_name(fake.SHARE_NAME, 'new_name')

        volume_rename_api_args = {
            'volume': fake.SHARE_NAME,
            'new-volume-name': 'new_name',
        }

        self.client.send_request.assert_called_once_with(
            'volume-rename', volume_rename_api_args)

    def test_rename_vserver(self):

        vserver_api_args = {
            'vserver-name': fake.VSERVER_NAME,
            'new-name': fake.VSERVER_NAME_2,
        }
        self.mock_object(self.client, 'send_request')

        self.client.rename_vserver(fake.VSERVER_NAME, fake.VSERVER_NAME_2)

        self.client.send_request.assert_called_once_with(
            'vserver-rename', vserver_api_args
        )

    @ddt.data(True, False)
    def test_modify_volume_no_optional_args(self, is_flexgroup):

        self.mock_object(self.client, 'send_request')
        mock_update_volume_efficiency_attributes = self.mock_object(
            self.client, 'update_volume_efficiency_attributes')

        aggr = fake.SHARE_AGGREGATE_NAME
        if is_flexgroup:
            aggr = list(fake.SHARE_AGGREGATE_NAMES)

        self.client.modify_volume(aggr, fake.SHARE_NAME)

        volume_modify_iter_api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME,
                    },
                },
            },
            'attributes': {
                'volume-attributes': {
                    'volume-inode-attributes': {},
                    'volume-language-attributes': {},
                    'volume-snapshot-attributes': {},
                    'volume-space-attributes': {
                        'space-guarantee': 'volume',
                    },
                    'volume-autosize-attributes': {},
                },
            },
        }

        if is_flexgroup:
            volume_modify_iter_api_args['query']['volume-attributes'][
                'volume-id-attributes']['aggr-list'] = [
                {'aggr-name': aggr[0]}, {'aggr-name': aggr[1]}]
        else:
            volume_modify_iter_api_args['query']['volume-attributes'][
                'volume-id-attributes'][
                'containing-aggregate-name'] = aggr

        self.client.send_request.assert_called_once_with(
            'volume-modify-iter', volume_modify_iter_api_args)
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

        volume_modify_iter_api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'containing-aggregate-name': fake.SHARE_AGGREGATE_NAME,
                        'name': fake.SHARE_NAME,
                    },
                },
            },
            'attributes': {
                'volume-attributes': {
                    'volume-inode-attributes': {
                        'files-total': fake.MAX_FILES,
                    },
                    'volume-language-attributes': {
                        'language': fake.LANGUAGE,
                    },
                    'volume-snapshot-attributes': {
                        'snapshot-policy': fake.SNAPSHOT_POLICY_NAME,
                        'snapdir-access-enabled': 'false'
                    },
                    'volume-space-attributes': {
                        'space-guarantee': 'none',
                    },
                    'volume-autosize-attributes': fake.VOLUME_AUTOSIZE_ATTRS,
                },
            },
        }
        if qos_group:
            qos_update = {
                'volume-qos-attributes': {
                    'policy-group-name': qos_group,
                },
            }
            volume_modify_iter_api_args[
                'attributes']['volume-attributes'].update(qos_update)
        if adaptive_qos_group:
            qos_update = {
                'volume-qos-attributes': {
                    'adaptive-policy-group-name': adaptive_qos_group,
                },
            }
            volume_modify_iter_api_args[
                'attributes']['volume-attributes'].update(qos_update)

        self.client.send_request.assert_called_once_with(
            'volume-modify-iter', volume_modify_iter_api_args)
        mock_update_volume_efficiency_attributes.assert_called_once_with(
            fake.SHARE_NAME, True, False, is_flexgroup=False)

    @ddt.data(
        {'existing': (True, True), 'desired': (True, True), 'fg': False},
        {'existing': (True, True), 'desired': (False, False), 'fg': False},
        {'existing': (True, True), 'desired': (True, False), 'fg': False},
        {'existing': (True, False), 'desired': (True, False), 'fg': False},
        {'existing': (True, False), 'desired': (False, False), 'fg': False},
        {'existing': (True, False), 'desired': (True, True), 'fg': False},
        {'existing': (False, False), 'desired': (False, False), 'fg': False},
        {'existing': (False, False), 'desired': (True, False), 'fg': False},
        {'existing': (False, False), 'desired': (True, True), 'fg': False},
        {'existing': (True, True), 'desired': (True, True), 'fg': True},
        {'existing': (True, True), 'desired': (False, False), 'fg': True},
        {'existing': (True, True), 'desired': (True, False), 'fg': True},
        {'existing': (True, False), 'desired': (True, False), 'fg': True},
        {'existing': (True, False), 'desired': (False, False), 'fg': True},
        {'existing': (True, False), 'desired': (True, True), 'fg': True},
        {'existing': (False, False), 'desired': (False, False), 'fg': True},
        {'existing': (False, False), 'desired': (True, False), 'fg': True},
        {'existing': (False, False), 'desired': (True, True), 'fg': True},
    )
    @ddt.unpack
    def test_update_volume_efficiency_attributes(self, existing, desired, fg):

        existing_dedupe = existing[0]
        existing_compression = existing[1]
        desired_dedupe = desired[0]
        desired_compression = desired[1]

        self.mock_object(
            self.client,
            'get_volume_efficiency_status',
            mock.Mock(return_value={'dedupe': existing_dedupe,
                                    'compression': existing_compression}))
        mock_enable_compression = self.mock_object(self.client,
                                                   'enable_compression')
        mock_enable_compression_async = self.mock_object(
            self.client, 'enable_compression_async')
        mock_disable_compression = self.mock_object(self.client,
                                                    'disable_compression')
        mock_disable_compression_async = self.mock_object(
            self.client, 'disable_compression_async')
        mock_enable_dedup = self.mock_object(self.client, 'enable_dedup')
        mock_enable_dedup_async = self.mock_object(self.client,
                                                   'enable_dedupe_async')
        mock_disable_dedup = self.mock_object(self.client, 'disable_dedup')
        mock_disable_dedup_async = self.mock_object(self.client,
                                                    'disable_dedupe_async')

        self.client.update_volume_efficiency_attributes(
            fake.SHARE_NAME, desired_dedupe, desired_compression,
            is_flexgroup=fg)

        if existing_dedupe == desired_dedupe:
            if fg:
                self.assertFalse(mock_enable_dedup_async.called)
                self.assertFalse(mock_disable_dedup_async.called)
            else:
                self.assertFalse(mock_enable_dedup.called)
                self.assertFalse(mock_disable_dedup.called)
        elif existing_dedupe and not desired_dedupe:
            if fg:
                self.assertFalse(mock_enable_dedup_async.called)
                self.assertTrue(mock_disable_dedup_async.called)
            else:
                self.assertFalse(mock_enable_dedup.called)
                self.assertTrue(mock_disable_dedup.called)
        elif not existing_dedupe and desired_dedupe:
            if fg:
                self.assertTrue(mock_enable_dedup_async.called)
                self.assertFalse(mock_disable_dedup_async.called)
            else:
                self.assertTrue(mock_enable_dedup.called)
                self.assertFalse(mock_disable_dedup.called)

        if existing_compression == desired_compression:
            if fg:
                self.assertFalse(mock_enable_compression_async.called)
                self.assertFalse(mock_disable_compression_async.called)
            else:
                self.assertFalse(mock_enable_compression.called)
                self.assertFalse(mock_disable_compression.called)
        elif existing_compression and not desired_compression:
            if fg:
                self.assertFalse(mock_enable_compression_async.called)
                self.assertTrue(mock_disable_compression_async.called)
            else:
                self.assertFalse(mock_enable_compression.called)
                self.assertTrue(mock_disable_compression.called)
        elif not existing_compression and desired_compression:
            if fg:
                self.assertTrue(mock_enable_compression_async.called)
                self.assertFalse(mock_disable_compression_async.called)
            else:
                self.assertTrue(mock_enable_compression.called)
                self.assertFalse(mock_disable_compression.called)

    def test_set_volume_size(self):

        api_response = netapp_api.NaElement(fake.VOLUME_MODIFY_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.client.set_volume_size(fake.SHARE_NAME, 10)

        volume_modify_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME
                    }
                }
            },
            'attributes': {
                'volume-attributes': {
                    'volume-space-attributes': {
                        'size': 10737418240,
                    },
                },
            },
        }
        self.client.send_request.assert_has_calls([
            mock.call('volume-modify-iter', volume_modify_iter_args)])

    @ddt.data(True, False)
    def test_set_volume_snapdir_access(self, hide_snapdir):
        api_response = netapp_api.NaElement(
            fake.VOLUME_MODIFY_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.client.set_volume_snapdir_access(fake.SHARE_NAME, hide_snapdir)

        api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME
                    }
                }
            },
            'attributes': {
                'volume-attributes': {
                    'volume-snapshot-attributes': {
                        'snapdir-access-enabled': str(
                            not hide_snapdir).lower(),
                    },
                },
            },
        }
        self.client.send_request.assert_called_once_with(
            'volume-modify-iter', api_args)

    def test_set_volume_snapdir_access_api_error(self):

        api_response = netapp_api.NaElement(
            fake.VOLUME_MODIFY_ITER_ERROR_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(netapp_api.NaApiError,
                          self.client.set_volume_size,
                          fake.SHARE_NAME,
                          10)

    @ddt.data(True, False)
    def test_set_volume_filesys_size_fixed(self, filesys_size_fixed):
        api_response = netapp_api.NaElement(
            fake.VOLUME_MODIFY_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.client.set_volume_filesys_size_fixed(fake.SHARE_NAME,
                                                  filesys_size_fixed)

        api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME
                    }
                }
            },
            'attributes': {
                'volume-attributes': {
                    'volume-space-attributes': {
                        'is-filesys-size-fixed': str(
                            filesys_size_fixed).lower(),
                    },
                },
            },
        }
        self.client.send_request.assert_called_once_with(
            'volume-modify-iter', api_args)

    def test_set_volume_size_api_error(self):

        api_response = netapp_api.NaElement(
            fake.VOLUME_MODIFY_ITER_ERROR_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(netapp_api.NaApiError,
                          self.client.set_volume_size,
                          fake.SHARE_NAME,
                          10)

    @ddt.data(None, 'ntfs')
    def test_set_volume_security_style(self, security_style):

        api_response = netapp_api.NaElement(fake.VOLUME_MODIFY_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))
        kwargs = {'security_style': security_style} if security_style else {}

        self.client.set_volume_security_style(fake.SHARE_NAME, **kwargs)

        volume_modify_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME
                    }
                }
            },
            'attributes': {
                'volume-attributes': {
                    'volume-security-attributes': {
                        'style': security_style or 'unix',
                    },
                },
            },
        }
        self.client.send_request.assert_called_once_with(
            'volume-modify-iter', volume_modify_iter_args)

    def test_set_volume_security_style_api_error(self):

        api_response = netapp_api.NaElement(
            fake.VOLUME_MODIFY_ITER_ERROR_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(netapp_api.NaApiError,
                          self.client.set_volume_security_style,
                          fake.SHARE_NAME,
                          'ntfs')

    def test_volume_exists(self):

        api_response = netapp_api.NaElement(fake.VOLUME_GET_NAME_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.volume_exists(fake.SHARE_NAME)

        volume_get_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME
                    }
                }
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': None
                    }
                }
            }
        }

        self.client.send_iter_request.assert_has_calls([
            mock.call('volume-get-iter', volume_get_iter_args)])
        self.assertTrue(result)

    def test_volume_exists_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.assertFalse(self.client.volume_exists(fake.SHARE_NAME))

    def test_snapshot_exists(self):

        api_response = netapp_api.NaElement(fake.VOLUME_GET_NAME_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.snapshot_exists(fake.SNAPSHOT_NAME,
                                             fake.SHARE_NAME)

        snapshot_get_iter_args = {
            'query': {
                'snapshot-info': {
                    'name': fake.SNAPSHOT_NAME,
                    'volume': fake.SHARE_NAME,
                }
            },
            'desired-attributes': {
                'snapshot-info': {
                    'name': None,
                    'volume': None,
                    'busy': None,
                    'snapshot-owners-list': {
                        'snapshot-owner': None,
                    }
                }
            }
        }

        self.client.send_request.assert_has_calls([
            mock.call('snapshot-get-iter', snapshot_get_iter_args)])
        self.assertTrue(result)

    def test_snapshot_exists_not_found(self):
        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.assertFalse(self.client.snapshot_exists(fake.SNAPSHOT_NAME,
                                                     fake.SHARE_NAME))

    @ddt.data({
        'api_response_xml': fake.SNAPSHOT_GET_ITER_UNAVAILABLE_RESPONSE,
        'raised_exception': exception.SnapshotUnavailable,
    }, {
        'api_response_xml': fake.SNAPSHOT_GET_ITER_OTHER_ERROR_RESPONSE,
        'raised_exception': exception.NetAppException,
    })
    @ddt.unpack
    def test_snapshot_exists_error(self, api_response_xml, raised_exception):

        api_response = netapp_api.NaElement(api_response_xml)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(raised_exception,
                          self.client.snapshot_exists,
                          fake.SNAPSHOT_NAME,
                          fake.SHARE_NAME)

    @ddt.data(True, False)
    def test_get_aggregate_for_volume(self, is_flexgroup):

        api_response = netapp_api.NaElement(
            fake.GET_AGGREGATE_FOR_FLEXGROUP_VOL_RESPONSE if is_flexgroup
            else fake.GET_AGGREGATE_FOR_VOLUME_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_aggregate_for_volume(fake.SHARE_NAME)

        volume_get_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME
                    }
                }
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'aggr-list': {
                            'aggr-name': None,
                        },
                        'containing-aggregate-name': None,
                        'name': None
                    }
                }
            }
        }

        self.client.send_iter_request.assert_has_calls([
            mock.call('volume-get-iter', volume_get_iter_args)])
        if is_flexgroup:
            self.assertEqual([fake.SHARE_AGGREGATE_NAME], result)
        else:
            self.assertEqual(fake.SHARE_AGGREGATE_NAME, result)

    def test_get_aggregate_for_volume_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(exception.NetAppException,
                          self.client.get_aggregate_for_volume,
                          fake.SHARE_NAME)

    def test_volume_has_luns(self):

        api_response = netapp_api.NaElement(fake.LUN_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.volume_has_luns(fake.SHARE_NAME)

        lun_get_iter_args = {
            'query': {
                'lun-info': {
                    'volume': fake.SHARE_NAME,
                },
            },
            'desired-attributes': {
                'lun-info': {
                    'path': None,
                },
            },
        }

        self.client.send_iter_request.assert_has_calls([
            mock.call('lun-get-iter', lun_get_iter_args)])
        self.assertTrue(result)

    def test_volume_has_luns_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.volume_has_luns(fake.SHARE_NAME)

        self.assertFalse(result)

    def test_volume_has_junctioned_volumes(self):

        api_response = netapp_api.NaElement(
            fake.VOLUME_GET_ITER_JUNCTIONED_VOLUMES_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        fake_junction_path = '/%s' % fake.SHARE_NAME
        result = self.client.volume_has_junctioned_volumes(fake_junction_path)

        volume_get_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'junction-path': fake_junction_path + '/*',
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': None,
                    },
                },
            },
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('volume-get-iter', volume_get_iter_args)])
        self.assertTrue(result)

    def test_volume_has_junctioned_volumes_no_junction_path(self):

        result = self.client.volume_has_junctioned_volumes(None)

        self.assertFalse(result)

    def test_volume_has_junctioned_volumes_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        fake_junction_path = '/%s' % fake.SHARE_NAME
        result = self.client.volume_has_junctioned_volumes(fake_junction_path)

        self.assertFalse(result)

    @ddt.data(True, False)
    def test_get_volume(self, is_flexgroup):

        api_response = netapp_api.NaElement(
            fake.VOLUME_GET_ITER_FLEXGROUP_VOLUME_TO_MANAGE_RESPONSE
            if is_flexgroup
            else fake.VOLUME_GET_ITER_VOLUME_TO_MANAGE_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_volume(fake.SHARE_NAME)

        volume_get_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME,
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'aggr-list': {
                            'aggr-name': None,
                        },
                        'containing-aggregate-name': None,
                        'junction-path': None,
                        'name': None,
                        'owning-vserver-name': None,
                        'type': None,
                        'style': None,
                        'style-extended': None,
                    },
                    'volume-space-attributes': {
                        'size': None,
                    },
                    'volume-qos-attributes': {
                        'policy-group-name': None,
                    },
                },
            },
        }

        expected = {
            'aggregate': '' if is_flexgroup else fake.SHARE_AGGREGATE_NAME,
            'aggr-list': [fake.SHARE_AGGREGATE_NAME] if is_flexgroup else [],
            'junction-path': '/%s' % fake.SHARE_NAME,
            'name': fake.SHARE_NAME,
            'type': 'rw',
            'style': 'flex',
            'size': fake.SHARE_SIZE,
            'owning-vserver-name': fake.VSERVER_NAME,
            'qos-policy-group-name': fake.QOS_POLICY_GROUP_NAME,
            'style-extended': (fake.FLEXGROUP_STYLE_EXTENDED
                               if is_flexgroup
                               else fake.FLEXVOL_STYLE_EXTENDED),
        }
        self.client.send_request.assert_has_calls([
            mock.call('volume-get-iter', volume_get_iter_args)])
        self.assertDictEqual(expected, result)

    def test_get_volume_no_qos(self):
        api_response = netapp_api.NaElement(
            fake.VOLUME_GET_ITER_NO_QOS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_volume(fake.SHARE_NAME)

        volume_get_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME,
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'aggr-list': {
                            'aggr-name': None,
                        },
                        'containing-aggregate-name': None,
                        'junction-path': None,
                        'name': None,
                        'owning-vserver-name': None,
                        'type': None,
                        'style': None,
                        'style-extended': None,
                    },
                    'volume-space-attributes': {
                        'size': None,
                    },
                    'volume-qos-attributes': {
                        'policy-group-name': None,
                    },
                },
            },
        }

        expected = {
            'aggregate': fake.SHARE_AGGREGATE_NAME,
            'aggr-list': [],
            'junction-path': '/%s' % fake.SHARE_NAME,
            'name': fake.SHARE_NAME,
            'type': 'rw',
            'style': 'flex',
            'size': fake.SHARE_SIZE,
            'owning-vserver-name': fake.VSERVER_NAME,
            'qos-policy-group-name': None,
            'style-extended': fake.FLEXVOL_STYLE_EXTENDED,
        }
        self.client.send_request.assert_has_calls([
            mock.call('volume-get-iter', volume_get_iter_args)])
        self.assertDictEqual(expected, result)

    def test_get_volume_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(exception.StorageResourceNotFound,
                          self.client.get_volume,
                          fake.SHARE_NAME)

    def test_get_volume_not_unique(self):

        api_response = netapp_api.NaElement(
            fake.VOLUME_GET_ITER_NOT_UNIQUE_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(exception.NetAppException,
                          self.client.get_volume,
                          fake.SHARE_NAME)

    def test_get_volume_at_junction_path(self):

        api_response = netapp_api.NaElement(
            fake.VOLUME_GET_ITER_VOLUME_TO_MANAGE_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))
        fake_junction_path = '/%s' % fake.SHARE_NAME

        result = self.client.get_volume_at_junction_path(fake_junction_path)

        volume_get_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'junction-path': fake_junction_path,
                        'style-extended': 'flexgroup|flexvol',
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': None,
                    },
                },
            },
        }
        expected = {
            'name': fake.SHARE_NAME,
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('volume-get-iter', volume_get_iter_args)])
        self.assertDictEqual(expected, result)

    def test_get_volume_at_junction_path_not_specified(self):

        result = self.client.get_volume_at_junction_path(None)

        self.assertIsNone(result)

    def test_get_volume_at_junction_path_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))
        fake_junction_path = '/%s' % fake.SHARE_NAME

        result = self.client.get_volume_at_junction_path(fake_junction_path)

        self.assertIsNone(result)

    @ddt.data(True, False)
    def test_get_volume_to_manage(self, is_flexgroup):

        api_response = netapp_api.NaElement(
            fake.VOLUME_GET_ITER_FLEXGROUP_VOLUME_TO_MANAGE_RESPONSE
            if is_flexgroup
            else fake.VOLUME_GET_ITER_VOLUME_TO_MANAGE_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        aggr = fake.SHARE_AGGREGATE_NAME
        result = self.client.get_volume_to_manage(
            [aggr] if is_flexgroup else aggr,
            fake.SHARE_NAME)

        volume_get_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME,
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'aggr-list': {
                            'aggr-name': None,
                        },
                        'containing-aggregate-name': None,
                        'junction-path': None,
                        'name': None,
                        'type': None,
                        'style': None,
                        'owning-vserver-name': None,
                    },
                    'volume-space-attributes': {
                        'size': None,
                    },
                    'volume-qos-attributes': {
                        'policy-group-name': None,
                    },
                },
            },
        }
        if is_flexgroup:
            volume_get_iter_args['query']['volume-attributes'][
                'volume-id-attributes']['aggr-list'] = [{'aggr-name': aggr}]
        else:
            volume_get_iter_args['query']['volume-attributes'][
                'volume-id-attributes']['containing-aggregate-name'] = aggr

        expected = {
            'aggregate': '' if is_flexgroup else aggr,
            'aggr-list': [aggr] if is_flexgroup else [],
            'junction-path': '/%s' % fake.SHARE_NAME,
            'name': fake.SHARE_NAME,
            'type': 'rw',
            'style': 'flex',
            'size': fake.SHARE_SIZE,
            'owning-vserver-name': fake.VSERVER_NAME,
            'qos-policy-group-name': fake.QOS_POLICY_GROUP_NAME,
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('volume-get-iter', volume_get_iter_args)])
        self.assertDictEqual(expected, result)

    def test_get_volume_to_manage_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_volume_to_manage(fake.SHARE_AGGREGATE_NAME,
                                                  fake.SHARE_NAME)

        self.assertIsNone(result)

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
        self.client.features.add_feature('ADAPTIVE_QOS')
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'split_volume_clone')
        set_qos_adapt_mock = self.mock_object(
            self.client,
            'set_qos_adaptive_policy_group_for_volume')

        self.client.create_volume_clone(
            fake.SHARE_NAME,
            fake.PARENT_SHARE_NAME,
            fake.PARENT_SNAPSHOT_NAME,
            qos_policy_group=qos_policy_group_name,
            adaptive_qos_policy_group=adaptive_qos_policy_group_name)

        volume_clone_create_args = {
            'volume': fake.SHARE_NAME,
            'parent-volume': fake.PARENT_SHARE_NAME,
            'parent-snapshot': fake.PARENT_SNAPSHOT_NAME,
            'junction-path': '/%s' % fake.SHARE_NAME
        }

        if qos_policy_group_name:
            volume_clone_create_args.update(
                {'qos-policy-group-name': fake.QOS_POLICY_GROUP_NAME})
        if adaptive_qos_policy_group_name:
            set_qos_adapt_mock.assert_called_once_with(
                fake.SHARE_NAME, fake.ADAPTIVE_QOS_POLICY_GROUP_NAME
            )
        self.client.send_request.assert_has_calls([
            mock.call('volume-clone-create', volume_clone_create_args)])
        self.assertFalse(self.client.split_volume_clone.called)

    @ddt.data(True, False)
    def test_create_volume_clone_split(self, split):

        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'split_volume_clone')

        self.client.create_volume_clone(fake.SHARE_NAME,
                                        fake.PARENT_SHARE_NAME,
                                        fake.PARENT_SNAPSHOT_NAME,
                                        split=split)

        volume_clone_create_args = {
            'volume': fake.SHARE_NAME,
            'parent-volume': fake.PARENT_SHARE_NAME,
            'parent-snapshot': fake.PARENT_SNAPSHOT_NAME,
            'junction-path': '/%s' % fake.SHARE_NAME
        }

        self.client.send_request.assert_has_calls([
            mock.call('volume-clone-create', volume_clone_create_args)])
        if split:
            self.client.split_volume_clone.assert_called_once_with(
                fake.SHARE_NAME)
        else:
            self.assertFalse(self.client.split_volume_clone.called)

    @ddt.data(None,
              mock.Mock(side_effect=netapp_api.NaApiError(
                  code=netapp_api.EVOL_CLONE_BEING_SPLIT)))
    def test_split_volume_clone(self, side_effect):

        self.mock_object(
            self.client, 'send_request',
            mock.Mock(side_effect=side_effect))

        self.client.split_volume_clone(fake.SHARE_NAME)

        volume_clone_split_args = {'volume': fake.SHARE_NAME}

        self.client.send_request.assert_has_calls([
            mock.call('volume-clone-split-start', volume_clone_split_args)])

    def test_split_volume_clone_api_error(self):

        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(side_effect=self._mock_api_error()))

        self.assertRaises(netapp_api.NaApiError,
                          self.client.split_volume_clone,
                          fake.SHARE_NAME)

    def test_get_clone_children_for_snapshot(self):

        api_response = netapp_api.NaElement(
            fake.VOLUME_GET_ITER_CLONE_CHILDREN_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_clone_children_for_snapshot(
            fake.SHARE_NAME, fake.SNAPSHOT_NAME)

        volume_get_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-clone-attributes': {
                        'volume-clone-parent-attributes': {
                            'name': fake.SHARE_NAME,
                            'snapshot-name': fake.SNAPSHOT_NAME,
                        },
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': None,
                    },
                },
            },
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('volume-get-iter', volume_get_iter_args)])

        expected = [
            {'name': fake.CLONE_CHILD_1},
            {'name': fake.CLONE_CHILD_2},
        ]
        self.assertEqual(expected, result)

    def test_get_clone_children_for_snapshot_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_clone_children_for_snapshot(
            fake.SHARE_NAME, fake.SNAPSHOT_NAME)

        self.assertEqual([], result)

    def test_get_volume_junction_path(self):

        api_response = netapp_api.NaElement(
            fake.VOLUME_GET_VOLUME_PATH_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_volume_junction_path(fake.SHARE_NAME)

        volume_get_volume_path_args = {
            'volume': fake.SHARE_NAME,
            'is-style-cifs': 'false'
        }

        self.client.send_request.assert_has_calls([
            mock.call('volume-get-volume-path', volume_get_volume_path_args)])
        self.assertEqual(fake.VOLUME_JUNCTION_PATH, result)

    def test_get_volume_junction_path_cifs(self):

        api_response = netapp_api.NaElement(
            fake.VOLUME_GET_VOLUME_PATH_CIFS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_volume_junction_path(fake.SHARE_NAME,
                                                      is_style_cifs=True)

        volume_get_volume_path_args = {
            'volume': fake.SHARE_NAME,
            'is-style-cifs': 'true'
        }

        self.client.send_request.assert_has_calls([
            mock.call('volume-get-volume-path', volume_get_volume_path_args)])
        self.assertEqual(fake.VOLUME_JUNCTION_PATH_CIFS, result)

    def test_mount_volume_default_junction_path(self):

        self.mock_object(self.client, 'send_request')

        self.client.mount_volume(fake.SHARE_NAME)

        volume_mount_args = {
            'volume-name': fake.SHARE_NAME,
            'junction-path': '/%s' % fake.SHARE_NAME,
        }

        self.client.send_request.assert_has_calls([
            mock.call('volume-mount', volume_mount_args)])

    def test_mount_volume(self):

        self.mock_object(self.client, 'send_request')
        fake_path = '/fake_path'

        self.client.mount_volume(fake.SHARE_NAME, junction_path=fake_path)

        volume_mount_args = {
            'volume-name': fake.SHARE_NAME,
            'junction-path': fake_path,
        }

        self.client.send_request.assert_has_calls([
            mock.call('volume-mount', volume_mount_args)])

    def test_offline_volume(self):

        self.mock_object(self.client, 'send_request')

        self.client.offline_volume(fake.SHARE_NAME)

        volume_offline_args = {'name': fake.SHARE_NAME}

        self.client.send_request.assert_has_calls([
            mock.call('volume-offline', volume_offline_args)])

    def test_offline_volume_already_offline(self):

        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(side_effect=self._mock_api_error(
                             netapp_api.EVOLUMEOFFLINE)))

        self.client.offline_volume(fake.SHARE_NAME)

        volume_offline_args = {'name': fake.SHARE_NAME}

        self.client.send_request.assert_has_calls([
            mock.call('volume-offline', volume_offline_args)])

    def test_offline_volume_api_error(self):

        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(side_effect=self._mock_api_error()))

        self.assertRaises(netapp_api.NaApiError,
                          self.client.offline_volume,
                          fake.SHARE_NAME)

    def test__unmount_volume(self):

        self.mock_object(self.client, 'send_request')

        self.client._unmount_volume(fake.SHARE_NAME)

        volume_unmount_args = {
            'volume-name': fake.SHARE_NAME,
            'force': 'false'
        }

        self.client.send_request.assert_has_calls([
            mock.call('volume-unmount', volume_unmount_args)])

    def test__unmount_volume_force(self):

        self.mock_object(self.client, 'send_request')

        self.client._unmount_volume(fake.SHARE_NAME, force=True)

        volume_unmount_args = {'volume-name': fake.SHARE_NAME, 'force': 'true'}

        self.client.send_request.assert_has_calls([
            mock.call('volume-unmount', volume_unmount_args)])

    def test__unmount_volume_already_unmounted(self):

        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(side_effect=self._mock_api_error(
                             netapp_api.EVOL_NOT_MOUNTED)))

        self.client._unmount_volume(fake.SHARE_NAME, force=True)

        volume_unmount_args = {'volume-name': fake.SHARE_NAME, 'force': 'true'}

        self.client.send_request.assert_has_calls([
            mock.call('volume-unmount', volume_unmount_args)])

    def test__unmount_volume_api_error(self):

        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(side_effect=self._mock_api_error()))

        self.assertRaises(netapp_api.NaApiError,
                          self.client._unmount_volume,
                          fake.SHARE_NAME,
                          force=True)

    def test_unmount_volume(self):

        self.mock_object(self.client, '_unmount_volume')

        self.client.unmount_volume(fake.SHARE_NAME)

        self.client._unmount_volume.assert_called_once_with(fake.SHARE_NAME,
                                                            force=False)
        self.assertEqual(1, client_cmode.LOG.debug.call_count)
        self.assertEqual(0, client_cmode.LOG.warning.call_count)

    def test_unmount_volume_api_error(self):

        self.mock_object(self.client,
                         '_unmount_volume',
                         self._mock_api_error())

        self.assertRaises(netapp_api.NaApiError,
                          self.client.unmount_volume,
                          fake.SHARE_NAME)

        self.assertEqual(1, self.client._unmount_volume.call_count)
        self.assertEqual(0, client_cmode.LOG.debug.call_count)
        self.assertEqual(0, client_cmode.LOG.warning.call_count)

    def test_unmount_volume_with_retries(self):

        side_effect = [netapp_api.NaApiError(code=netapp_api.EAPIERROR,
                                             message='...job ID...')] * 5
        side_effect.append(None)
        self.mock_object(self.client,
                         '_unmount_volume',
                         mock.Mock(side_effect=side_effect))
        self.mock_object(time, 'sleep')

        self.client.unmount_volume(fake.SHARE_NAME)

        self.assertEqual(6, self.client._unmount_volume.call_count)
        self.assertEqual(1, client_cmode.LOG.debug.call_count)
        self.assertEqual(5, client_cmode.LOG.warning.call_count)

    def test_unmount_volume_with_max_retries(self):

        side_effect = [netapp_api.NaApiError(code=netapp_api.EAPIERROR,
                                             message='...job ID...')] * 30
        self.mock_object(self.client,
                         '_unmount_volume',
                         mock.Mock(side_effect=side_effect))
        self.mock_object(time, 'sleep')

        self.assertRaises(exception.NetAppException,
                          self.client.unmount_volume,
                          fake.SHARE_NAME)

        self.assertEqual(10, self.client._unmount_volume.call_count)
        self.assertEqual(0, client_cmode.LOG.debug.call_count)
        self.assertEqual(10, client_cmode.LOG.warning.call_count)

    def test_delete_volume(self):

        self.mock_object(self.client, 'send_request')

        self.client.delete_volume(fake.SHARE_NAME)

        volume_destroy_args = {'name': fake.SHARE_NAME}

        self.client.send_request.assert_has_calls([
            mock.call('volume-destroy', volume_destroy_args)])

    def test_create_snapshot(self):

        self.mock_object(self.client, 'send_request')

        self.client.create_snapshot(fake.SHARE_NAME, fake.SNAPSHOT_NAME)

        snapshot_create_args = {
            'volume': fake.SHARE_NAME,
            'snapshot': fake.SNAPSHOT_NAME
        }

        self.client.send_request.assert_has_calls([
            mock.call('snapshot-create', snapshot_create_args)])

    @ddt.data({
        'mock_return': fake.SNAPSHOT_GET_ITER_NOT_BUSY_RESPONSE,
        'expected': {
            'access-time': fake.SNAPSHOT_ACCESS_TIME,
            'name': fake.SNAPSHOT_NAME,
            'volume': fake.SHARE_NAME,
            'busy': False,
            'owners': set(),
            'locked_by_clone': False,
        }
    }, {
        'mock_return': fake.SNAPSHOT_GET_ITER_BUSY_RESPONSE,
        'expected': {
            'access-time': fake.SNAPSHOT_ACCESS_TIME,
            'name': fake.SNAPSHOT_NAME,
            'volume': fake.SHARE_NAME,
            'busy': True,
            'owners': {'volume clone'},
            'locked_by_clone': True,
        }
    })
    @ddt.unpack
    def test_get_snapshot(self, mock_return, expected):

        api_response = netapp_api.NaElement(mock_return)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_snapshot(fake.SHARE_NAME, fake.SNAPSHOT_NAME)

        snapshot_get_iter_args = {
            'query': {
                'snapshot-info': {
                    'name': fake.SNAPSHOT_NAME,
                    'volume': fake.SHARE_NAME,
                },
            },
            'desired-attributes': {
                'snapshot-info': {
                    'access-time': None,
                    'name': None,
                    'volume': None,
                    'busy': None,
                    'snapshot-owners-list': {
                        'snapshot-owner': None,
                    }
                },
            },
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapshot-get-iter', snapshot_get_iter_args)])
        self.assertDictEqual(expected, result)

    @ddt.data({
        'api_response_xml': fake.NO_RECORDS_RESPONSE,
        'raised_exception': exception.SnapshotResourceNotFound,
    }, {
        'api_response_xml': fake.SNAPSHOT_GET_ITER_NOT_UNIQUE_RESPONSE,
        'raised_exception': exception.NetAppException,
    }, {
        'api_response_xml': fake.SNAPSHOT_GET_ITER_UNAVAILABLE_RESPONSE,
        'raised_exception': exception.SnapshotUnavailable,
    }, {
        'api_response_xml': fake.SNAPSHOT_GET_ITER_OTHER_ERROR_RESPONSE,
        'raised_exception': exception.NetAppException,
    })
    @ddt.unpack
    def test_get_snapshot_error(self, api_response_xml, raised_exception):

        api_response = netapp_api.NaElement(api_response_xml)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(raised_exception,
                          self.client.get_snapshot,
                          fake.SHARE_NAME,
                          fake.SNAPSHOT_NAME)

    def test_rename_snapshot(self):

        self.mock_object(self.client, 'send_request')

        self.client.rename_snapshot(fake.SHARE_NAME,
                                    fake.SNAPSHOT_NAME,
                                    'new_snapshot_name')

        snapshot_rename_args = {
            'volume': fake.SHARE_NAME,
            'current-name': fake.SNAPSHOT_NAME,
            'new-name': 'new_snapshot_name'
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapshot-rename', snapshot_rename_args)])

    def test_restore_snapshot(self):

        self.mock_object(self.client, 'send_request')

        self.client.restore_snapshot(fake.SHARE_NAME,
                                     fake.SNAPSHOT_NAME)

        snapshot_restore_args = {
            'volume': fake.SHARE_NAME,
            'snapshot': fake.SNAPSHOT_NAME,
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapshot-restore-volume', snapshot_restore_args)])

    @ddt.data(True, False)
    def test_delete_snapshot(self, ignore_owners):

        self.mock_object(self.client, 'send_request')

        self.client.delete_snapshot(
            fake.SHARE_NAME, fake.SNAPSHOT_NAME, ignore_owners=ignore_owners)

        snapshot_delete_args = {
            'volume': fake.SHARE_NAME,
            'snapshot': fake.SNAPSHOT_NAME,
            'ignore-owners': 'true' if ignore_owners else 'false',
        }

        self.client.send_request.assert_has_calls([
            mock.call('snapshot-delete', snapshot_delete_args)])

    def test_soft_delete_snapshot(self):

        mock_delete_snapshot = self.mock_object(self.client, 'delete_snapshot')
        mock_rename_snapshot = self.mock_object(self.client, 'rename_snapshot')

        self.client.soft_delete_snapshot(fake.SHARE_NAME, fake.SNAPSHOT_NAME)

        mock_delete_snapshot.assert_called_once_with(
            fake.SHARE_NAME, fake.SNAPSHOT_NAME)
        self.assertFalse(mock_rename_snapshot.called)

    def test_soft_delete_snapshot_api_error(self):

        mock_delete_snapshot = self.mock_object(
            self.client, 'delete_snapshot', self._mock_api_error())
        mock_rename_snapshot = self.mock_object(self.client, 'rename_snapshot')

        self.client.soft_delete_snapshot(fake.SHARE_NAME, fake.SNAPSHOT_NAME)

        mock_delete_snapshot.assert_called_once_with(
            fake.SHARE_NAME, fake.SNAPSHOT_NAME)
        mock_rename_snapshot.assert_called_once_with(
            fake.SHARE_NAME, fake.SNAPSHOT_NAME,
            'deleted_manila_' + fake.SNAPSHOT_NAME)

    def test_prune_deleted_snapshots(self):

        deleted_snapshots_map = {
            'vserver1': [{
                'name': 'deleted_snap_1',
                'volume': 'fake_volume_1',
                'vserver': 'vserver1',
            }],
            'vserver2': [{
                'name': 'deleted_snap_2',
                'volume': 'fake_volume_2',
                'vserver': 'vserver2',
            }],
        }
        mock_get_deleted_snapshots = self.mock_object(
            self.client, '_get_deleted_snapshots',
            mock.Mock(return_value=deleted_snapshots_map))
        mock_delete_snapshot = self.mock_object(
            self.client, 'delete_snapshot',
            mock.Mock(side_effect=[None, netapp_api.NaApiError]))
        self.mock_object(
            copy, 'deepcopy', mock.Mock(return_value=self.client))

        self.client.prune_deleted_snapshots()

        mock_get_deleted_snapshots.assert_called_once_with()
        mock_delete_snapshot.assert_has_calls([
            mock.call('fake_volume_1', 'deleted_snap_1'),
            mock.call('fake_volume_2', 'deleted_snap_2'),
        ], any_order=True)

    def test_get_deleted_snapshots(self):

        api_response = netapp_api.NaElement(
            fake.SNAPSHOT_GET_ITER_DELETED_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client._get_deleted_snapshots()

        snapshot_get_iter_args = {
            'query': {
                'snapshot-info': {
                    'name': 'deleted_manila_*',
                    'busy': 'false',
                },
            },
            'desired-attributes': {
                'snapshot-info': {
                    'name': None,
                    'vserver': None,
                    'volume': None,
                },
            },
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('snapshot-get-iter', snapshot_get_iter_args)])

        expected = {
            fake.VSERVER_NAME: [{
                'name': 'deleted_manila_' + fake.SNAPSHOT_NAME,
                'volume': fake.SHARE_NAME,
                'vserver': fake.VSERVER_NAME,
            }],
        }
        self.assertDictEqual(expected, result)

    def test_create_cg_snapshot(self):

        mock_start_cg_snapshot = self.mock_object(
            self.client, '_start_cg_snapshot',
            mock.Mock(return_value=fake.CG_SNAPSHOT_ID))
        mock_commit_cg_snapshot = self.mock_object(
            self.client, '_commit_cg_snapshot')

        self.client.create_cg_snapshot([fake.SHARE_NAME, fake.SHARE_NAME_2],
                                       fake.SNAPSHOT_NAME)

        mock_start_cg_snapshot.assert_called_once_with(
            [fake.SHARE_NAME, fake.SHARE_NAME_2], fake.SNAPSHOT_NAME)
        mock_commit_cg_snapshot.assert_called_once_with(fake.CG_SNAPSHOT_ID)

    def test_create_cg_snapshot_no_id(self):

        mock_start_cg_snapshot = self.mock_object(
            self.client, '_start_cg_snapshot', mock.Mock(return_value=None))
        mock_commit_cg_snapshot = self.mock_object(
            self.client, '_commit_cg_snapshot')

        self.assertRaises(exception.NetAppException,
                          self.client.create_cg_snapshot,
                          [fake.SHARE_NAME, fake.SHARE_NAME_2],
                          fake.SNAPSHOT_NAME)

        mock_start_cg_snapshot.assert_called_once_with(
            [fake.SHARE_NAME, fake.SHARE_NAME_2], fake.SNAPSHOT_NAME)
        self.assertFalse(mock_commit_cg_snapshot.called)

    def test_start_cg_snapshot(self):

        self.mock_object(self.client, 'send_request')

        self.client._start_cg_snapshot([fake.SHARE_NAME, fake.SHARE_NAME_2],
                                       fake.SNAPSHOT_NAME)

        cg_start_args = {
            'snapshot': fake.SNAPSHOT_NAME,
            'timeout': 'relaxed',
            'volumes': [
                {'volume-name': fake.SHARE_NAME},
                {'volume-name': fake.SHARE_NAME_2},
            ],
        }

        self.client.send_request.assert_has_calls([
            mock.call('cg-start', cg_start_args)])

    def test_commit_cg_snapshot(self):

        self.mock_object(self.client, 'send_request')

        self.client._commit_cg_snapshot(fake.CG_SNAPSHOT_ID)

        cg_commit_args = {'cg-id': fake.CG_SNAPSHOT_ID}

        self.client.send_request.assert_has_calls([
            mock.call('cg-commit', cg_commit_args)])

    def test_create_cifs_share(self):

        self.mock_object(self.client, 'send_request')

        self.client.create_cifs_share(
            fake.SHARE_NAME, fake.VOLUME_JUNCTION_PATH)

        cifs_share_create_args = {
            'path': fake.VOLUME_JUNCTION_PATH,
            'share-name': fake.SHARE_NAME
        }

        self.client.send_request.assert_has_calls([
            mock.call('cifs-share-create', cifs_share_create_args)])

    def test_get_cifs_share_access(self):

        api_response = netapp_api.NaElement(
            fake.CIFS_SHARE_ACCESS_CONTROL_GET_ITER)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_cifs_share_access(fake.SHARE_NAME)

        cifs_share_access_control_get_iter_args = {
            'query': {
                'cifs-share-access-control': {
                    'share': fake.SHARE_NAME,
                },
            },
            'desired-attributes': {
                'cifs-share-access-control': {
                    'user-or-group': None,
                    'permission': None,
                },
            },
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('cifs-share-access-control-get-iter',
                      cifs_share_access_control_get_iter_args)])

        expected = {
            'Administrator': 'full_control',
            'Administrators': 'change',
            'Power Users': 'read',
            'Users': 'no_access',
        }
        self.assertDictEqual(expected, result)

    def test_get_cifs_share_access_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_cifs_share_access(fake.SHARE_NAME)

        self.assertEqual({}, result)

    @ddt.data(True, False)
    def test_add_cifs_share_access(self, readonly):

        self.mock_object(self.client, 'send_request')

        self.client.add_cifs_share_access(fake.SHARE_NAME,
                                          fake.USER_NAME,
                                          readonly)

        cifs_share_access_control_create_args = {
            'permission': 'read' if readonly else 'full_control',
            'share': fake.SHARE_NAME,
            'user-or-group': fake.USER_NAME
        }

        self.client.send_request.assert_has_calls([
            mock.call(
                'cifs-share-access-control-create',
                cifs_share_access_control_create_args)])

    @ddt.data(True, False)
    def test_modify_cifs_share_access(self, readonly):

        self.mock_object(self.client, 'send_request')

        self.client.modify_cifs_share_access(fake.SHARE_NAME,
                                             fake.USER_NAME,
                                             readonly)

        cifs_share_access_control_modify_args = {
            'permission': 'read' if readonly else 'full_control',
            'share': fake.SHARE_NAME,
            'user-or-group': fake.USER_NAME
        }

        self.client.send_request.assert_has_calls([
            mock.call(
                'cifs-share-access-control-modify',
                cifs_share_access_control_modify_args)])

    def test_remove_cifs_share_access(self):

        self.mock_object(self.client, 'send_request')

        self.client.remove_cifs_share_access(fake.SHARE_NAME, fake.USER_NAME)

        cifs_share_access_control_delete_args = {
            'user-or-group': fake.USER_NAME,
            'share': fake.SHARE_NAME
        }

        self.client.send_request.assert_has_calls([
            mock.call(
                'cifs-share-access-control-delete',
                cifs_share_access_control_delete_args)])

    def test_remove_cifs_share(self):

        self.mock_object(self.client, 'send_request')

        self.client.remove_cifs_share(fake.SHARE_NAME)

        cifs_share_delete_args = {'share-name': fake.SHARE_NAME}

        self.client.send_request.assert_has_calls([
            mock.call('cifs-share-delete', cifs_share_delete_args)])

    def test_remove_cifs_share_not_found(self):

        self.mock_object(self.client,
                         'send_request',
                         self._mock_api_error(code=netapp_api.EOBJECTNOTFOUND))

        self.client.remove_cifs_share(fake.SHARE_NAME)

        cifs_share_args = {'share-name': fake.SHARE_NAME}
        self.client.send_request.assert_has_calls([
            mock.call('cifs-share-delete', cifs_share_args)])

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

    def test_add_nfs_export_rule_single_existing(self):

        mock_get_nfs_export_rule_indices = self.mock_object(
            self.client, '_get_nfs_export_rule_indices',
            mock.Mock(return_value=['1']))
        mock_add_nfs_export_rule = self.mock_object(
            self.client, '_add_nfs_export_rule')
        mock_update_nfs_export_rule = self.mock_object(
            self.client, '_update_nfs_export_rule')
        mock_remove_nfs_export_rules = self.mock_object(
            self.client, '_remove_nfs_export_rules')
        auth_methods = ['sys']

        self.client.add_nfs_export_rule(fake.EXPORT_POLICY_NAME,
                                        fake.IP_ADDRESS,
                                        False,
                                        auth_methods)

        mock_get_nfs_export_rule_indices.assert_called_once_with(
            fake.EXPORT_POLICY_NAME, fake.IP_ADDRESS)
        self.assertFalse(mock_add_nfs_export_rule.called)
        mock_update_nfs_export_rule.assert_called_once_with(
            fake.EXPORT_POLICY_NAME, fake.IP_ADDRESS, False, '1',
            auth_methods)
        mock_remove_nfs_export_rules.assert_called_once_with(
            fake.EXPORT_POLICY_NAME, [])

    def test_add_nfs_export_rule_multiple_existing(self):

        mock_get_nfs_export_rule_indices = self.mock_object(
            self.client, '_get_nfs_export_rule_indices',
            mock.Mock(return_value=['2', '4', '6']))
        mock_add_nfs_export_rule = self.mock_object(
            self.client, '_add_nfs_export_rule')
        mock_update_nfs_export_rule = self.mock_object(
            self.client, '_update_nfs_export_rule')
        mock_remove_nfs_export_rules = self.mock_object(
            self.client, '_remove_nfs_export_rules')
        auth_methods = ['sys']
        self.client.add_nfs_export_rule(fake.EXPORT_POLICY_NAME,
                                        fake.IP_ADDRESS,
                                        False,
                                        auth_methods)

        mock_get_nfs_export_rule_indices.assert_called_once_with(
            fake.EXPORT_POLICY_NAME, fake.IP_ADDRESS)
        self.assertFalse(mock_add_nfs_export_rule.called)
        mock_update_nfs_export_rule.assert_called_once_with(
            fake.EXPORT_POLICY_NAME, fake.IP_ADDRESS, False, '2', auth_methods)
        mock_remove_nfs_export_rules.assert_called_once_with(
            fake.EXPORT_POLICY_NAME, ['4', '6'])

    @ddt.data({'readonly': False, 'auth_method': 'sys'},
              {'readonly': True, 'auth_method': 'sys'})
    @ddt.unpack
    def test__add_nfs_export_rule(self, readonly, auth_method):

        self.mock_object(self.client, 'send_request')

        self.client._add_nfs_export_rule(fake.EXPORT_POLICY_NAME,
                                         fake.IP_ADDRESS,
                                         readonly,
                                         [auth_method])
        export_rule_create_args = {
            'policy-name': fake.EXPORT_POLICY_NAME,
            'client-match': fake.IP_ADDRESS,
            'ro-rule': [
                {'security-flavor': auth_method},
            ],
            'rw-rule': [
                {'security-flavor': auth_method},
            ],
            'super-user-security': [
                {'security-flavor': auth_method},
            ],
        }
        if readonly:
            export_rule_create_args['rw-rule'] = [
                {'security-flavor': 'never'}
            ]

        self.client.send_request.assert_has_calls(
            [mock.call('export-rule-create', export_rule_create_args)])

    @ddt.data({'readonly': False, 'auth_method': 'sys', 'index': '2'},
              {'readonly': True, 'auth_method': 'krb5', 'index': '4'})
    @ddt.unpack
    def test_update_nfs_export_rule(self, readonly, auth_method, index):

        self.mock_object(self.client, 'send_request')
        self.client._update_nfs_export_rule(fake.EXPORT_POLICY_NAME,
                                            fake.IP_ADDRESS,
                                            readonly,
                                            index,
                                            [auth_method])

        export_rule_modify_args = {
            'policy-name': fake.EXPORT_POLICY_NAME,
            'rule-index': index,
            'client-match': fake.IP_ADDRESS,
            'ro-rule': [
                {'security-flavor': auth_method},
            ],
            'rw-rule': [
                {'security-flavor': auth_method},
            ],
            'super-user-security': [
                {'security-flavor': auth_method},
            ],
        }
        if readonly:
            export_rule_modify_args['rw-rule'] = [
                {'security-flavor': 'never'}
            ]

        self.client.send_request.assert_has_calls(
            [mock.call('export-rule-modify', export_rule_modify_args)])

    def test_get_nfs_export_rule_indices(self):

        api_response = netapp_api.NaElement(fake.EXPORT_RULE_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client._get_nfs_export_rule_indices(
            fake.EXPORT_POLICY_NAME, fake.IP_ADDRESS)

        export_rule_get_iter_args = {
            'query': {
                'export-rule-info': {
                    'policy-name': fake.EXPORT_POLICY_NAME,
                    'client-match': fake.IP_ADDRESS,
                },
            },
            'desired-attributes': {
                'export-rule-info': {
                    'vserver-name': None,
                    'policy-name': None,
                    'client-match': None,
                    'rule-index': None,
                },
            },
        }
        self.assertListEqual(['1', '3'], result)
        self.client.send_iter_request.assert_has_calls([
            mock.call('export-rule-get-iter', export_rule_get_iter_args)])

    def test_remove_nfs_export_rule(self):

        fake_indices = ['1', '3', '4']
        mock_get_nfs_export_rule_indices = self.mock_object(
            self.client, '_get_nfs_export_rule_indices',
            mock.Mock(return_value=fake_indices))
        mock_remove_nfs_export_rules = self.mock_object(
            self.client, '_remove_nfs_export_rules')

        self.client.remove_nfs_export_rule(fake.EXPORT_POLICY_NAME,
                                           fake.IP_ADDRESS)

        mock_get_nfs_export_rule_indices.assert_called_once_with(
            fake.EXPORT_POLICY_NAME, fake.IP_ADDRESS)
        mock_remove_nfs_export_rules.assert_called_once_with(
            fake.EXPORT_POLICY_NAME, fake_indices)

    def test_remove_nfs_export_rules(self):

        fake_indices = ['1', '3']
        self.mock_object(self.client, 'send_request')

        self.client._remove_nfs_export_rules(fake.EXPORT_POLICY_NAME,
                                             fake_indices)

        self.client.send_request.assert_has_calls([
            mock.call(
                'export-rule-destroy',
                {'policy-name': fake.EXPORT_POLICY_NAME, 'rule-index': '1'}),
            mock.call(
                'export-rule-destroy',
                {'policy-name': fake.EXPORT_POLICY_NAME, 'rule-index': '3'})])

    def test_remove_nfs_export_rules_not_found(self):

        self.mock_object(self.client,
                         'send_request',
                         self._mock_api_error(code=netapp_api.EOBJECTNOTFOUND))

        self.client._remove_nfs_export_rules(fake.EXPORT_POLICY_NAME, ['1'])

        self.client.send_request.assert_has_calls([
            mock.call(
                'export-rule-destroy',
                {'policy-name': fake.EXPORT_POLICY_NAME, 'rule-index': '1'})])

    def test_remove_nfs_export_rules_api_error(self):

        self.mock_object(self.client, 'send_request', self._mock_api_error())

        self.assertRaises(netapp_api.NaApiError,
                          self.client._remove_nfs_export_rules,
                          fake.EXPORT_POLICY_NAME,
                          ['1'])

    def test_clear_nfs_export_policy_for_volume(self):

        mock_set_nfs_export_policy_for_volume = self.mock_object(
            self.client, 'set_nfs_export_policy_for_volume')

        self.client.clear_nfs_export_policy_for_volume(fake.SHARE_NAME)

        mock_set_nfs_export_policy_for_volume.assert_called_once_with(
            fake.SHARE_NAME, 'default')

    def test_set_nfs_export_policy_for_volume(self):

        self.mock_object(self.client, 'send_request')

        self.client.set_nfs_export_policy_for_volume(fake.SHARE_NAME,
                                                     fake.EXPORT_POLICY_NAME)

        volume_modify_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME,
                    },
                },
            },
            'attributes': {
                'volume-attributes': {
                    'volume-export-attributes': {
                        'policy': fake.EXPORT_POLICY_NAME,
                    },
                },
            },
        }
        self.client.send_request.assert_has_calls([
            mock.call('volume-modify-iter', volume_modify_iter_args)])

    def test_set_qos_policy_group_for_volume(self):

        self.mock_object(self.client, 'send_request')

        self.client.set_qos_policy_group_for_volume(fake.SHARE_NAME,
                                                    fake.QOS_POLICY_GROUP_NAME)

        volume_modify_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME,
                    },
                },
            },
            'attributes': {
                'volume-attributes': {
                    'volume-qos-attributes': {
                        'policy-group-name': fake.QOS_POLICY_GROUP_NAME,
                    },
                },
            },
        }
        self.client.send_request.assert_called_once_with(
            'volume-modify-iter', volume_modify_iter_args)

    def test_get_nfs_export_policy_for_volume(self):

        api_response = netapp_api.NaElement(
            fake.VOLUME_GET_EXPORT_POLICY_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_nfs_export_policy_for_volume(fake.SHARE_NAME)

        volume_get_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME,
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-export-attributes': {
                        'policy': None,
                    },
                },
            },
        }
        self.assertEqual(fake.EXPORT_POLICY_NAME, result)
        self.client.send_iter_request.assert_has_calls([
            mock.call('volume-get-iter', volume_get_iter_args)])

    def test_get_nfs_export_policy_for_volume_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(exception.NetAppException,
                          self.client.get_nfs_export_policy_for_volume,
                          fake.SHARE_NAME)

    def test_create_nfs_export_policy(self):

        self.mock_object(self.client, 'send_request')

        self.client.create_nfs_export_policy(fake.EXPORT_POLICY_NAME)

        export_policy_create_args = {'policy-name': fake.EXPORT_POLICY_NAME}
        self.client.send_request.assert_has_calls([
            mock.call('export-policy-create', export_policy_create_args)])

    def test_create_nfs_export_policy_already_present(self):

        self.mock_object(self.client,
                         'send_request',
                         self._mock_api_error(code=netapp_api.EDUPLICATEENTRY))

        self.client.create_nfs_export_policy(fake.EXPORT_POLICY_NAME)

        export_policy_create_args = {'policy-name': fake.EXPORT_POLICY_NAME}
        self.client.send_request.assert_has_calls([
            mock.call('export-policy-create', export_policy_create_args)])

    def test_create_nfs_export_policy_api_error(self):

        self.mock_object(self.client, 'send_request', self._mock_api_error())

        self.assertRaises(netapp_api.NaApiError,
                          self.client.create_nfs_export_policy,
                          fake.EXPORT_POLICY_NAME)

    def test_soft_delete_nfs_export_policy(self):

        self.mock_object(self.client, 'delete_nfs_export_policy')
        self.mock_object(self.client, 'rename_nfs_export_policy')

        self.client.soft_delete_nfs_export_policy(fake.EXPORT_POLICY_NAME)

        self.client.delete_nfs_export_policy.assert_has_calls([
            mock.call(fake.EXPORT_POLICY_NAME)])
        self.assertFalse(self.client.rename_nfs_export_policy.called)

    def test_soft_delete_nfs_export_policy_api_error(self):

        self.mock_object(self.client,
                         'delete_nfs_export_policy',
                         self._mock_api_error())
        self.mock_object(self.client, 'rename_nfs_export_policy')

        self.client.soft_delete_nfs_export_policy(fake.EXPORT_POLICY_NAME)

        self.client.delete_nfs_export_policy.assert_has_calls([
            mock.call(fake.EXPORT_POLICY_NAME)])
        self.assertTrue(self.client.rename_nfs_export_policy.called)

    def test_delete_nfs_export_policy(self):

        self.mock_object(self.client, 'send_request')

        self.client.delete_nfs_export_policy(fake.EXPORT_POLICY_NAME)

        export_policy_destroy_args = {'policy-name': fake.EXPORT_POLICY_NAME}
        self.client.send_request.assert_has_calls([
            mock.call('export-policy-destroy', export_policy_destroy_args)])

    def test_delete_nfs_export_policy_not_found(self):

        self.mock_object(self.client,
                         'send_request',
                         self._mock_api_error(code=netapp_api.EOBJECTNOTFOUND))

        self.client.delete_nfs_export_policy(fake.EXPORT_POLICY_NAME)

        export_policy_destroy_args = {'policy-name': fake.EXPORT_POLICY_NAME}
        self.client.send_request.assert_has_calls([
            mock.call('export-policy-destroy', export_policy_destroy_args)])

    def test_delete_nfs_export_policy_api_error(self):

        self.mock_object(self.client, 'send_request', self._mock_api_error())

        self.assertRaises(netapp_api.NaApiError,
                          self.client.delete_nfs_export_policy,
                          fake.EXPORT_POLICY_NAME)

    def test_rename_nfs_export_policy(self):

        self.mock_object(self.client, 'send_request')

        self.client.rename_nfs_export_policy(fake.EXPORT_POLICY_NAME,
                                             'new_policy_name')

        export_policy_rename_args = {
            'policy-name': fake.EXPORT_POLICY_NAME,
            'new-policy-name': 'new_policy_name'
        }
        self.client.send_request.assert_has_calls([
            mock.call('export-policy-rename', export_policy_rename_args)])

    def test_prune_deleted_nfs_export_policies(self):
        # Mock client lest we not be able to see calls on its copy.
        self.mock_object(copy,
                         'deepcopy',
                         mock.Mock(return_value=self.client))
        self.mock_object(self.client,
                         '_get_deleted_nfs_export_policies',
                         mock.Mock(return_value=fake.DELETED_EXPORT_POLICIES))
        self.mock_object(self.client, 'delete_nfs_export_policy')

        self.client.prune_deleted_nfs_export_policies()

        self.assertTrue(self.client.delete_nfs_export_policy.called)
        self.client.delete_nfs_export_policy.assert_has_calls(
            [mock.call(policy) for policy in
             fake.DELETED_EXPORT_POLICIES[fake.VSERVER_NAME]])

    def test_prune_deleted_nfs_export_policies_api_error(self):
        self.mock_object(copy,
                         'deepcopy',
                         mock.Mock(return_value=self.client))
        self.mock_object(self.client,
                         '_get_deleted_nfs_export_policies',
                         mock.Mock(return_value=fake.DELETED_EXPORT_POLICIES))
        self.mock_object(self.client,
                         'delete_nfs_export_policy',
                         self._mock_api_error())

        self.client.prune_deleted_nfs_export_policies()

        self.assertTrue(self.client.delete_nfs_export_policy.called)
        self.client.delete_nfs_export_policy.assert_has_calls(
            [mock.call(policy) for policy in
             fake.DELETED_EXPORT_POLICIES[fake.VSERVER_NAME]])

    def test_get_deleted_nfs_export_policies(self):

        api_response = netapp_api.NaElement(
            fake.DELETED_EXPORT_POLICY_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client._get_deleted_nfs_export_policies()

        export_policy_get_iter_args = {
            'query': {
                'export-policy-info': {
                    'policy-name': 'deleted_manila_*',
                },
            },
            'desired-attributes': {
                'export-policy-info': {
                    'policy-name': None,
                    'vserver': None,
                },
            },
        }
        self.assertSequenceEqual(fake.DELETED_EXPORT_POLICIES, result)
        self.client.send_iter_request.assert_has_calls([
            mock.call('export-policy-get-iter', export_policy_get_iter_args)])

    def test_get_ems_log_destination_vserver(self):

        self.mock_object(self.client,
                         'get_ontapi_version',
                         mock.Mock(return_value=(1, 21)))
        mock_list_vservers = self.mock_object(
            self.client,
            'list_vservers',
            mock.Mock(return_value=[fake.ADMIN_VSERVER_NAME]))

        result = self.client._get_ems_log_destination_vserver()

        mock_list_vservers.assert_called_once_with(vserver_type='admin')
        self.assertEqual(fake.ADMIN_VSERVER_NAME, result)

    def test_get_ems_log_destination_vserver_future(self):

        self.mock_object(self.client,
                         'get_ontapi_version',
                         mock.Mock(return_value=(2, 0)))
        mock_list_vservers = self.mock_object(
            self.client,
            'list_vservers',
            mock.Mock(return_value=[fake.ADMIN_VSERVER_NAME]))

        result = self.client._get_ems_log_destination_vserver()

        mock_list_vservers.assert_called_once_with(vserver_type='admin')
        self.assertEqual(fake.ADMIN_VSERVER_NAME, result)

    def test_get_ems_log_destination_vserver_legacy(self):

        self.mock_object(self.client,
                         'get_ontapi_version',
                         mock.Mock(return_value=(1, 15)))
        mock_list_vservers = self.mock_object(
            self.client,
            'list_vservers',
            mock.Mock(return_value=[fake.NODE_VSERVER_NAME]))

        result = self.client._get_ems_log_destination_vserver()

        mock_list_vservers.assert_called_once_with(vserver_type='node')
        self.assertEqual(fake.NODE_VSERVER_NAME, result)

    def test_get_ems_log_destination_no_cluster_creds(self):

        self.mock_object(self.client,
                         'get_ontapi_version',
                         mock.Mock(return_value=(1, 21)))
        mock_list_vservers = self.mock_object(
            self.client,
            'list_vservers',
            mock.Mock(side_effect=[[], [fake.VSERVER_NAME]]))

        result = self.client._get_ems_log_destination_vserver()

        mock_list_vservers.assert_has_calls([
            mock.call(vserver_type='admin'),
            mock.call(vserver_type='data')])
        self.assertEqual(fake.VSERVER_NAME, result)

    def test_get_ems_log_destination_vserver_not_found(self):

        self.mock_object(self.client,
                         'get_ontapi_version',
                         mock.Mock(return_value=(1, 21)))
        mock_list_vservers = self.mock_object(
            self.client,
            'list_vservers',
            mock.Mock(return_value=[]))

        self.assertRaises(exception.NotFound,
                          self.client._get_ems_log_destination_vserver)

        mock_list_vservers.assert_has_calls([
            mock.call(vserver_type='admin'),
            mock.call(vserver_type='data'),
            mock.call(vserver_type='node')])

    def test_send_ems_log_message(self):

        # Mock client lest we not be able to see calls on its copy.
        self.mock_object(
            copy, 'copy',
            mock.Mock(side_effect=[self.client, self.client.connection]))
        self.mock_object(self.client,
                         '_get_ems_log_destination_vserver',
                         mock.Mock(return_value=fake.ADMIN_VSERVER_NAME))
        self.mock_object(self.client, 'send_request')

        self.client.send_ems_log_message(fake.EMS_MESSAGE)

        self.client.send_request.assert_has_calls([
            mock.call('ems-autosupport-log', fake.EMS_MESSAGE)])
        self.assertEqual(1, client_cmode.LOG.debug.call_count)

    def test_send_ems_log_message_api_error(self):

        # Mock client lest we not be able to see calls on its copy.
        self.mock_object(
            copy, 'copy',
            mock.Mock(side_effect=[self.client, self.client.connection]))
        self.mock_object(self.client,
                         '_get_ems_log_destination_vserver',
                         mock.Mock(return_value=fake.ADMIN_VSERVER_NAME))
        self.mock_object(self.client, 'send_request', self._mock_api_error())

        self.client.send_ems_log_message(fake.EMS_MESSAGE)

        self.client.send_request.assert_has_calls([
            mock.call('ems-autosupport-log', fake.EMS_MESSAGE)])
        self.assertEqual(1, client_cmode.LOG.warning.call_count)

    def test_get_aggregate_none_specified(self):

        result = self.client.get_aggregate('')

        self.assertEqual({}, result)

    def test_get_aggregate(self):

        api_response = netapp_api.NaElement(
            fake.AGGR_GET_ITER_SSC_RESPONSE).get_child_by_name(
            'attributes-list').get_children()
        self.mock_object(self.client,
                         '_get_aggregates',
                         mock.Mock(return_value=api_response))

        result = self.client.get_aggregate(fake.SHARE_AGGREGATE_NAME)

        desired_attributes = {
            'aggr-attributes': {
                'aggregate-name': None,
                'aggr-raid-attributes': {
                    'raid-type': None,
                    'is-hybrid': None,
                },
            },
        }
        self.client._get_aggregates.assert_has_calls([
            mock.call(
                aggregate_names=[fake.SHARE_AGGREGATE_NAME],
                desired_attributes=desired_attributes)])

        expected = {
            'name': fake.SHARE_AGGREGATE_NAME,
            'raid-type': 'raid_dp',
            'is-hybrid': False,
        }
        self.assertEqual(expected, result)

    def test_get_aggregate_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_aggregate(fake.SHARE_AGGREGATE_NAME)

        self.assertEqual({}, result)

    def test_get_aggregate_api_error(self):

        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(side_effect=self._mock_api_error()))

        result = self.client.get_aggregate(fake.SHARE_AGGREGATE_NAME)

        self.assertEqual({}, result)

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

    def test_get_aggregate_disk_types_not_found(self):

        mock_get_aggregate_disk_types = self.mock_object(
            self.client, '_get_aggregate_disk_types',
            mock.Mock(return_value=set()))

        result = self.client.get_aggregate_disk_types(
            fake.SHARE_AGGREGATE_NAME)

        self.assertIsNone(result)
        mock_get_aggregate_disk_types.assert_called_once_with(
            fake.SHARE_AGGREGATE_NAME)

    def test_get_aggregate_disk_types_shared(self):

        self.client.features.add_feature('ADVANCED_DISK_PARTITIONING')
        mock_get_aggregate_disk_types = self.mock_object(
            self.client, '_get_aggregate_disk_types',
            mock.Mock(side_effect=[set(['SSD']), set(['SATA'])]))

        result = self.client.get_aggregate_disk_types(
            fake.SHARE_AGGREGATE_NAME)

        self.assertIsInstance(result, list)
        self.assertEqual(sorted(['SATA', 'SSD']), sorted(result))
        mock_get_aggregate_disk_types.assert_has_calls([
            mock.call(fake.SHARE_AGGREGATE_NAME),
            mock.call(fake.SHARE_AGGREGATE_NAME, shared=True),
        ])

    @ddt.data({
        'shared': False,
        'query_disk_raid_info': {
            'disk-aggregate-info': {
                'aggregate-name': fake.SHARE_AGGREGATE_NAME,
            },
        },
    }, {
        'shared': True,
        'query_disk_raid_info': {
            'disk-shared-info': {
                'aggregate-list': {
                    'shared-aggregate-info': {
                        'aggregate-name':
                        fake.SHARE_AGGREGATE_NAME,
                    },
                },
            },
        },
    })
    @ddt.unpack
    def test__get_aggregate_disk_types_ddt(self, shared, query_disk_raid_info):

        api_response = netapp_api.NaElement(
            fake.STORAGE_DISK_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client._get_aggregate_disk_types(
            fake.SHARE_AGGREGATE_NAME, shared=shared)

        storage_disk_get_iter_args = {
            'query': {
                'storage-disk-info': {
                    'disk-raid-info': query_disk_raid_info,
                },
            },
            'desired-attributes': {
                'storage-disk-info': {
                    'disk-raid-info': {
                        'effective-disk-type': None,
                    },
                },
            },
        }
        self.client.send_iter_request.assert_called_once_with(
            'storage-disk-get-iter', storage_disk_get_iter_args)

        expected = set(fake.SHARE_AGGREGATE_DISK_TYPES)
        self.assertEqual(expected, result)

    def test__get_aggregate_disk_types_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client._get_aggregate_disk_types(
            fake.SHARE_AGGREGATE_NAME)

        self.assertEqual(set(), result)

    def test__get_aggregate_disk_types_api_error(self):

        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(side_effect=self._mock_api_error()))

        result = self.client._get_aggregate_disk_types(
            fake.SHARE_AGGREGATE_NAME)

        self.assertEqual(set([]), result)

    def test_check_for_cluster_credentials(self):

        api_response = netapp_api.NaElement(fake.SYSTEM_NODE_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.check_for_cluster_credentials()

        self.assertTrue(result)

    def test_check_for_cluster_credentials_not_cluster(self):

        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(side_effect=self._mock_api_error(
                             netapp_api.EAPINOTFOUND)))

        result = self.client.check_for_cluster_credentials()

        self.assertFalse(result)

    def test_check_for_cluster_credentials_api_error(self):

        self.mock_object(self.client,
                         'send_iter_request',
                         self._mock_api_error())

        self.assertRaises(netapp_api.NaApiError,
                          self.client.check_for_cluster_credentials)

    def test_create_cluster_peer(self):

        self.mock_object(self.client, 'send_request')

        self.client.create_cluster_peer(['fake_address_1', 'fake_address_2'],
                                        'fake_user', 'fake_password',
                                        'fake_passphrase')

        cluster_peer_create_args = {
            'peer-addresses': [
                {'remote-inet-address': 'fake_address_1'},
                {'remote-inet-address': 'fake_address_2'},
            ],
            'user-name': 'fake_user',
            'password': 'fake_password',
            'passphrase': 'fake_passphrase',
        }
        self.client.send_request.assert_has_calls([
            mock.call('cluster-peer-create', cluster_peer_create_args,
                      enable_tunneling=False)])

    def test_get_cluster_peers(self):

        api_response = netapp_api.NaElement(
            fake.CLUSTER_PEER_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_cluster_peers()

        cluster_peer_get_iter_args = {}
        self.client.send_iter_request.assert_has_calls([
            mock.call('cluster-peer-get-iter', cluster_peer_get_iter_args)])

        expected = [{
            'active-addresses': [
                fake.CLUSTER_ADDRESS_1,
                fake.CLUSTER_ADDRESS_2
            ],
            'availability': 'available',
            'cluster-name': fake.CLUSTER_NAME,
            'cluster-uuid': 'fake_uuid',
            'peer-addresses': [fake.CLUSTER_ADDRESS_1],
            'remote-cluster-name': fake.REMOTE_CLUSTER_NAME,
            'serial-number': 'fake_serial_number',
            'timeout': '60',
        }]

        self.assertEqual(expected, result)

    def test_get_cluster_peers_single(self):

        api_response = netapp_api.NaElement(
            fake.CLUSTER_PEER_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        self.client.get_cluster_peers(remote_cluster_name=fake.CLUSTER_NAME)

        cluster_peer_get_iter_args = {
            'query': {
                'cluster-peer-info': {
                    'remote-cluster-name': fake.CLUSTER_NAME,
                }
            },
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('cluster-peer-get-iter', cluster_peer_get_iter_args)])

    def test_get_cluster_peers_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_cluster_peers(
            remote_cluster_name=fake.CLUSTER_NAME)

        self.assertEqual([], result)
        self.assertTrue(self.client.send_iter_request.called)

    def test_delete_cluster_peer(self):

        self.mock_object(self.client, 'send_request')

        self.client.delete_cluster_peer(fake.CLUSTER_NAME)

        cluster_peer_delete_args = {'cluster-name': fake.CLUSTER_NAME}
        self.client.send_request.assert_has_calls([
            mock.call('cluster-peer-delete', cluster_peer_delete_args,
                      enable_tunneling=False)])

    def test_get_cluster_peer_policy(self):

        self.client.features.add_feature('CLUSTER_PEER_POLICY')

        api_response = netapp_api.NaElement(
            fake.CLUSTER_PEER_POLICY_GET_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_cluster_peer_policy()

        expected = {
            'is-unauthenticated-access-permitted': False,
            'passphrase-minimum-length': 8
        }
        self.assertEqual(expected, result)
        self.assertTrue(self.client.send_request.called)

    def test_get_cluster_peer_policy_not_supported(self):

        result = self.client.get_cluster_peer_policy()

        self.assertEqual({}, result)

    def test_set_cluster_peer_policy_not_supported(self):

        self.mock_object(self.client, 'send_request')

        self.client.set_cluster_peer_policy()

        self.assertFalse(self.client.send_request.called)

    def test_set_cluster_peer_policy_no_arguments(self):

        self.client.features.add_feature('CLUSTER_PEER_POLICY')
        self.mock_object(self.client, 'send_request')

        self.client.set_cluster_peer_policy()

        self.assertFalse(self.client.send_request.called)

    def test_set_cluster_peer_policy(self):

        self.client.features.add_feature('CLUSTER_PEER_POLICY')
        self.mock_object(self.client, 'send_request')

        self.client.set_cluster_peer_policy(
            is_unauthenticated_access_permitted=True,
            passphrase_minimum_length=12)

        cluster_peer_policy_modify_args = {
            'is-unauthenticated-access-permitted': 'true',
            'passphrase-minlength': '12',
        }
        self.client.send_request.assert_has_calls([
            mock.call('cluster-peer-policy-modify',
                      cluster_peer_policy_modify_args)])

    @ddt.data(None, 'cluster_name')
    def test_create_vserver_peer(self, cluster_name):

        self.mock_object(self.client, 'send_request')

        self.client.create_vserver_peer(fake.VSERVER_NAME,
                                        fake.VSERVER_PEER_NAME,
                                        peer_cluster_name=cluster_name)

        vserver_peer_create_args = {
            'vserver': fake.VSERVER_NAME,
            'peer-vserver': fake.VSERVER_PEER_NAME,
            'applications': [
                {'vserver-peer-application': 'snapmirror'},
            ],
        }
        if cluster_name:
            vserver_peer_create_args['peer-cluster'] = cluster_name

        self.client.send_request.assert_has_calls([
            mock.call('vserver-peer-create', vserver_peer_create_args,
                      enable_tunneling=False)])

    def test_delete_vserver_peer(self):

        self.mock_object(self.client, 'send_request')

        self.client.delete_vserver_peer('fake_vserver', 'fake_vserver_peer')

        vserver_peer_delete_args = {
            'vserver': 'fake_vserver',
            'peer-vserver': 'fake_vserver_peer',
        }
        self.client.send_request.assert_has_calls([
            mock.call('vserver-peer-delete', vserver_peer_delete_args,
                      enable_tunneling=False)])

    def test_accept_vserver_peer(self):

        self.mock_object(self.client, 'send_request')

        self.client.accept_vserver_peer('fake_vserver', 'fake_vserver_peer')

        vserver_peer_accept_args = {
            'vserver': 'fake_vserver',
            'peer-vserver': 'fake_vserver_peer',
        }
        self.client.send_request.assert_has_calls([
            mock.call('vserver-peer-accept', vserver_peer_accept_args,
                      enable_tunneling=False)])

    def test_get_vserver_peers(self):

        api_response = netapp_api.NaElement(
            fake.VSERVER_PEER_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_vserver_peers(
            vserver_name=fake.VSERVER_NAME,
            peer_vserver_name=fake.VSERVER_NAME_2)

        vserver_peer_get_iter_args = {
            'query': {
                'vserver-peer-info': {
                    'vserver': fake.VSERVER_NAME,
                    'peer-vserver': fake.VSERVER_NAME_2,
                }
            },
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('vserver-peer-get-iter', vserver_peer_get_iter_args)])

        expected = [{
            'vserver': 'fake_vserver',
            'peer-vserver': 'fake_vserver_2',
            'peer-state': 'peered',
            'peer-cluster': 'fake_cluster'
        }]
        self.assertEqual(expected, result)

    def test_get_vserver_peers_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_vserver_peers(
            vserver_name=fake.VSERVER_NAME,
            peer_vserver_name=fake.VSERVER_NAME_2)

        self.assertEqual([], result)
        self.assertTrue(self.client.send_iter_request.called)

    def test_ensure_snapmirror_v2(self):

        self.assertIsNone(self.client._ensure_snapmirror_v2())

    def test_ensure_snapmirror_v2_not_supported(self):

        self.client.features.add_feature('SNAPMIRROR_V2', supported=False)

        self.assertRaises(exception.NetAppException,
                          self.client._ensure_snapmirror_v2)

    @ddt.data({'schedule': 'fake_schedule', 'policy': 'fake_policy'},
              {'schedule': None, 'policy': None})
    @ddt.unpack
    def test_create_snapmirror(self, schedule, policy):
        self.mock_object(self.client, 'send_request')

        self.client.create_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME,
            na_utils.DATA_PROTECTION_TYPE, schedule=schedule, policy=policy)

        snapmirror_create_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
            'relationship-type': na_utils.DATA_PROTECTION_TYPE,
        }
        if schedule:
            snapmirror_create_args['schedule'] = schedule
        if policy:
            snapmirror_create_args['policy'] = policy
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-create', snapmirror_create_args)])

    def test_create_snapmirror_already_exists(self):
        mock_send_req = mock.Mock(side_effect=netapp_api.NaApiError(
            code=netapp_api.ERELATION_EXISTS))
        self.mock_object(self.client, 'send_request', mock_send_req)

        self.client.create_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME,
            na_utils.DATA_PROTECTION_TYPE)

        snapmirror_create_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
            'relationship-type': na_utils.DATA_PROTECTION_TYPE,
            'policy': na_utils.MIRROR_ALL_SNAP_POLICY,
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-create', snapmirror_create_args)])

    def test_create_snapmirror_error(self):
        mock_send_req = mock.Mock(side_effect=netapp_api.NaApiError(
            code=0))
        self.mock_object(self.client, 'send_request', mock_send_req)

        self.assertRaises(netapp_api.NaApiError,
                          self.client.create_snapmirror_vol,
                          fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
                          fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME,
                          na_utils.DATA_PROTECTION_TYPE)
        self.assertTrue(self.client.send_request.called)

    def test_create_snapmirror_svm(self):
        self.mock_object(self.client, 'send_request')

        self.client.create_snapmirror_svm(fake.SM_SOURCE_VSERVER,
                                          fake.SM_DEST_VSERVER,
                                          max_transfer_rate='fake_xfer_rate')

        snapmirror_create_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'relationship-type': na_utils.DATA_PROTECTION_TYPE,
            'identity-preserve': 'true',
            'max-transfer-rate': 'fake_xfer_rate'
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-create', snapmirror_create_args)])

    @ddt.data(
        {
            'source_snapshot': 'fake_snapshot',
            'transfer_priority': 'fake_priority'
        },
        {
            'source_snapshot': None,
            'transfer_priority': None
        }
    )
    @ddt.unpack
    def test_initialize_snapmirror(self, source_snapshot, transfer_priority):

        api_response = netapp_api.NaElement(fake.SNAPMIRROR_INITIALIZE_RESULT)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.initialize_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME,
            source_snapshot=source_snapshot,
            transfer_priority=transfer_priority)

        snapmirror_initialize_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
        }
        if source_snapshot:
            snapmirror_initialize_args['source-snapshot'] = source_snapshot
        if transfer_priority:
            snapmirror_initialize_args['transfer-priority'] = transfer_priority
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-initialize', snapmirror_initialize_args)])

        expected = {
            'operation-id': None,
            'status': 'succeeded',
            'jobid': None,
            'error-code': None,
            'error-message': None
        }
        self.assertEqual(expected, result)

    def test_initialize_snapmirror_svm(self):

        api_response = netapp_api.NaElement(fake.SNAPMIRROR_INITIALIZE_RESULT)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.initialize_snapmirror_svm(fake.SM_SOURCE_VSERVER,
                                                       fake.SM_DEST_VSERVER)

        snapmirror_initialize_args = {
            'source-location': fake.SM_SOURCE_VSERVER + ':',
            'destination-location': fake.SM_DEST_VSERVER + ':',
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-initialize', snapmirror_initialize_args)])

        expected = {
            'operation-id': None,
            'status': 'succeeded',
            'jobid': None,
            'error-code': None,
            'error-message': None
        }
        self.assertEqual(expected, result)

    @ddt.data({'snapmirror_destinations_list': [],
               'relationship_info_only': True},
              {'snapmirror_destinations_list': [],
               'relationship_info_only': False},
              {'snapmirror_destinations_list':
               [{'relationship-id': 'fake_relationship_id'}],
               'relationship_info_only': True},
              {'snapmirror_destinations_list':
               [{'relationship-id': 'fake_relationship_id'}],
               'relationship_info_only': False})
    @ddt.unpack
    def test_release_snapmirror_vol(self, relationship_info_only,
                                    snapmirror_destinations_list):
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'get_snapmirror_destinations',
                         mock.Mock(return_value=snapmirror_destinations_list))
        self.mock_object(self.client, '_ensure_snapmirror_v2')

        self.client.release_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME,
            relationship_info_only=relationship_info_only)

        snapmirror_release_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
            'relationship-info-only': ('true' if relationship_info_only
                                       else 'false'),
        }

        if len(snapmirror_destinations_list) == 1:
            snapmirror_release_args['relationship-id'] = 'fake_relationship_id'

        self.client.send_request.assert_called_once_with(
            'snapmirror-release', snapmirror_release_args,
            enable_tunneling=True)

    def test_release_snapmirror_vol_error_not_unique_relationship(self):
        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, 'get_snapmirror_destinations',
                         mock.Mock(return_value=[{'relationship-id': 'fake'},
                                                 {'relationship-id': 'fake'}]))

        self.assertRaises(exception.NetAppException,
                          self.client.release_snapmirror_vol,
                          fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
                          fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

    def test_release_snapmirror_svm(self):

        self.mock_object(self.client, 'send_request')
        self.mock_object(self.client, '_ensure_snapmirror_v2')

        self.client.release_snapmirror_svm(
            fake.SM_SOURCE_VSERVER, fake.SM_DEST_VSERVER)

        snapmirror_release_args = {
            'query': {
                'snapmirror-destination-info': {
                    'source-location': fake.SM_SOURCE_VSERVER + ':',
                    'destination-location': fake.SM_DEST_VSERVER + ':',
                },
            },
            'relationship-info-only': 'false',
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-release-iter', snapmirror_release_args,
                      enable_tunneling=False)])

    def test_quiesce_snapmirror(self):

        self.mock_object(self.client, 'send_request')

        self.client.quiesce_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

        snapmirror_quiesce_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-quiesce', snapmirror_quiesce_args)])

    def test_quiesce_snapmirror_svm(self):

        self.mock_object(self.client, 'send_request')

        self.client.quiesce_snapmirror_svm(
            fake.SM_SOURCE_VSERVER, fake.SM_DEST_VSERVER)

        snapmirror_quiesce_args = {
            'source-location': fake.SM_SOURCE_VSERVER + ':',
            'destination-location': fake.SM_DEST_VSERVER + ':',
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-quiesce', snapmirror_quiesce_args)])

    @ddt.data(True, False)
    def test_abort_snapmirror(self, clear_checkpoint):

        self.mock_object(self.client, 'send_request')

        self.client.abort_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME,
            clear_checkpoint=clear_checkpoint)

        snapmirror_abort_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
            'clear-checkpoint': 'true' if clear_checkpoint else 'false',
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-abort', snapmirror_abort_args)])

    def test_abort_snapmirror_svm(self):

        self.mock_object(self.client, 'send_request')

        self.client.abort_snapmirror_svm(
            fake.SM_SOURCE_VSERVER, fake.SM_DEST_VSERVER)

        snapmirror_abort_args = {
            'source-location': fake.SM_SOURCE_VSERVER + ':',
            'destination-location': fake.SM_DEST_VSERVER + ':',
            'clear-checkpoint': 'false'
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-abort', snapmirror_abort_args)])

    def test_abort_snapmirror_no_transfer_in_progress(self):
        mock_send_req = mock.Mock(side_effect=netapp_api.NaApiError(
            code=netapp_api.ENOTRANSFER_IN_PROGRESS))
        self.mock_object(self.client, 'send_request', mock_send_req)

        self.client.abort_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

        snapmirror_abort_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
            'clear-checkpoint': 'false',
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-abort', snapmirror_abort_args)])

    def test_abort_snapmirror_error(self):
        mock_send_req = mock.Mock(side_effect=netapp_api.NaApiError(code=0))
        self.mock_object(self.client, 'send_request', mock_send_req)

        self.assertRaises(netapp_api.NaApiError,
                          self.client.abort_snapmirror_vol,
                          fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
                          fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

    def test_break_snapmirror(self):

        self.mock_object(self.client, 'send_request')

        self.client.break_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

        snapmirror_break_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-break', snapmirror_break_args)])

    def test_break_snapmirror_svm(self):

        self.mock_object(self.client, 'send_request')

        self.client.break_snapmirror_svm(
            fake.SM_SOURCE_VSERVER, fake.SM_DEST_VSERVER)

        snapmirror_break_args = {
            'source-location': fake.SM_SOURCE_VSERVER + ':',
            'destination-location': fake.SM_DEST_VSERVER + ':',
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-break', snapmirror_break_args)])

    @ddt.data(
        {
            'schedule': 'fake_schedule',
            'policy': 'fake_policy',
            'tries': 5,
            'max_transfer_rate': 1024,
        },
        {
            'schedule': None,
            'policy': None,
            'tries': None,
            'max_transfer_rate': None,
        }
    )
    @ddt.unpack
    def test_modify_snapmirror(self, schedule, policy, tries,
                               max_transfer_rate):

        self.mock_object(self.client, 'send_request')

        self.client.modify_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME,
            schedule=schedule, policy=policy, tries=tries,
            max_transfer_rate=max_transfer_rate)

        snapmirror_modify_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
        }
        if schedule:
            snapmirror_modify_args['schedule'] = schedule
        if policy:
            snapmirror_modify_args['policy'] = policy
        if tries:
            snapmirror_modify_args['tries'] = tries
        if max_transfer_rate:
            snapmirror_modify_args['max-transfer-rate'] = max_transfer_rate
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-modify', snapmirror_modify_args)])

    def test_update_snapmirror(self):

        self.mock_object(self.client, 'send_request')

        self.client.update_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

        snapmirror_update_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-update', snapmirror_update_args)])

    def test_update_snapmirror_svm(self):

        self.mock_object(self.client, 'send_request')

        self.client.update_snapmirror_svm(
            fake.SM_SOURCE_VSERVER, fake.SM_DEST_VSERVER)

        snapmirror_update_args = {
            'source-location': fake.SM_SOURCE_VSERVER + ':',
            'destination-location': fake.SM_DEST_VSERVER + ':',
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-update', snapmirror_update_args)])

    def test_update_snapmirror_already_transferring(self):
        mock_send_req = mock.Mock(side_effect=netapp_api.NaApiError(
            code=netapp_api.ETRANSFER_IN_PROGRESS))
        self.mock_object(self.client, 'send_request', mock_send_req)

        self.client.update_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

        snapmirror_update_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-update', snapmirror_update_args)])

    def test_update_snapmirror_already_transferring_two(self):
        mock_send_req = mock.Mock(side_effect=netapp_api.NaApiError(
            code=netapp_api.EANOTHER_OP_ACTIVE))
        self.mock_object(self.client, 'send_request', mock_send_req)

        self.client.update_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

        snapmirror_update_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-update', snapmirror_update_args)])

    def test_update_snapmirror_error(self):
        mock_send_req = mock.Mock(side_effect=netapp_api.NaApiError(code=0))
        self.mock_object(self.client, 'send_request', mock_send_req)

        self.assertRaises(netapp_api.NaApiError,
                          self.client.update_snapmirror_vol,
                          fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
                          fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

    def test_delete_snapmirror(self):

        self.mock_object(self.client, 'send_request')

        self.client.delete_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

        snapmirror_delete_args = {
            'query': {
                'snapmirror-info': {
                    'source-vserver': fake.SM_SOURCE_VSERVER,
                    'source-volume': fake.SM_SOURCE_VOLUME,
                    'destination-vserver': fake.SM_DEST_VSERVER,
                    'destination-volume': fake.SM_DEST_VOLUME,
                }
            }
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-destroy-iter', snapmirror_delete_args)])

    def test_delete_snapmirror_svm(self):

        self.mock_object(self.client, 'send_request')

        self.client.delete_snapmirror_svm(
            fake.SM_SOURCE_VSERVER, fake.SM_DEST_VSERVER)

        snapmirror_delete_args = {
            'query': {
                'snapmirror-info': {
                    'source-location': fake.SM_SOURCE_VSERVER + ':',
                    'destination-location': fake.SM_DEST_VSERVER + ':',
                }
            }
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-destroy-iter', snapmirror_delete_args)])

    def test__get_snapmirrors(self):

        api_response = netapp_api.NaElement(fake.SNAPMIRROR_GET_ITER_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        desired_attributes = {
            'snapmirror-info': {
                'source-vserver': None,
                'source-volume': None,
                'destination-vserver': None,
                'destination-volume': None,
                'is-healthy': None,
            }
        }

        result = self.client._get_snapmirrors(
            source_vserver=fake.SM_SOURCE_VSERVER,
            source_volume=fake.SM_SOURCE_VOLUME,
            dest_vserver=fake.SM_DEST_VSERVER,
            dest_volume=fake.SM_DEST_VOLUME,
            desired_attributes=desired_attributes)

        snapmirror_get_iter_args = {
            'query': {
                'snapmirror-info': {
                    'source-vserver': fake.SM_SOURCE_VSERVER,
                    'source-volume': fake.SM_SOURCE_VOLUME,
                    'destination-vserver': fake.SM_DEST_VSERVER,
                    'destination-volume': fake.SM_DEST_VOLUME,
                },
            },
            'desired-attributes': {
                'snapmirror-info': {
                    'source-vserver': None,
                    'source-volume': None,
                    'destination-vserver': None,
                    'destination-volume': None,
                    'is-healthy': None,
                },
            },
        }
        self.client.send_iter_request.assert_has_calls([
            mock.call('snapmirror-get-iter', snapmirror_get_iter_args)])
        self.assertEqual(1, len(result))

    def test__get_snapmirrors_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client._get_snapmirrors()

        self.client.send_iter_request.assert_has_calls([
            mock.call('snapmirror-get-iter', {})])

        self.assertEqual([], result)

    def test_get_snapmirrors(self):

        api_response = netapp_api.NaElement(
            fake.SNAPMIRROR_GET_ITER_FILTERED_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        desired_attributes = ['source-vserver', 'source-volume',
                              'destination-vserver', 'destination-volume',
                              'is-healthy', 'mirror-state', 'schedule',
                              'relationship-status']

        result = self.client.get_snapmirrors(
            source_vserver=fake.SM_SOURCE_VSERVER,
            dest_vserver=fake.SM_DEST_VSERVER,
            source_volume=fake.SM_SOURCE_VOLUME,
            dest_volume=fake.SM_DEST_VOLUME,
            desired_attributes=desired_attributes)

        snapmirror_get_iter_args = {
            'query': {
                'snapmirror-info': {
                    'source-vserver': fake.SM_SOURCE_VSERVER,
                    'source-volume': fake.SM_SOURCE_VOLUME,
                    'destination-vserver': fake.SM_DEST_VSERVER,
                    'destination-volume': fake.SM_DEST_VOLUME,
                },
            },
            'desired-attributes': {
                'snapmirror-info': {
                    'source-vserver': None,
                    'source-volume': None,
                    'destination-vserver': None,
                    'destination-volume': None,
                    'is-healthy': None,
                    'mirror-state': None,
                    'schedule': None,
                    'relationship-status': None,
                },
            },
        }

        expected = [{
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
            'is-healthy': 'true',
            'mirror-state': 'snapmirrored',
            'schedule': 'daily',
            'relationship-status': 'idle'
        }]

        self.client.send_iter_request.assert_has_calls([
            mock.call('snapmirror-get-iter', snapmirror_get_iter_args)])
        self.assertEqual(expected, result)

    def test_get_snapmirrors_svm(self):

        api_response = netapp_api.NaElement(
            fake.SNAPMIRROR_GET_ITER_FILTERED_RESPONSE_2)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        desired_attributes = ['source-vserver', 'destination-vserver',
                              'relationship-status', 'mirror-state']

        result = self.client.get_snapmirrors_svm(
            source_vserver=fake.SM_SOURCE_VSERVER,
            dest_vserver=fake.SM_DEST_VSERVER,
            desired_attributes=desired_attributes)

        snapmirror_get_iter_args = {
            'query': {
                'snapmirror-info': {
                    'source-location': fake.SM_SOURCE_VSERVER + ':',
                    'destination-location': fake.SM_DEST_VSERVER + ':',
                },
            },
            'desired-attributes': {
                'snapmirror-info': {
                    'source-vserver': None,
                    'destination-vserver': None,
                    'relationship-status': None,
                    'mirror-state': None,
                },
            },
        }

        expected = [{
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'relationship-status': 'idle',
            'mirror-state': 'snapmirrored',
        }]

        self.client.send_iter_request.assert_has_calls([
            mock.call('snapmirror-get-iter', snapmirror_get_iter_args)])
        self.assertEqual(expected, result)

    @ddt.data(fake.SNAPMIRROR_GET_DESTINATIONS_ITER_FILTERED_RESPONSE,
              fake.NO_RECORDS_RESPONSE)
    def test_get_snapmirror_destinations_svm(self, api_response):
        self.mock_object(
            self.client, 'send_iter_request',
            mock.Mock(return_value=netapp_api.NaElement(api_response)))

        result = self.client.get_snapmirror_destinations_svm(
            source_vserver=fake.SM_SOURCE_VSERVER,
            dest_vserver=fake.SM_DEST_VSERVER)

        snapmirror_get_iter_args = {
            'query': {
                'snapmirror-destination-info': {
                    'source-location': fake.SM_SOURCE_VSERVER + ':',
                    'destination-location': fake.SM_DEST_VSERVER + ':',
                },
            },
        }

        if api_response == fake.NO_RECORDS_RESPONSE:
            expected = []
        else:
            expected = [{
                'source-vserver': fake.SM_SOURCE_VSERVER,
                'destination-vserver': fake.SM_DEST_VSERVER,
                'source-location': fake.SM_SOURCE_VSERVER + ':',
                'destination-location': fake.SM_DEST_VSERVER + ':',
                'relationship-id': 'fake_relationship_id',
            }]

        self.client.send_iter_request.assert_has_calls([
            mock.call('snapmirror-get-destination-iter',
                      snapmirror_get_iter_args)])
        self.assertEqual(expected, result)

    def test_resume_snapmirror(self):
        self.mock_object(self.client, 'send_request')

        self.client.resume_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

        snapmirror_resume_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-resume', snapmirror_resume_args)])

    def test_resume_snapmirror_svm(self):
        self.mock_object(self.client, 'send_request')

        self.client.resume_snapmirror_svm(
            fake.SM_SOURCE_VSERVER, fake.SM_DEST_VSERVER)

        snapmirror_resume_args = {
            'source-location': fake.SM_SOURCE_VSERVER + ':',
            'destination-location': fake.SM_DEST_VSERVER + ':',
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-resume', snapmirror_resume_args)])

    def test_resume_snapmirror_not_quiesed(self):
        mock_send_req = mock.Mock(side_effect=netapp_api.NaApiError(
            code=netapp_api.ERELATION_NOT_QUIESCED))
        self.mock_object(self.client, 'send_request', mock_send_req)

        self.client.resume_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

        snapmirror_resume_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-resume', snapmirror_resume_args)])

    def test_resume_snapmirror_error(self):
        mock_send_req = mock.Mock(side_effect=netapp_api.NaApiError(code=0))
        self.mock_object(self.client, 'send_request', mock_send_req)

        self.assertRaises(netapp_api.NaApiError,
                          self.client.resume_snapmirror_vol,
                          fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
                          fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

    def test_resync_snapmirror(self):
        self.mock_object(self.client, 'send_request')

        self.client.resync_snapmirror_vol(
            fake.SM_SOURCE_VSERVER, fake.SM_SOURCE_VOLUME,
            fake.SM_DEST_VSERVER, fake.SM_DEST_VOLUME)

        snapmirror_resync_args = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-resync', snapmirror_resync_args)])

    def test_resync_snapmirror_svm(self):
        self.mock_object(self.client, 'send_request')

        self.client.resync_snapmirror_svm(
            fake.SM_SOURCE_VSERVER, fake.SM_DEST_VSERVER)

        snapmirror_resync_args = {
            'source-location': fake.SM_SOURCE_VSERVER + ':',
            'destination-location': fake.SM_DEST_VSERVER + ':',
        }
        self.client.send_request.assert_has_calls([
            mock.call('snapmirror-resync', snapmirror_resync_args)])

    @ddt.data('source', 'destination', None)
    def test_volume_has_snapmirror_relationships(self, snapmirror_rel_type):
        """Snapmirror relationships can be both ways."""

        vol = fake.FAKE_MANAGE_VOLUME
        snapmirror = {
            'source-vserver': fake.SM_SOURCE_VSERVER,
            'source-volume': fake.SM_SOURCE_VOLUME,
            'destination-vserver': fake.SM_DEST_VSERVER,
            'destination-volume': fake.SM_DEST_VOLUME,
            'is-healthy': 'true',
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
                side_effect=self._mock_api_error(netapp_api.EINTERNALERROR)))
        mock_exc_log = self.mock_object(client_cmode.LOG, 'exception')

        retval = self.client.volume_has_snapmirror_relationships(vol)

        self.assertFalse(retval)
        self.assertEqual(1, mock_get_snapmirrors_call.call_count)
        mock_get_snapmirrors_call.assert_has_calls(
            expected_get_snapmirrors_calls)
        self.assertTrue(mock_exc_log.called)

    @ddt.data(None, '12345')
    def test_list_snapmirror_snapshots(self, newer_than):

        api_response = netapp_api.NaElement(
            fake.SNAPSHOT_GET_ITER_SNAPMIRROR_RESPONSE)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.list_snapmirror_snapshots(fake.SHARE_NAME,
                                                       newer_than=newer_than)

        snapshot_get_iter_args = {
            'query': {
                'snapshot-info': {
                    'dependency': 'snapmirror',
                    'volume': fake.SHARE_NAME,
                },
            },
        }
        if newer_than:
            snapshot_get_iter_args['query']['snapshot-info']['access-time'] = (
                '>' + newer_than)
        self.client.send_iter_request.assert_has_calls([
            mock.call('snapshot-get-iter', snapshot_get_iter_args)])

        expected = [fake.SNAPSHOT_NAME]
        self.assertEqual(expected, result)

    @ddt.data(
        {'method_name': 'start_volume_move', 'ontapi_version': (1, 20)},
        {'method_name': 'start_volume_move', 'ontapi_version': (1, 110)},
        {'method_name': 'check_volume_move', 'ontapi_version': (1, 20)},
        {'method_name': 'check_volume_move', 'ontapi_version': (1, 110)}
    )
    @ddt.unpack
    def test_volume_move_method(self, method_name, ontapi_version):
        self.mock_object(client_base.NetAppBaseClient,
                         'get_ontapi_version',
                         mock.Mock(return_value=ontapi_version))

        self.client._init_features()

        method = getattr(self.client, method_name)
        self.mock_object(self.client, 'send_request')

        retval = method(fake.SHARE_NAME, fake.VSERVER_NAME,
                        fake.SHARE_AGGREGATE_NAME)

        expected_api_args = {
            'source-volume': fake.SHARE_NAME,
            'vserver': fake.VSERVER_NAME,
            'dest-aggr': fake.SHARE_AGGREGATE_NAME,
            'cutover-action': 'wait',
        }

        if ontapi_version >= (1, 110):
            expected_api_args['encrypt-destination'] = 'false'
            self.assertTrue(self.client.features.FLEXVOL_ENCRYPTION)
        else:
            self.assertFalse(self.client.features.FLEXVOL_ENCRYPTION)

        if method_name.startswith('check'):
            expected_api_args['perform-validation-only'] = 'true'

        self.assertIsNone(retval)
        self.client.send_request.assert_called_once_with(
            'volume-move-start', expected_api_args)

    def test_abort_volume_move(self):
        self.mock_object(self.client, 'send_request')

        retval = self.client.abort_volume_move(
            fake.SHARE_NAME, fake.VSERVER_NAME)

        expected_api_args = {
            'source-volume': fake.SHARE_NAME,
            'vserver': fake.VSERVER_NAME,
        }
        self.assertIsNone(retval)
        self.client.send_request.assert_called_once_with(
            'volume-move-trigger-abort', expected_api_args)

    @ddt.data(True, False)
    def test_trigger_volume_move_cutover_force(self, forced):
        self.mock_object(self.client, 'send_request')

        retval = self.client.trigger_volume_move_cutover(
            fake.SHARE_NAME, fake.VSERVER_NAME, force=forced)

        expected_api_args = {
            'source-volume': fake.SHARE_NAME,
            'vserver': fake.VSERVER_NAME,
            'force': 'true' if forced else 'false',
        }
        self.assertIsNone(retval)
        self.client.send_request.assert_called_once_with(
            'volume-move-trigger-cutover', expected_api_args)

    def test_get_volume_move_status_no_records(self):
        self.mock_object(self.client, 'send_iter_request')
        self.mock_object(self.client, '_has_records',
                         mock.Mock(return_value=False))

        self.assertRaises(exception.NetAppException,
                          self.client.get_volume_move_status,
                          fake.SHARE_NAME, fake.VSERVER_NAME)

        expected_api_args = {
            'query': {
                'volume-move-info': {
                    'volume': fake.SHARE_NAME,
                    'vserver': fake.VSERVER_NAME,
                },
            },
            'desired-attributes': {
                'volume-move-info': {
                    'percent-complete': None,
                    'estimated-completion-time': None,
                    'state': None,
                    'details': None,
                    'cutover-action': None,
                    'phase': None,
                },
            },
        }
        self.client.send_iter_request.assert_called_once_with(
            'volume-move-get-iter', expected_api_args)

    def test_get_volume_move_status(self):
        move_status = netapp_api.NaElement(fake.VOLUME_MOVE_GET_ITER_RESULT)
        self.mock_object(self.client, 'send_iter_request',
                         mock.Mock(return_value=move_status))

        actual_status_info = self.client.get_volume_move_status(
            fake.SHARE_NAME, fake.VSERVER_NAME)

        expected_api_args = {
            'query': {
                'volume-move-info': {
                    'volume': fake.SHARE_NAME,
                    'vserver': fake.VSERVER_NAME,
                },
            },
            'desired-attributes': {
                'volume-move-info': {
                    'percent-complete': None,
                    'estimated-completion-time': None,
                    'state': None,
                    'details': None,
                    'cutover-action': None,
                    'phase': None,
                },
            },
        }
        expected_status_info = {
            'percent-complete': '82',
            'estimated-completion-time': '1481919246',
            'state': 'healthy',
            'details': 'Cutover Completed::Volume move job finishing move',
            'cutover-action': 'retry_on_failure',
            'phase': 'finishing',
        }

        self.assertDictEqual(expected_status_info, actual_status_info)
        self.client.send_iter_request.assert_called_once_with(
            'volume-move-get-iter', expected_api_args)

    def test_qos_policy_group_exists_no_records(self):
        self.mock_object(self.client, 'qos_policy_group_get', mock.Mock(
            side_effect=exception.NetAppException))

        policy_exists = self.client.qos_policy_group_exists(
            'i-dont-exist-but-i-am')

        self.assertIs(False, policy_exists)

    def test_qos_policy_group_exists(self):
        self.mock_object(self.client, 'qos_policy_group_get',
                         mock.Mock(return_value=fake.QOS_POLICY_GROUP))

        policy_exists = self.client.qos_policy_group_exists(
            fake.QOS_POLICY_GROUP_NAME)

        self.assertIs(True, policy_exists)

    def test_qos_policy_group_get_no_permissions_to_execute_zapi(self):
        naapi_error = self._mock_api_error(code=netapp_api.EAPINOTFOUND,
                                           message='13005:Unable to find API')
        self.mock_object(self.client, 'send_request', naapi_error)

        self.assertRaises(exception.NetAppException,
                          self.client.qos_policy_group_get,
                          'possibly-valid-qos-policy')

    def test_qos_policy_group_get_other_zapi_errors(self):
        naapi_error = self._mock_api_error(code=netapp_api.EINTERNALERROR,
                                           message='13114:Internal error')
        self.mock_object(self.client, 'send_request', naapi_error)

        self.assertRaises(netapp_api.NaApiError,
                          self.client.qos_policy_group_get,
                          'possibly-valid-qos-policy')

    def test_qos_policy_group_get_none_found(self):
        no_records_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=no_records_response))

        self.assertRaises(exception.NetAppException,
                          self.client.qos_policy_group_get,
                          'non-existent-qos-policy')

        qos_policy_group_get_iter_args = {
            'query': {
                'qos-policy-group-info': {
                    'policy-group': 'non-existent-qos-policy',
                },
            },
            'desired-attributes': {
                'qos-policy-group-info': {
                    'policy-group': None,
                    'vserver': None,
                    'max-throughput': None,
                    'num-workloads': None
                },
            },
        }

        self.client.send_request.assert_called_once_with(
            'qos-policy-group-get-iter', qos_policy_group_get_iter_args, False)

    def test_qos_policy_group_get(self):
        api_response = netapp_api.NaElement(
            fake.QOS_POLICY_GROUP_GET_ITER_RESPONSE)
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))

        qos_info = self.client.qos_policy_group_get(fake.QOS_POLICY_GROUP_NAME)

        qos_policy_group_get_iter_args = {
            'query': {
                'qos-policy-group-info': {
                    'policy-group': fake.QOS_POLICY_GROUP_NAME,
                },
            },
            'desired-attributes': {
                'qos-policy-group-info': {
                    'policy-group': None,
                    'vserver': None,
                    'max-throughput': None,
                    'num-workloads': None
                },
            },
        }
        self.client.send_request.assert_called_once_with(
            'qos-policy-group-get-iter', qos_policy_group_get_iter_args, False)
        self.assertDictEqual(fake.QOS_POLICY_GROUP, qos_info)

    @ddt.data(None, fake.QOS_MAX_THROUGHPUT)
    def test_qos_policy_group_create(self, max_throughput):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=fake.PASSED_RESPONSE))

        self.client.qos_policy_group_create(
            fake.QOS_POLICY_GROUP_NAME, fake.VSERVER_NAME,
            max_throughput=max_throughput)

        qos_policy_group_create_args = {
            'policy-group': fake.QOS_POLICY_GROUP_NAME,
            'vserver': fake.VSERVER_NAME,
        }
        if max_throughput:
            qos_policy_group_create_args.update(
                {'max-throughput': max_throughput})

        self.client.send_request.assert_called_once_with(
            'qos-policy-group-create', qos_policy_group_create_args, False)

    def test_qos_policy_group_modify(self):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=fake.PASSED_RESPONSE))

        self.client.qos_policy_group_modify(fake.QOS_POLICY_GROUP_NAME,
                                            '3000iops')

        qos_policy_group_modify_args = {
            'policy-group': fake.QOS_POLICY_GROUP_NAME,
            'max-throughput': '3000iops',
        }

        self.client.send_request.assert_called_once_with(
            'qos-policy-group-modify', qos_policy_group_modify_args, False)

    def test_qos_policy_group_delete(self):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=fake.PASSED_RESPONSE))

        self.client.qos_policy_group_delete(fake.QOS_POLICY_GROUP_NAME)

        qos_policy_group_delete_args = {
            'policy-group': fake.QOS_POLICY_GROUP_NAME,
        }

        self.client.send_request.assert_called_once_with(
            'qos-policy-group-delete', qos_policy_group_delete_args, False)

    def test_qos_policy_group_rename(self):
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=fake.PASSED_RESPONSE))

        self.client.qos_policy_group_rename(
            fake.QOS_POLICY_GROUP_NAME, 'new_' + fake.QOS_POLICY_GROUP_NAME)

        qos_policy_group_rename_args = {
            'policy-group-name': fake.QOS_POLICY_GROUP_NAME,
            'new-name': 'new_' + fake.QOS_POLICY_GROUP_NAME,
        }

        self.client.send_request.assert_called_once_with(
            'qos-policy-group-rename', qos_policy_group_rename_args, False)

    def test_qos_policy_group_rename_noop(self):
        self.mock_object(self.client, 'send_request')

        # rename to same name = no-op
        self.client.qos_policy_group_rename(
            fake.QOS_POLICY_GROUP_NAME, fake.QOS_POLICY_GROUP_NAME)

        self.assertFalse(self.client.send_request.called)

    def test_mark_qos_policy_group_for_deletion_rename_failure(self):
        self.mock_object(self.client, 'qos_policy_group_exists',
                         mock.Mock(return_value=True))
        self.mock_object(self.client, 'qos_policy_group_rename',
                         mock.Mock(side_effect=netapp_api.NaApiError))
        self.mock_object(client_cmode.LOG, 'warning')
        self.mock_object(self.client, 'remove_unused_qos_policy_groups')

        retval = self.client.mark_qos_policy_group_for_deletion(
            fake.QOS_POLICY_GROUP_NAME)

        self.assertIsNone(retval)
        client_cmode.LOG.warning.assert_called_once()
        self.client.qos_policy_group_exists.assert_called_once_with(
            fake.QOS_POLICY_GROUP_NAME)
        self.client.qos_policy_group_rename.assert_called_once_with(
            fake.QOS_POLICY_GROUP_NAME,
            client_cmode.DELETED_PREFIX + fake.QOS_POLICY_GROUP_NAME)
        self.client.remove_unused_qos_policy_groups.assert_called_once_with()

    @ddt.data(True, False)
    def test_mark_qos_policy_group_for_deletion_policy_exists(self, exists):
        self.mock_object(self.client, 'qos_policy_group_exists',
                         mock.Mock(return_value=exists))
        self.mock_object(self.client, 'qos_policy_group_rename')
        mock_remove_unused_policies = self.mock_object(
            self.client, 'remove_unused_qos_policy_groups')
        self.mock_object(client_cmode.LOG, 'warning')

        retval = self.client.mark_qos_policy_group_for_deletion(
            fake.QOS_POLICY_GROUP_NAME)

        self.assertIsNone(retval)

        if exists:
            self.client.qos_policy_group_rename.assert_called_once_with(
                fake.QOS_POLICY_GROUP_NAME,
                client_cmode.DELETED_PREFIX + fake.QOS_POLICY_GROUP_NAME)
            mock_remove_unused_policies.assert_called_once_with()
        else:
            self.assertFalse(self.client.qos_policy_group_rename.called)
            self.assertFalse(
                self.client.remove_unused_qos_policy_groups.called)
        self.assertFalse(client_cmode.LOG.warning.called)

    @ddt.data(True, False)
    def test_remove_unused_qos_policy_groups_with_failure(self, failed):

        if failed:
            args = mock.Mock(side_effect=netapp_api.NaApiError)
        else:
            args = mock.Mock(return_value=fake.PASSED_FAILED_ITER_RESPONSE)

        self.mock_object(self.client, 'send_request', args)
        self.mock_object(client_cmode.LOG, 'debug')

        retval = self.client.remove_unused_qos_policy_groups()

        qos_policy_group_delete_iter_args = {
            'query': {
                'qos-policy-group-info': {
                    'policy-group': '%s*' % client_cmode.DELETED_PREFIX,
                }
            },
            'max-records': 3500,
            'continue-on-failure': 'true',
            'return-success-list': 'false',
            'return-failure-list': 'false',
        }

        self.assertIsNone(retval)
        self.client.send_request.assert_called_once_with(
            'qos-policy-group-delete-iter',
            qos_policy_group_delete_iter_args, False)
        self.assertIs(failed, client_cmode.LOG.debug.called)

    def test_get_cluster_name(self):
        api_response = netapp_api.NaElement(
            fake.CLUSTER_GET_CLUSTER_NAME)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))
        api_args = {
            'desired-attributes': {
                'cluster-identity-info': {
                    'cluster-name': None,
                }
            }
        }
        result = self.client.get_cluster_name()

        self.assertEqual(fake.CLUSTER_NAME, result)
        self.client.send_request.assert_called_once_with(
            'cluster-identity-get', api_args, enable_tunneling=False)

    @ddt.data('fake_snapshot_name', None)
    def test_check_volume_clone_split_completed(self, get_clone_parent):
        volume_name = fake.SHARE_NAME
        mock_get_vol_clone_parent = self.mock_object(
            self.client, 'get_volume_clone_parent_snaphot',
            mock.Mock(return_value=get_clone_parent))

        result = self.client.check_volume_clone_split_completed(volume_name)

        mock_get_vol_clone_parent.assert_called_once_with(volume_name)
        expected_result = get_clone_parent is None
        self.assertEqual(expected_result, result)

    def test_rehost_volume(self):
        volume_name = fake.SHARE_NAME
        vserver = fake.VSERVER_NAME
        dest_vserver = fake.VSERVER_NAME_2
        api_args = {
            'volume': volume_name,
            'vserver': vserver,
            'destination-vserver': dest_vserver,
        }
        self.mock_object(self.client, 'send_request')

        self.client.rehost_volume(volume_name, vserver, dest_vserver)

        self.client.send_request.assert_called_once_with('volume-rehost',
                                                         api_args)

    @ddt.data(
        {'fake_api_response': fake.VOLUME_GET_ITER_PARENT_SNAP_EMPTY_RESPONSE,
         'expected_snapshot_name': None},
        {'fake_api_response': fake.VOLUME_GET_ITER_PARENT_SNAP_RESPONSE,
         'expected_snapshot_name': fake.SNAPSHOT_NAME},
        {'fake_api_response': fake.NO_RECORDS_RESPONSE,
         'expected_snapshot_name': None})
    @ddt.unpack
    def test_get_volume_clone_parent_snaphot(self, fake_api_response,
                                             expected_snapshot_name):

        api_response = netapp_api.NaElement(fake_api_response)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_volume_clone_parent_snaphot(fake.SHARE_NAME)

        expected_api_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME
                    }
                }
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-clone-attributes': {
                        'volume-clone-parent-attributes': {
                            'snapshot-name': ''
                        }
                    }
                }
            }
        }
        self.client.send_iter_request.assert_called_once_with(
            'volume-get-iter', expected_api_args)
        self.assertEqual(expected_snapshot_name, result)

    def test_set_qos_adaptive_policy_group_for_volume(self):

        self.client.features.add_feature('ADAPTIVE_QOS')

        self.mock_object(self.client, 'send_request')

        self.client.set_qos_adaptive_policy_group_for_volume(
            fake.SHARE_NAME,
            fake.QOS_POLICY_GROUP_NAME)

        volume_modify_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME,
                    },
                },
            },
            'attributes': {
                'volume-attributes': {
                    'volume-qos-attributes': {
                        'adaptive-policy-group-name':
                            fake.QOS_POLICY_GROUP_NAME,
                    },
                },
            },
        }
        self.client.send_request.assert_called_once_with(
            'volume-modify-iter', volume_modify_iter_args)

    def test_get_nfs_config(self):
        api_args = {
            'query': {
                'nfs-info': {
                    'vserver': 'vserver',
                },
            },
            'desired-attributes': {
                'nfs-info': {
                    'field': None,
                },
            },
        }
        api_response = netapp_api.NaElement(
            fake.NFS_CONFIG_SERVER_RESULT)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))
        self.mock_object(self.client,
                         'parse_nfs_config',
                         mock.Mock(return_value=None))

        self.client.get_nfs_config(['field'], 'vserver')

        self.client.send_request.assert_called_once_with(
            'nfs-service-get-iter', api_args)

    def test_get_nfs_config_default(self):
        api_response = netapp_api.NaElement(
            fake.NFS_CONFIG_DEFAULT_RESULT)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))
        self.mock_object(self.client,
                         'parse_nfs_config',
                         mock.Mock(return_value=None))

        self.client.get_nfs_config_default(['field'])

        self.client.send_request.assert_called_once_with(
            'nfs-service-get-create-defaults', None)

    @ddt.data(
        {'nfs_info': fake.NFS_CONFIG_SERVER_RESULT,
         'desired_args': ['tcp-max-xfer-size'],
         'expected_nfs': {
             'tcp-max-xfer-size': '65536',
         }},
        {'nfs_info': fake.NFS_CONFIG_SERVER_RESULT,
         'desired_args': ['udp-max-xfer-size'],
         'expected_nfs': {
             'udp-max-xfer-size': '32768',
         }},
        {'nfs_info': fake.NFS_CONFIG_SERVER_RESULT,
         'desired_args': ['tcp-max-xfer-size', 'udp-max-xfer-size'],
         'expected_nfs': {
             'tcp-max-xfer-size': '65536',
             'udp-max-xfer-size': '32768',
         }},
        {'nfs_info': fake.NFS_CONFIG_SERVER_RESULT,
         'desired_args': [],
         'expected_nfs': {}})
    @ddt.unpack
    def test_parse_nfs_config(self, nfs_info, desired_args, expected_nfs):
        parent_elem = netapp_api.NaElement(nfs_info).get_child_by_name(
            'attributes-list')

        nfs_config = self.client.parse_nfs_config(parent_elem, desired_args)

        self.assertDictEqual(nfs_config, expected_nfs)

    @ddt.data(fake.NO_RECORDS_RESPONSE,
              fake.VSERVER_GET_ITER_RESPONSE_INFO)
    def test_get_vserver_info(self, api_response):
        self.mock_object(self.client, 'send_iter_request',
                         mock.Mock(
                             return_value=netapp_api.NaElement(
                                 api_response)))

        result = self.client.get_vserver_info(fake.VSERVER_NAME)

        expected_api_args = {
            'query': {
                'vserver-info': {
                    'vserver-name': fake.VSERVER_NAME,
                },
            },
            'desired-attributes': {
                'vserver-info': {
                    'vserver-name': None,
                    'vserver-subtype': None,
                    'state': None,
                    'operational-state': None,
                },
            },
        }
        self.client.send_iter_request.assert_called_once_with(
            'vserver-get-iter', expected_api_args)
        if api_response == fake.NO_RECORDS_RESPONSE:
            self.assertIsNone(result)
        else:
            self.assertDictEqual(fake.VSERVER_INFO, result)

    @ddt.data({'discard_network': True, 'preserve_snapshots': False},
              {'discard_network': False, 'preserve_snapshots': True})
    @ddt.unpack
    def test_create_snapmirror_policy(self, discard_network,
                                      preserve_snapshots):
        api_response = netapp_api.NaElement(fake.PASSED_RESPONSE)
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))

        self.client.create_snapmirror_policy(
            fake.SNAPMIRROR_POLICY_NAME, discard_network_info=discard_network,
            preserve_snapshots=preserve_snapshots)

        expected_create_api_args = {
            'policy-name': fake.SNAPMIRROR_POLICY_NAME,
            'type': 'async_mirror',
        }
        if discard_network:
            expected_create_api_args['discard-configs'] = {
                'svmdr-config-obj': 'network'
            }
        expected_calls = [
            mock.call('snapmirror-policy-create', expected_create_api_args)
        ]

        if preserve_snapshots:
            expected_add_rules = {
                'policy-name': fake.SNAPMIRROR_POLICY_NAME,
                'snapmirror-label': 'all_source_snapshots',
                'keep': '1',
                'preserve': 'false'
            }
            expected_calls.append(mock.call('snapmirror-policy-add-rule',
                                            expected_add_rules))

        self.client.send_request.assert_has_calls(expected_calls)

    def test_delete_snapmirror_policy(self):
        api_response = netapp_api.NaElement(fake.PASSED_RESPONSE)
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))

        self.client.delete_snapmirror_policy(fake.SNAPMIRROR_POLICY_NAME)

        expected_api_args = {
            'policy-name': fake.SNAPMIRROR_POLICY_NAME,
        }

        self.client.send_request.assert_called_once_with(
            'snapmirror-policy-delete', expected_api_args)

    def test_delete_snapmirror_policy_not_found(self):
        self.mock_object(self.client, 'send_request',
                         self._mock_api_error(code=netapp_api.EOBJECTNOTFOUND))

        self.client.delete_snapmirror_policy(fake.SNAPMIRROR_POLICY_NAME)

        expected_api_args = {
            'policy-name': fake.SNAPMIRROR_POLICY_NAME,
        }

        self.client.send_request.assert_called_once_with(
            'snapmirror-policy-delete', expected_api_args)

    def test_get_snapmirror_policies(self):
        api_response = netapp_api.NaElement(
            fake.SNAPMIRROR_POLICY_GET_ITER_RESPONSE)
        self.mock_object(self.client, 'send_iter_request',
                         mock.Mock(return_value=api_response))
        result_elem = [fake.SNAPMIRROR_POLICY_NAME]

        result = self.client.get_snapmirror_policies(
            fake.VSERVER_NAME)

        expected_api_args = {
            'query': {
                'snapmirror-policy-info': {
                    'vserver-name': fake.VSERVER_NAME,
                },
            },
            'desired-attributes': {
                'snapmirror-policy-info': {
                    'policy-name': None,
                },
            },
        }

        self.client.send_iter_request.assert_called_once_with(
            'snapmirror-policy-get-iter', expected_api_args)
        self.assertEqual(result_elem, result)

    @ddt.data(True, False, None)
    def test_start_vserver(self, force):
        api_response = netapp_api.NaElement(fake.PASSED_RESPONSE)
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))

        self.client.start_vserver(fake.VSERVER_NAME, force=force)

        expected_api_args = {
            'vserver-name': fake.VSERVER_NAME,
        }
        if force is not None:
            expected_api_args['force'] = 'true' if force is True else 'false'

        self.client.send_request.assert_called_once_with(
            'vserver-start', expected_api_args, enable_tunneling=False)

    def test_start_vserver_already_started(self):
        self.mock_object(self.client, 'send_request',
                         self._mock_api_error(
                             code=netapp_api.EVSERVERALREADYSTARTED))

        self.client.start_vserver(fake.VSERVER_NAME)

        expected_api_args = {
            'vserver-name': fake.VSERVER_NAME,
        }

        self.client.send_request.assert_called_once_with(
            'vserver-start', expected_api_args, enable_tunneling=False)

    def test_stop_vserver(self):
        api_response = netapp_api.NaElement(fake.PASSED_RESPONSE)
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=api_response))

        self.client.stop_vserver(fake.VSERVER_NAME)

        expected_api_args = {
            'vserver-name': fake.VSERVER_NAME,
        }

        self.client.send_request.assert_called_once_with(
            'vserver-stop', expected_api_args, enable_tunneling=False)

    def test_is_svm_dr_supported(self):
        self.client.features.add_feature('SVM_DR')

        result = self.client.is_svm_dr_supported()

        self.assertTrue(result)

    @ddt.data({'get_iter_response': fake.CIFS_SHARE_GET_ITER_RESPONSE,
               'expected_result': True},
              {'get_iter_response': fake.NO_RECORDS_RESPONSE,
               'expected_result': False})
    @ddt.unpack
    def test_cifs_share_exists(self, get_iter_response, expected_result):
        api_response = netapp_api.NaElement(get_iter_response)
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))
        fake_share_path = '/%s' % fake.SHARE_NAME

        result = self.client.cifs_share_exists(fake.SHARE_NAME)

        cifs_share_get_iter_args = {
            'query': {
                'cifs-share': {
                    'share-name': fake.SHARE_NAME,
                    'path': fake_share_path,
                },
            },
            'desired-attributes': {
                'cifs-share': {
                    'share-name': None
                }
            },
        }
        self.assertEqual(expected_result, result)
        self.client.send_iter_request.assert_called_once_with(
            'cifs-share-get-iter', cifs_share_get_iter_args)

    def test_get_volume_autosize_attributes(self):
        api_response = netapp_api.NaElement(fake.VOLUME_AUTOSIZE_GET_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_volume_autosize_attributes(fake.SHARE_NAME)

        expected_result = {}
        expected_keys = ['mode', 'grow-threshold-percent', 'minimum-size',
                         'shrink-threshold-percent', 'maximum-size']
        for key in expected_keys:
            expected_result[key] = fake.VOLUME_AUTOSIZE_ATTRS[key]

        self.assertEqual(expected_result, result)
        self.client.send_request.assert_called_once_with(
            'volume-autosize-get', {'volume': fake.SHARE_NAME})

    @ddt.data('server_to_server',
              'server_to_default_ad_site',
              'default_ad_site_to_default_ad_site',
              'default_ad_site_to_server')
    def test_modify_active_directory_security_service(self,
                                                      modify_ad_direction):
        if modify_ad_direction == 'server_to_server':
            curr_sec_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE)
            new_sec_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE_2)
        if modify_ad_direction == 'server_to_default_ad_site':
            curr_sec_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE)
            new_sec_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE_3)
        if modify_ad_direction == 'default_ad_site_to_default_ad_site':
            curr_sec_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE_3)
            new_sec_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE_4)
        if modify_ad_direction == 'default_ad_site_to_server':
            curr_sec_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE_4)
            new_sec_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE_2)

        # we don't support domain change, but this validation isn't made in
        # within this method
        new_sec_service['domain'] = curr_sec_service['domain']
        api_responses = [fake.PASSED_RESPONSE, fake.PASSED_RESPONSE,
                         fake.PASSED_RESPONSE]

        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=api_responses))
        self.mock_object(self.client, 'remove_preferred_dcs')
        self.mock_object(self.client, 'set_preferred_dc')
        self.mock_object(self.client, 'configure_cifs_options')
        differing_keys = {'password', 'user', 'server', 'default_ad_site'}

        self.client.modify_active_directory_security_service(
            fake.VSERVER_NAME, differing_keys, new_sec_service,
            curr_sec_service)

        cifs_server = self.client._get_cifs_server_name(fake.VSERVER_NAME)
        current_cifs_username = cifs_server + '\\' + curr_sec_service['user']
        set_pass_api_args = {
            'user-name': current_cifs_username,
            'user-password': new_sec_service['password']
        }
        user_rename_api_args = {
            'user-name': current_cifs_username,
            'new-user-name': new_sec_service['user']
        }

        self.client.send_request.assert_has_calls([
            mock.call('cifs-local-user-set-password', set_pass_api_args),
            mock.call('cifs-local-user-rename', user_rename_api_args)])

        if modify_ad_direction in ('default_ad_site_to_default_ad_site',
                                   'server_to_default_ad_site'):
            cifs_server_modify_args = {
                'admin-username': new_sec_service['user'],
                'admin-password': new_sec_service['password'],
                'force-account-overwrite': 'true',
                'cifs-server': cifs_server,
                'default-site': new_sec_service['default_ad_site'],
            }
            self.client.send_request.assert_has_calls([
                mock.call('cifs-server-modify', cifs_server_modify_args)])
            self.client.configure_cifs_options.assert_has_calls([
                mock.call(new_sec_service)])
        if modify_ad_direction in ('server_to_server',
                                   'server_to_default_ad_site'):
            self.client.remove_preferred_dcs.assert_called_once_with(
                curr_sec_service)
        if modify_ad_direction in ('server_to_server',
                                   'default_ad_site_to_server'):
            self.client.set_preferred_dc.assert_called_once_with(
                new_sec_service)
            self.client.configure_cifs_options.assert_has_calls([
                mock.call(new_sec_service)])

    @ddt.data(True, False)
    def test_modify_active_directory_security_service_error(
            self, cifs_set_password_failure):
        curr_sec_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE)
        new_sec_service = copy.deepcopy(fake.CIFS_SECURITY_SERVICE_2)
        # we don't support domain change, but this validation isn't made in
        # within this method
        new_sec_service['domain'] = curr_sec_service['domain']
        if cifs_set_password_failure:
            api_responses = [netapp_api.NaApiError(code='fake'),
                             fake.PASSED_RESPONSE]
        else:
            api_responses = [fake.PASSED_RESPONSE,
                             netapp_api.NaApiError(code='fake')]

        self.mock_object(self.client, 'send_request',
                         mock.Mock(side_effect=api_responses))
        differing_keys = {'password', 'user', 'server'}

        self.assertRaises(
            exception.NetAppException,
            self.client.modify_active_directory_security_service,
            fake.VSERVER_NAME, differing_keys, new_sec_service,
            curr_sec_service)

        cifs_server = self.client._get_cifs_server_name(fake.VSERVER_NAME)
        current_cifs_username = cifs_server + '\\' + curr_sec_service['user']
        set_pass_api_args = {
            'user-name': current_cifs_username,
            'user-password': new_sec_service['password']
        }
        user_rename_api_args = {
            'user-name': current_cifs_username,
            'new-user-name': new_sec_service['user']
        }

        if cifs_set_password_failure:
            send_request_calls = [
                mock.call('cifs-local-user-set-password', set_pass_api_args)]
        else:
            send_request_calls = [
                mock.call('cifs-local-user-set-password', set_pass_api_args),
                mock.call('cifs-local-user-rename', user_rename_api_args)
            ]

        self.client.send_request.assert_has_calls(send_request_calls)

    @ddt.data(False, True)
    def test_modify_ldap(self, api_not_found):
        current_ldap_service = fake.LDAP_AD_SECURITY_SERVICE
        new_ldap_service = fake.LDAP_LINUX_SECURITY_SERVICE
        config_name = hashlib.md5(
            new_ldap_service['id'].encode("latin-1")).hexdigest()
        api_result = (self._mock_api_error(code=netapp_api.EOBJECTNOTFOUND)
                      if api_not_found else mock.Mock())
        mock_create_client = self.mock_object(
            self.client, '_create_ldap_client')
        mock_send_request = self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=api_result))
        mock_delete_client = self.mock_object(
            self.client, '_delete_ldap_client',
            mock.Mock(return_value=api_result))

        self.client.modify_ldap(new_ldap_service, current_ldap_service)

        api_args = {'client-config': config_name, 'client-enabled': 'true'}
        mock_create_client.assert_called_once_with(new_ldap_service)
        mock_send_request.assert_has_calls([
            mock.call('ldap-config-delete'),
            mock.call('ldap-config-create', api_args)])
        mock_delete_client.assert_called_once_with(current_ldap_service)

    def test_modify_ldap_config_delete_failure(self):
        current_ldap_service = fake.LDAP_AD_SECURITY_SERVICE
        new_ldap_service = fake.LDAP_LINUX_SECURITY_SERVICE
        mock_create_client = self.mock_object(
            self.client, '_create_ldap_client')
        mock_send_request = self.mock_object(
            self.client, 'send_request', mock.Mock(
                side_effect=netapp_api.NaApiError(code=netapp_api.EAPIERROR)))
        mock_delete_client = self.mock_object(
            self.client, '_delete_ldap_client')

        self.assertRaises(exception.NetAppException,
                          self.client.modify_ldap,
                          new_ldap_service,
                          current_ldap_service)

        mock_create_client.assert_called_once_with(new_ldap_service)
        mock_send_request.assert_called_once_with('ldap-config-delete')
        mock_delete_client.assert_called_once_with(new_ldap_service)

    def test_modify_ldap_current_config_delete_error(self):
        current_ldap_service = fake.LDAP_AD_SECURITY_SERVICE
        new_ldap_service = fake.LDAP_LINUX_SECURITY_SERVICE
        config_name = hashlib.md5(
            new_ldap_service['id'].encode("latin-1")).hexdigest()
        mock_create_client = self.mock_object(
            self.client, '_create_ldap_client')
        mock_send_request = self.mock_object(
            self.client, 'send_request')
        mock_delete_client = self.mock_object(
            self.client, '_delete_ldap_client', mock.Mock(
                side_effect=netapp_api.NaApiError(code=netapp_api.EAPIERROR)))

        self.client.modify_ldap(new_ldap_service, current_ldap_service)

        api_args = {'client-config': config_name, 'client-enabled': 'true'}
        mock_create_client.assert_called_once_with(new_ldap_service)
        mock_send_request.assert_has_calls([
            mock.call('ldap-config-delete'),
            mock.call('ldap-config-create', api_args)])
        mock_delete_client.assert_called_once_with(current_ldap_service)

    def test_create_fpolicy_event(self):
        self.mock_object(self.client, 'send_request')

        self.client.create_fpolicy_event(fake.SHARE_NAME,
                                         fake.FPOLICY_EVENT_NAME,
                                         fake.FPOLICY_PROTOCOL,
                                         fake.FPOLICY_FILE_OPERATIONS_LIST)

        expected_args = {
            'event-name': fake.FPOLICY_EVENT_NAME,
            'protocol': fake.FPOLICY_PROTOCOL,
            'file-operations': [],
        }
        for file_op in fake.FPOLICY_FILE_OPERATIONS_LIST:
            expected_args['file-operations'].append(
                {'fpolicy-operation': file_op})

        self.client.send_request.assert_called_once_with(
            'fpolicy-policy-event-create', expected_args)

    @ddt.data(None, netapp_api.EEVENTNOTFOUND)
    def test_delete_fpolicy_event(self, send_request_error):
        if send_request_error:
            send_request_mock = mock.Mock(
                side_effect=self._mock_api_error(code=send_request_error))
        else:
            send_request_mock = mock.Mock()
        self.mock_object(self.client, 'send_request', send_request_mock)

        self.client.delete_fpolicy_event(fake.SHARE_NAME,
                                         fake.FPOLICY_EVENT_NAME)

        self.client.send_request.assert_called_once_with(
            'fpolicy-policy-event-delete',
            {'event-name': fake.FPOLICY_EVENT_NAME})

    def test_delete_fpolicy_event_error(self):
        eapi_error = self._mock_api_error(code=netapp_api.EAPIERROR)
        self.mock_object(
            self.client, 'send_request', mock.Mock(side_effect=eapi_error))

        self.assertRaises(exception.NetAppException,
                          self.client.delete_fpolicy_event,
                          fake.SHARE_NAME,
                          fake.FPOLICY_EVENT_NAME)

        self.client.send_request.assert_called_once_with(
            'fpolicy-policy-event-delete',
            {'event-name': fake.FPOLICY_EVENT_NAME})

    def test_get_fpolicy_events(self):
        api_response = netapp_api.NaElement(
            fake.FPOLICY_EVENT_GET_ITER_RESPONSE)
        self.mock_object(self.client, 'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_fpolicy_events(
            event_name=fake.FPOLICY_EVENT_NAME,
            protocol=fake.FPOLICY_PROTOCOL,
            file_operations=fake.FPOLICY_FILE_OPERATIONS_LIST)

        expected_options = {
            'event-name': fake.FPOLICY_EVENT_NAME,
            'protocol': fake.FPOLICY_PROTOCOL,
            'file-operations': []
        }
        for file_op in fake.FPOLICY_FILE_OPERATIONS_LIST:
            expected_options['file-operations'].append(
                {'fpolicy-operation': file_op})

        expected_args = {
            'query': {
                'fpolicy-event-options-config': expected_options,
            },
        }
        expected = [{
            'event-name': fake.FPOLICY_EVENT_NAME,
            'protocol': fake.FPOLICY_PROTOCOL,
            'file-operations': fake.FPOLICY_FILE_OPERATIONS_LIST
        }]

        self.assertEqual(expected, result)
        self.client.send_iter_request.assert_called_once_with(
            'fpolicy-policy-event-get-iter', expected_args)

    def test_create_fpolicy_policy(self):
        self.mock_object(self.client, 'send_request')

        self.client.create_fpolicy_policy(fake.FPOLICY_POLICY_NAME,
                                          fake.SHARE_NAME,
                                          [fake.FPOLICY_EVENT_NAME],
                                          engine=fake.FPOLICY_ENGINE)

        expected_args = {
            'policy-name': fake.FPOLICY_POLICY_NAME,
            'events': [],
            'engine-name': fake.FPOLICY_ENGINE
        }
        for event in [fake.FPOLICY_EVENT_NAME]:
            expected_args['events'].append(
                {'event-name': event})

        self.client.send_request.assert_called_once_with(
            'fpolicy-policy-create', expected_args)

    @ddt.data(None, netapp_api.EPOLICYNOTFOUND)
    def test_delete_fpolicy_policy(self, send_request_error):
        if send_request_error:
            send_request_mock = mock.Mock(
                side_effect=self._mock_api_error(code=send_request_error))
        else:
            send_request_mock = mock.Mock()
        self.mock_object(self.client, 'send_request', send_request_mock)

        self.client.delete_fpolicy_policy(
            fake.SHARE_NAME, fake.FPOLICY_POLICY_NAME)

        self.client.send_request.assert_called_once_with(
            'fpolicy-policy-delete',
            {'policy-name': fake.FPOLICY_POLICY_NAME})

    def test_delete_fpolicy_policy_error(self):
        eapi_error = self._mock_api_error(code=netapp_api.EAPIERROR)
        self.mock_object(
            self.client, 'send_request', mock.Mock(side_effect=eapi_error))

        self.assertRaises(exception.NetAppException,
                          self.client.delete_fpolicy_policy,
                          fake.SHARE_NAME,
                          fake.FPOLICY_POLICY_NAME)

        self.client.send_request.assert_called_once_with(
            'fpolicy-policy-delete',
            {'policy-name': fake.FPOLICY_POLICY_NAME})

    def test_get_fpolicy_policies(self):
        api_response = netapp_api.NaElement(
            fake.FPOLICY_POLICY_GET_ITER_RESPONSE)
        self.mock_object(self.client, 'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_fpolicy_policies(
            share_name=fake.SHARE_NAME,
            policy_name=fake.FPOLICY_POLICY_NAME,
            engine_name=fake.FPOLICY_ENGINE,
            event_names=[fake.FPOLICY_EVENT_NAME])

        expected_options = {
            'policy-name': fake.FPOLICY_POLICY_NAME,
            'engine-name': fake.FPOLICY_ENGINE,
            'events': []
        }
        for policy in [fake.FPOLICY_EVENT_NAME]:
            expected_options['events'].append(
                {'event-name': policy})

        expected_args = {
            'query': {
                'fpolicy-policy-info': expected_options,
            },
        }
        expected = [{
            'policy-name': fake.FPOLICY_POLICY_NAME,
            'engine-name': fake.FPOLICY_ENGINE,
            'events': [fake.FPOLICY_EVENT_NAME]
        }]

        self.assertEqual(expected, result)
        self.client.send_iter_request.assert_called_once_with(
            'fpolicy-policy-get-iter', expected_args)

    def test_create_fpolicy_scope(self):
        self.mock_object(self.client, 'send_request')

        self.client.create_fpolicy_scope(
            fake.FPOLICY_POLICY_NAME,
            fake.SHARE_NAME,
            extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
            extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE)

        expected_args = {
            'policy-name': fake.FPOLICY_POLICY_NAME,
            'shares-to-include': {
                'string': fake.SHARE_NAME,
            },
            'file-extensions-to-include': [],
            'file-extensions-to-exclude': [],
        }
        for file_ext in fake.FPOLICY_EXT_TO_INCLUDE_LIST:
            expected_args['file-extensions-to-include'].append(
                {'string': file_ext})
        for file_ext in fake.FPOLICY_EXT_TO_EXCLUDE_LIST:
            expected_args['file-extensions-to-exclude'].append(
                {'string': file_ext})

        self.client.send_request.assert_called_once_with(
            'fpolicy-policy-scope-create', expected_args)

    def test_modify_fpolicy_scope(self):
        self.mock_object(self.client, 'send_request')

        self.client.modify_fpolicy_scope(
            fake.SHARE_NAME,
            fake.FPOLICY_POLICY_NAME,
            shares_to_include=[fake.SHARE_NAME],
            extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
            extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE)

        expected_args = {
            'policy-name': fake.FPOLICY_POLICY_NAME,
            'file-extensions-to-include': [],
            'file-extensions-to-exclude': [],
            'shares-to-include': [{
                'string': fake.SHARE_NAME,
            }],
        }
        for file_ext in fake.FPOLICY_EXT_TO_INCLUDE_LIST:
            expected_args['file-extensions-to-include'].append(
                {'string': file_ext})
        for file_ext in fake.FPOLICY_EXT_TO_EXCLUDE_LIST:
            expected_args['file-extensions-to-exclude'].append(
                {'string': file_ext})

        self.client.send_request.assert_called_once_with(
            'fpolicy-policy-scope-modify', expected_args)

    @ddt.data(None, netapp_api.ESCOPENOTFOUND)
    def test_delete_fpolicy_scope(self, send_request_error):
        if send_request_error:
            send_request_mock = mock.Mock(
                side_effect=self._mock_api_error(code=send_request_error))
        else:
            send_request_mock = mock.Mock()
        self.mock_object(self.client, 'send_request', send_request_mock)

        self.client.delete_fpolicy_scope(fake.FPOLICY_POLICY_NAME)

        self.client.send_request.assert_called_once_with(
            'fpolicy-policy-scope-delete',
            {'policy-name': fake.FPOLICY_POLICY_NAME})

    def test_delete_fpolicy_scope_error(self):
        eapi_error = self._mock_api_error(code=netapp_api.EAPIERROR)
        self.mock_object(
            self.client, 'send_request', mock.Mock(side_effect=eapi_error))

        self.assertRaises(exception.NetAppException,
                          self.client.delete_fpolicy_scope,
                          fake.FPOLICY_POLICY_NAME)

        self.client.send_request.assert_called_once_with(
            'fpolicy-policy-scope-delete',
            {'policy-name': fake.FPOLICY_POLICY_NAME})

    def test_get_fpolicy_scopes(self):
        api_response = netapp_api.NaElement(
            fake.FPOLICY_SCOPE_GET_ITER_RESPONSE)
        self.mock_object(self.client, 'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_fpolicy_scopes(
            share_name=fake.SHARE_NAME,
            policy_name=fake.FPOLICY_POLICY_NAME,
            extensions_to_include=fake.FPOLICY_EXT_TO_INCLUDE,
            extensions_to_exclude=fake.FPOLICY_EXT_TO_EXCLUDE,
            shares_to_include=[fake.SHARE_NAME])

        expected_options = {
            'policy-name': fake.FPOLICY_POLICY_NAME,
            'shares-to-include': [{
                'string': fake.SHARE_NAME,
            }],
            'file-extensions-to-include': [],
            'file-extensions-to-exclude': [],
        }
        for file_ext in fake.FPOLICY_EXT_TO_INCLUDE_LIST:
            expected_options['file-extensions-to-include'].append(
                {'string': file_ext})
        for file_ext in fake.FPOLICY_EXT_TO_EXCLUDE_LIST:
            expected_options['file-extensions-to-exclude'].append(
                {'string': file_ext})

        expected_args = {
            'query': {
                'fpolicy-scope-config': expected_options,
            },
        }
        expected = [{
            'policy-name': fake.FPOLICY_POLICY_NAME,
            'file-extensions-to-include': fake.FPOLICY_EXT_TO_INCLUDE_LIST,
            'file-extensions-to-exclude': fake.FPOLICY_EXT_TO_EXCLUDE_LIST,
            'shares-to-include': [fake.SHARE_NAME],
        }]

        self.assertEqual(expected, result)
        self.client.send_iter_request.assert_called_once_with(
            'fpolicy-policy-scope-get-iter', expected_args)

    def test_enable_fpolicy_policy(self):
        self.mock_object(self.client, 'send_request')

        self.client.enable_fpolicy_policy(
            fake.SHARE_NAME, fake.FPOLICY_POLICY_NAME, 10)

        expected_args = {
            'policy-name': fake.FPOLICY_POLICY_NAME,
            'sequence-number': 10,
        }
        self.client.send_request.assert_called_once_with(
            'fpolicy-enable-policy', expected_args)

    @ddt.data(None, netapp_api.EPOLICYNOTFOUND)
    def test_disable_fpolicy_policy(self, send_request_error):
        if send_request_error:
            send_request_mock = mock.Mock(
                side_effect=self._mock_api_error(code=send_request_error))
        else:
            send_request_mock = mock.Mock()
        self.mock_object(self.client, 'send_request', send_request_mock)

        self.client.disable_fpolicy_policy(fake.FPOLICY_POLICY_NAME)

        expected_args = {
            'policy-name': fake.FPOLICY_POLICY_NAME,
        }
        self.client.send_request.assert_called_once_with(
            'fpolicy-disable-policy', expected_args)

    def test_disable_fpolicy_policy_error(self):
        eapi_error = self._mock_api_error(code=netapp_api.EAPIERROR)
        self.mock_object(
            self.client, 'send_request', mock.Mock(side_effect=eapi_error))

        self.assertRaises(exception.NetAppException,
                          self.client.disable_fpolicy_policy,
                          fake.FPOLICY_POLICY_NAME)

        self.client.send_request.assert_called_once_with(
            'fpolicy-disable-policy',
            {'policy-name': fake.FPOLICY_POLICY_NAME})

    def test_get_fpolicy_status(self):
        api_response = netapp_api.NaElement(
            fake.FPOLICY_POLICY_STATUS_GET_ITER_RESPONSE)
        self.mock_object(self.client, 'send_iter_request',
                         mock.Mock(return_value=api_response))

        result = self.client.get_fpolicy_policies_status(
            share_name=fake.SHARE_NAME,
            policy_name=fake.FPOLICY_POLICY_NAME)

        expected_args = {
            'query': {
                'fpolicy-policy-status-info': {
                    'policy-name': fake.FPOLICY_POLICY_NAME,
                    'status': 'true'
                },
            },
        }
        expected = [{
            'policy-name': fake.FPOLICY_POLICY_NAME,
            'status': True,
            'sequence-number': '1'
        }]

        self.assertEqual(expected, result)
        self.client.send_iter_request.assert_called_once_with(
            'fpolicy-policy-status-get-iter', expected_args)

    def test_is_svm_migrate_supported(self):
        self.client.features.add_feature('SVM_MIGRATE')

        result = self.client.is_svm_migrate_supported()

        self.assertTrue(result)

    @ddt.data(
        {"body": fake.FAKE_HTTP_BODY,
         "headers": fake.FAKE_HTTP_HEADER,
         "query": {},
         "url_params": fake.FAKE_URL_PARAMS
         },
        {"body": {},
         "headers": fake.FAKE_HTTP_HEADER,
         "query": fake.FAKE_HTTP_QUERY,
         "url_params": fake.FAKE_URL_PARAMS
         },
    )
    @ddt.unpack
    def test__format_request(self, body, headers, query, url_params):
        expected_result = {
            "body": body,
            "headers": headers,
            "query": query,
            "url_params": url_params
        }

        result = self.client._format_request(
            body, headers=headers, query=query, url_params=url_params)

        for k, v in expected_result.items():
            self.assertIn(k, result)
            self.assertEqual(result.get(k), v)

    @ddt.data(
        {"dest_ipspace": None, "check_only": True},
        {"dest_ipspace": "fake_dest_ipspace", "check_only": False},
    )
    @ddt.unpack
    def test_svm_migration_start(self, dest_ipspace, check_only):
        api_args = {
            "auto_cutover": False,
            "auto_source_cleanup": True,
            "check_only": check_only,
            "source": {
                "cluster": {"name": fake.CLUSTER_NAME},
                "svm": {"name": fake.VSERVER_NAME},
            },
            "destination": {
                "volume_placement": {
                    "aggregates": [fake.SHARE_AGGREGATE_NAME],
                },
            },
        }
        if dest_ipspace:
            ipspace_data = {
                "ipspace": {"name": dest_ipspace}
            }
            api_args['destination'].update(ipspace_data)

        self.mock_object(self.client, '_format_request',
                         mock.Mock(return_value=api_args))
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=fake.FAKE_MIGRATION_RESPONSE_WITH_JOB))

        result = self.client.svm_migration_start(
            fake.CLUSTER_NAME, fake.VSERVER_NAME, [fake.SHARE_AGGREGATE_NAME],
            dest_ipspace=dest_ipspace, check_only=check_only)

        self.client._format_request.assert_called_once_with(api_args)
        self.client.send_request.assert_called_once_with(
            'svm-migration-start', api_args=api_args, use_zapi=False)

        self.assertEqual(result, fake.FAKE_MIGRATION_RESPONSE_WITH_JOB)

    @ddt.data({"check_only": False}, {"check_only": True})
    def test_share_server_migration_start_failed(self, check_only):
        api_args = {}

        self.mock_object(self.client, '_format_request',
                         mock.Mock(return_value=api_args))
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(side_effect=netapp_api.NaApiError(message='fake')))

        self.assertRaises(
            netapp_api.NaApiError,
            self.client.svm_migration_start,
            fake.CLUSTER_NAME, fake.VSERVER_NAME,
            [fake.SHARE_AGGREGATE_NAME],
            check_only=check_only
        )

    def test_svm_migrate_complete(self):
        migration_id = 'ongoing_migration_id'
        request = {
            'action': 'cutover'
        }
        expected_url_params = {
            'svm_migration_id': migration_id
        }

        self.mock_object(self.client, '_format_request',
                         mock.Mock(return_value=request))
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=fake.FAKE_MIGRATION_RESPONSE_WITH_JOB))

        self.client.svm_migrate_complete(migration_id)

        self.client._format_request.assert_called_once_with(
            request, url_params=expected_url_params)
        self.client.send_request.assert_called_once_with(
            'svm-migration-complete', api_args=request, use_zapi=False)

    def test_get_job(self):
        request = {}
        job_uuid = 'fake_job_uuid'
        url_params = {
            'job_uuid': job_uuid
        }

        self.mock_object(self.client, '_format_request',
                         mock.Mock(return_value=request))
        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=fake.FAKE_JOB_SUCCESS_STATE))

        result = self.client.get_job(job_uuid)

        self.assertEqual(fake.FAKE_JOB_SUCCESS_STATE, result)
        self.client._format_request.assert_called_once_with(
            request, url_params=url_params)
        self.client.send_request.assert_called_once_with(
            'get-job', api_args=request, use_zapi=False)

    def test_svm_migrate_cancel(self):
        request = {}
        migration_id = 'fake_migration_uuid'
        url_params = {
            "svm_migration_id": migration_id
        }

        self.mock_object(self.client, '_format_request',
                         mock.Mock(return_value=request))
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=fake.FAKE_MIGRATION_RESPONSE_WITH_JOB))

        result = self.client.svm_migrate_cancel(migration_id)

        self.assertEqual(fake.FAKE_MIGRATION_RESPONSE_WITH_JOB, result)
        self.client._format_request.assert_called_once_with(
            request, url_params=url_params)
        self.client.send_request.assert_called_once_with(
            'svm-migration-cancel', api_args=request, use_zapi=False)

    def test_svm_migration_get(self):
        request = {}
        migration_id = 'fake_migration_uuid'
        url_params = {
            "svm_migration_id": migration_id
        }

        self.mock_object(self.client, '_format_request',
                         mock.Mock(return_value=request))
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=fake.FAKE_MIGRATION_JOB_SUCCESS))

        result = self.client.svm_migration_get(migration_id)

        self.assertEqual(fake.FAKE_MIGRATION_JOB_SUCCESS, result)
        self.client._format_request.assert_called_once_with(
            request, url_params=url_params)
        self.client.send_request.assert_called_once_with(
            'svm-migration-get', api_args=request, use_zapi=False)

    def test_svm_migrate_pause(self):
        request = {
            "action": "pause"
        }
        migration_id = 'fake_migration_uuid'
        url_params = {
            "svm_migration_id": migration_id
        }

        self.mock_object(self.client, '_format_request',
                         mock.Mock(return_value=request))
        self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=fake.FAKE_MIGRATION_RESPONSE_WITH_JOB))

        result = self.client.svm_migrate_pause(migration_id)

        self.assertEqual(fake.FAKE_MIGRATION_RESPONSE_WITH_JOB, result)
        self.client._format_request.assert_called_once_with(
            request, url_params=url_params)
        self.client.send_request.assert_called_once_with(
            'svm-migration-pause', api_args=request, use_zapi=False)

    def test_migration_check_job_state(self):
        self.mock_object(self.client, 'get_job',
                         mock.Mock(return_value=fake.FAKE_JOB_SUCCESS_STATE))

        result = self.client.get_migration_check_job_state(
            fake.FAKE_JOB_ID
        )

        self.assertEqual(result, fake.FAKE_JOB_SUCCESS_STATE)
        self.client.get_job.assert_called_once_with(fake.FAKE_JOB_ID)

    @ddt.data(netapp_api.ENFS_V4_0_ENABLED_MIGRATION_FAILURE,
              netapp_api.EVSERVER_MIGRATION_TO_NON_AFF_CLUSTER)
    def test_migration_check_job_state_failed(self, error_code):

        self.mock_object(
            self.client, 'get_job',
            mock.Mock(side_effect=netapp_api.NaApiError(code=error_code)))

        self.assertRaises(
            exception.NetAppException,
            self.client.get_migration_check_job_state,
            fake.FAKE_JOB_ID
        )
        self.client.get_job.assert_called_once_with(fake.FAKE_JOB_ID)

    @ddt.data(True, False)
    def test_get_volume_state(self, has_record):

        api_response = netapp_api.NaElement(
            fake.VOLUME_GET_ITER_STATE_RESPONSE)
        mock_send_iter_request = self.mock_object(
            self.client, 'send_iter_request',
            mock.Mock(return_value=api_response))
        mock_has_record = self.mock_object(self.client,
                                           '_has_records',
                                           mock.Mock(return_value=has_record))

        state = self.client.get_volume_state(fake.SHARE_NAME)

        volume_get_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME,
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-state-attributes': {
                        'state': None
                    }
                }
            },
        }
        mock_send_iter_request.assert_called_once_with(
            'volume-get-iter', volume_get_iter_args)
        mock_has_record.assert_called_once_with(api_response)
        if has_record:
            self.assertEqual('online', state)
        else:
            self.assertEqual('', state)

    @ddt.data(True, False)
    def test_is_flexgroup_volume(self, is_flexgroup):

        self.client.features.add_feature('FLEXGROUP', supported=True)
        api_response = netapp_api.NaElement(
            fake.VOLUME_GET_ITER_STYLE_FLEXGROUP_RESPONSE
            if is_flexgroup else fake.VOLUME_GET_ITER_STYLE_FLEXVOL_RESPONSE)
        mock_send_iter_request = self.mock_object(
            self.client, 'send_request',
            mock.Mock(return_value=api_response))
        mock_has_record = self.mock_object(self.client,
                                           '_has_records',
                                           mock.Mock(return_value=True))
        mock_is_style_extended_flexgroup = self.mock_object(
            na_utils, 'is_style_extended_flexgroup',
            mock.Mock(return_value=is_flexgroup))

        is_flexgroup_res = self.client.is_flexgroup_volume(fake.SHARE_NAME)

        volume_get_iter_args = {
            'query': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'name': fake.SHARE_NAME,
                    },
                },
            },
            'desired-attributes': {
                'volume-attributes': {
                    'volume-id-attributes': {
                        'style-extended': None,
                    },
                },
            },
        }
        mock_send_iter_request.assert_called_once_with(
            'volume-get-iter', volume_get_iter_args)
        mock_has_record.assert_called_once_with(api_response)
        mock_is_style_extended_flexgroup.assert_called_once_with(
            fake.FLEXGROUP_STYLE_EXTENDED
            if is_flexgroup else fake.FLEXVOL_STYLE_EXTENDED)
        self.assertEqual(is_flexgroup, is_flexgroup_res)

    def test_is_flexgroup_volume_not_found(self):

        self.client.features.add_feature('FLEXGROUP', supported=True)
        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(exception.StorageResourceNotFound,
                          self.client.is_flexgroup_volume,
                          fake.SHARE_NAME)

    def test_is_flexgroup_volume_not_unique(self):

        self.client.features.add_feature('FLEXGROUP', supported=True)
        api_response = netapp_api.NaElement(
            fake.VOLUME_GET_ITER_NOT_UNIQUE_RESPONSE)
        self.mock_object(self.client,
                         'send_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(exception.NetAppException,
                          self.client.is_flexgroup_volume,
                          fake.SHARE_NAME)

    def test_is_flexgroup_volume_unsupported(self):

        self.client.features.add_feature('FLEXGROUP', supported=False)

        result = self.client.is_flexgroup_volume(fake.SHARE_NAME)

        self.assertFalse(result)

    def test_is_flexgroup_supported(self):
        self.client.features.add_feature('FLEXGROUP')

        result = self.client.is_flexgroup_supported()

        self.assertTrue(result)

    def test_is_flexgroup_fan_out_supported(self):
        self.client.features.add_feature('FLEXGROUP_FAN_OUT')

        result = self.client.is_flexgroup_fan_out_supported()

        self.assertTrue(result)

    def test_get_job_state(self):

        api_response = netapp_api.NaElement(fake.JOB_GET_STATE_RESPONSE)
        mock_send_iter_request = self.mock_object(
            self.client, 'send_iter_request',
            mock.Mock(return_value=api_response))
        mock_has_record = self.mock_object(self.client,
                                           '_has_records',
                                           mock.Mock(return_value=True))

        job_state_res = self.client.get_job_state(fake.JOB_ID)

        job_get_iter_args = {
            'query': {
                'job-info': {
                    'job-id': fake.JOB_ID,
                },
            },
            'desired-attributes': {
                'job-info': {
                    'job-state': None,
                },
            },
        }
        mock_send_iter_request.assert_called_once_with(
            'job-get-iter', job_get_iter_args, enable_tunneling=False)
        mock_has_record.assert_called_once_with(api_response)
        self.assertEqual(fake.JOB_STATE, job_state_res)

    def test_get_job_state_not_found(self):

        api_response = netapp_api.NaElement(fake.NO_RECORDS_RESPONSE)
        self.mock_object(self.client,
                         '_has_records',
                         mock.Mock(return_value=False))
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(exception.NetAppException,
                          self.client.get_job_state,
                          fake.JOB_ID)

    def test_get_job_state_not_unique(self):

        api_response = netapp_api.NaElement(
            fake.JOB_GET_STATE_NOT_UNIQUE_RESPONSE)
        self.mock_object(self.client,
                         '_has_records',
                         mock.Mock(return_value=True))
        self.mock_object(self.client,
                         'send_iter_request',
                         mock.Mock(return_value=api_response))

        self.assertRaises(exception.NetAppException,
                          self.client.get_job_state,
                          fake.JOB_ID)

    def test_check_snaprestore_license_svm_scoped_notfound(self):
        self.mock_object(self.client,
                         'restore_snapshot',
                         mock.Mock(side_effect=netapp_api.NaApiError(
                                   code=netapp_api.EAPIERROR,
                                   message=fake.NO_SNAPRESTORE_LICENSE)))
        result = self.client.check_snaprestore_license()
        self.assertIs(False, result)

    def test_check_snaprestore_license_svm_scoped_found(self):
        self.mock_object(self.client,
                         'restore_snapshot',
                         mock.Mock(side_effect=netapp_api.NaApiError(
                                   code=netapp_api.EAPIERROR,
                                   message='Other error')))
        result = self.client.check_snaprestore_license()
        self.assertIs(True, result)

    def test_check_snaprestore_license_svm_scoped_found_exception(self):
        self.mock_object(client_cmode.LOG, 'exception')
        self.mock_object(self.client,
                         'restore_snapshot',
                         mock.Mock(return_value=None))

        self.assertRaises(
            exception.NetAppException,
            self.client.check_snaprestore_license)
        client_cmode.LOG.exception.assert_called_once()

    def test_get_svm_volumes_total_size(self):
        expected = 1

        request = {}

        api_args = {
            'svm.name': fake.VSERVER_NAME,
            'fields': 'size'
        }

        self.mock_object(self.client, '_format_request',
                         mock.Mock(return_value=api_args))

        self.mock_object(self.client, 'send_request',
                         mock.Mock(return_value=fake.FAKE_GET_VOLUME))

        result = self.client.get_svm_volumes_total_size(fake.VSERVER_NAME)

        self.client._format_request.assert_called_once_with(request,
                                                            query=api_args)
        self.client.send_request.assert_called_once_with(
            'svm-migration-get-progress', api_args=api_args, use_zapi=False)

        self.assertEqual(expected, result)
