# Copyright 2023 NetApp, Inc.
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
"""
Tests For NetApp Active IQ Weigher.
"""

from unittest import mock

import ddt
from oslo_config import cfg
from oslo_serialization import jsonutils
import requests

from manila import context
from manila import exception
from manila.scheduler.weighers import base_host
from manila.scheduler.weighers import netapp_aiq
from manila.share import utils
from manila import test
from manila.tests.scheduler import fakes
from manila.tests import utils as test_utils

CONF = cfg.CONF


@ddt.ddt
class NetAppAIQWeigherTestCase(test.TestCase):
    def setUp(self):
        super(NetAppAIQWeigherTestCase, self).setUp()
        self.weight_handler = base_host.HostWeightHandler(
            'manila.scheduler.weighers')

        netapp_aiq.LOG.debug = mock.Mock()
        netapp_aiq.LOG.error = mock.Mock()

        self.mock_session = mock.Mock()
        self.mock_session.get = mock.Mock()
        self.mock_session.post = mock.Mock()
        self.mock_session.delete = mock.Mock()
        self.mock_session.patch = mock.Mock()
        self.mock_session.put = mock.Mock()

        data = {
            'netapp_active_iq': {
                'aiq_hostname': "10.10.10.10",
                'aiq_transport_type': 'https',
                'aiq_ssl_verify': True,
                'aiq_ssl_cert_path': 'fake_cert',
                'aiq_username': 'fake_user',
                'aiq_password': 'fake_password',
                'aiq_eval_method': 1,
                'aiq_priority_order': 'ops'
            }
        }
        self.netapp_aiq_weigher = None
        with test_utils.create_temp_config_with_opts(data):
            self.netapp_aiq_weigher = netapp_aiq.NetAppAIQWeigher()

    def test__weigh_object(self):
        self.assertRaises(NotImplementedError,
                          self.netapp_aiq_weigher._weigh_object,
                          "fake", "fake")

    @ddt.data(
        {'resource_keys': ["fake_resource_key"], 'performance_level': None},
        {'resource_keys': ["fake_resource_key"],
         'performance_level': "fake_psl"},
        {'resource_keys': [], 'performance_level': 'fake_psl'})
    @ddt.unpack
    def test__weigh_active_iq(self, resource_keys, performance_level):
        weight_properties = {
            'size': 1,
            'share_type': {
                'extra_specs': {
                    "netapp:performance_service_level_name": "fake_name",
                }
            }
        }
        mock_get_psl_id = self.mock_object(
            self.netapp_aiq_weigher, '_get_performance_level_id',
            mock.Mock(return_value=performance_level))
        mock_get_resource_keys = self.mock_object(
            self.netapp_aiq_weigher, '_get_resource_keys',
            mock.Mock(return_value=resource_keys))
        mock_balance_aggregates = self.mock_object(
            self.netapp_aiq_weigher, '_balance_aggregates',
            mock.Mock(return_value=["1.0", "1.0"]))

        res = self.netapp_aiq_weigher._weigh_active_iq(
            fakes.FAKE_ACTIVE_IQ_WEIGHER_LIST, weight_properties)

        mock_get_psl_id.assert_called_once_with("fake_name")
        if not resource_keys or not performance_level:
            self.assertEqual([], res)
        else:
            self.assertEqual(["1.0", "1.0"], res)
        if performance_level:
            mock_get_resource_keys.assert_called_once_with(
                fakes.FAKE_ACTIVE_IQ_WEIGHER_LIST)
        else:
            mock_get_resource_keys.assert_not_called()
        if not resource_keys or not performance_level:
            mock_balance_aggregates.assert_not_called()
        else:
            mock_balance_aggregates.assert_called_once_with(
                resource_keys, 1, performance_level)

    @ddt.data(True, False)
    def test__get_url(self, ipv6):
        if ipv6:
            self.netapp_aiq_weigher.host = "2001:db8::"
        else:
            self.netapp_aiq_weigher.host = "1.1.1.1"
        self.netapp_aiq_weigher.port = "fake_port"
        self.netapp_aiq_weigher.protocol = "fake_protocol"

        res = self.netapp_aiq_weigher._get_url()

        if ipv6:
            self.assertEqual('fake_protocol://[2001:db8::]:fake_port/api/',
                             res)
        else:
            self.assertEqual('fake_protocol://1.1.1.1:fake_port/api/',
                             res)

    @ddt.data('get', 'post', 'delete', 'patch', 'put')
    def test__get_request_method(self, method):
        res = self.netapp_aiq_weigher._get_request_method(
            method, self.mock_session)

        if method == 'get':
            self.assertEqual(self.mock_session.get, res)
        elif method == 'post':
            self.assertEqual(self.mock_session.post, res)
        elif method == 'delete':
            self.assertEqual(self.mock_session.delete, res)
        elif method == 'put':
            self.assertEqual(self.mock_session.put, res)
        elif method == 'patch':
            self.assertEqual(self.mock_session.patch, res)

    def test__get_session_method(self):
        mock_session_builder = self.mock_object(
            requests, 'Session', mock.Mock(return_value=self.mock_session))
        mock__get_request_method = self.mock_object(
            self.netapp_aiq_weigher, '_get_request_method',
            mock.Mock(return_value=self.mock_session.post))

        res = self.netapp_aiq_weigher._get_session_method('post')

        self.assertEqual(self.mock_session.post, res)
        mock_session_builder.assert_called_once_with()
        mock__get_request_method.assert_called_once_with(
            'post', self.mock_session)

    def test__call_active_iq(self):
        response = mock.Mock()
        response.content = "fake_response"
        response.status_code = "fake_code"
        mock_post = mock.Mock(return_value=response)
        mock__get_session_method = self.mock_object(
            self.netapp_aiq_weigher, '_get_session_method',
            mock.Mock(return_value=mock_post))
        fake_url = "fake_url"
        fake_path = "/fake_path"
        mock__get_url = self.mock_object(
            self.netapp_aiq_weigher, '_get_url',
            mock.Mock(return_value=fake_url))

        self.netapp_aiq_weigher._call_active_iq(fake_path, "post",
                                                body="fake_body")

        mock_post.assert_called_once_with(fake_url + fake_path,
                                          json="fake_body")
        self.assertTrue(netapp_aiq.LOG.debug.called)
        mock__get_session_method.assert_called_once_with("post")
        mock__get_url.assert_called_once_with()

    @ddt.data({}, jsonutils.dumps(
        fakes.FAKE_ACTIVE_IQ_WEIGHER_AGGREGATES_RESPONSE))
    def test__get_resource_keys(self, api_res):
        mock__call_active_iq = self.mock_object(
            self.netapp_aiq_weigher, '_call_active_iq',
            mock.Mock(return_value=(200, api_res)))

        res = self.netapp_aiq_weigher._get_resource_keys(
            fakes.FAKE_ACTIVE_IQ_WEIGHER_LIST)

        if api_res:
            self.assertEqual(['fake_key_1', 'fake_key_2', 'fake_key_3'], res)
        else:
            self.assertEqual([0, 0, 0], res)
        mock__call_active_iq.assert_called_once_with(
            'datacenter/storage/aggregates', 'get')

    @ddt.data(mock.Mock(side_effect=exception.NotFound),
              mock.Mock(return_value=(400, "fake_res")))
    def test__get_resource_keys_error(self, mock_cal):
        self.mock_object(
            self.netapp_aiq_weigher, '_call_active_iq', mock_cal)

        res = self.netapp_aiq_weigher._get_resource_keys(
            fakes.FAKE_ACTIVE_IQ_WEIGHER_LIST)

        self.assertEqual([], res)
        self.assertTrue(netapp_aiq.LOG.error.called)

    @ddt.data([], jsonutils.dumps(
        fakes.FAKE_ACTIVE_IQ_WEIGHER_BALANCE_RESPONSE))
    def test__balance_aggregates(self, api_res):
        mock__call_active_iq = self.mock_object(
            self.netapp_aiq_weigher, '_call_active_iq',
            mock.Mock(return_value=(200, api_res)))

        res = self.netapp_aiq_weigher._balance_aggregates(
            ['fake_key_1', 'fake_key_2', 0, 'fake_key_3'], 10, 'fake_uuid')

        if not api_res:
            self.assertEqual([0.0, 0.0, 0.0, 0.0], res)
        else:
            self.assertEqual([10.0, 20.0, 0.0, 0.0], res)
        fake_body = {
            "capacity": '10GB',
            "eval_method": 1,
            "opt_method": 0,
            "priority_order": ['ops'],
            "separate_flag": False,
            "resource_keys": ['fake_key_1', 'fake_key_2', 'fake_key_3'],
            "ssl_key": 'fake_uuid'
        }
        mock__call_active_iq.assert_called_once_with(
            'storage-provider/data-placement/balance', 'post', body=fake_body)

    @ddt.data(mock.Mock(side_effect=exception.NotFound),
              mock.Mock(return_value=(400, "fake_res")))
    def test__balance_aggregates_error(self, mock_cal):
        self.mock_object(
            self.netapp_aiq_weigher, '_call_active_iq', mock_cal)

        res = self.netapp_aiq_weigher._balance_aggregates(
            ['fake_key_1', 'fake_key_2', 0, 'fake_key_3'], 10, 'fake_uuid')

        self.assertEqual([], res)
        self.assertTrue(netapp_aiq.LOG.error.called)

    @mock.patch('manila.db.api.IMPL.service_get_all_by_topic')
    def _get_all_hosts(self, _mock_service_get_all_by_topic, disabled=False):
        ctxt = context.get_admin_context()
        fakes.mock_host_manager_db_calls(_mock_service_get_all_by_topic,
                                         disabled=disabled)
        host_states = self.host_manager.get_all_host_states_share(ctxt)
        _mock_service_get_all_by_topic.assert_called_once_with(
            ctxt, CONF.share_topic)
        return host_states

    def test_weigh_objects_netapp_only(self):
        self.host_manager = fakes.FakeHostManagerNetAppOnly()
        hosts = self._get_all_hosts()  # pylint: disable=no-value-for-parameter
        weight_properties = "fake_properties"
        mock_weigh_active_iq = self.mock_object(
            netapp_aiq.NetAppAIQWeigher, '_weigh_active_iq',
            # third host wins
            mock.Mock(return_value=[0.0, 0.0, 10.0, 0.0, 0.0, 0.0]))

        weighed_host = self.weight_handler.get_weighed_objects(
            [netapp_aiq.NetAppAIQWeigher],
            hosts,
            weight_properties)[0]

        mock_weigh_active_iq.assert_called()
        self.assertEqual(1.0, weighed_host.weight)
        self.assertEqual(
            'host3', utils.extract_host(weighed_host.obj.host))

    def test_weigh_objects_non_netapp_backends(self):
        self.host_manager = fakes.FakeHostManager()
        hosts = self._get_all_hosts()  # pylint: disable=no-value-for-parameter
        weight_properties = "fake_properties"
        mock_weigh_active_iq = self.mock_object(
            netapp_aiq.NetAppAIQWeigher, '_weigh_active_iq')

        weighed_host = self.weight_handler.get_weighed_objects(
            [netapp_aiq.NetAppAIQWeigher],
            hosts,
            weight_properties)[0]

        mock_weigh_active_iq.assert_not_called()
        self.assertEqual(0.0, weighed_host.weight)
        self.assertEqual(
            'host1', utils.extract_host(weighed_host.obj.host))
