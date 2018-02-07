# Copyright 2011 OpenStack Foundation
# Copyright (c) 2015 Rushil Chugh
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

"""Tests For miscellaneous util methods used with share."""

import ddt
import mock

from manila.common import constants
from manila.share import utils as share_utils
from manila import test


@ddt.ddt
class ShareUtilsTestCase(test.TestCase):
    def test_extract_host_without_pool(self):
        host = 'Host@Backend'
        self.assertEqual(
            'Host@Backend', share_utils.extract_host(host))

    def test_extract_host_only_return_host(self):
        host = 'Host@Backend'
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'host'))

    def test_extract_host_only_return_pool(self):
        host = 'Host@Backend'
        self.assertIsNone(
            share_utils.extract_host(host, 'pool'))

    def test_extract_host_only_return_backend(self):
        host = 'Host@Backend'
        self.assertEqual(
            'Host@Backend', share_utils.extract_host(host, 'backend'))

    def test_extract_host_missing_backend_and_pool(self):
        host = 'Host'
        # Default level is 'backend'
        self.assertEqual(
            'Host', share_utils.extract_host(host))

    def test_extract_host_only_return_backend_name(self):
        host = 'Host@Backend#Pool'
        self.assertEqual(
            'Backend', share_utils.extract_host(host, 'backend_name'))

    def test_extract_host_only_return_backend_name_index_error(self):
        host = 'Host#Pool'

        self.assertRaises(IndexError,
                          share_utils.extract_host,
                          host, 'backend_name')

    def test_extract_host_missing_backend(self):
        host = 'Host#Pool'
        self.assertEqual(
            'Host', share_utils.extract_host(host))
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'host'))

    def test_extract_host_missing_backend_only_return_backend(self):
        host = 'Host#Pool'
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'backend'))

    def test_extract_host_missing_backend_only_return_pool(self):
        host = 'Host#Pool'
        self.assertEqual(
            'Pool', share_utils.extract_host(host, 'pool'))
        self.assertEqual(
            'Pool', share_utils.extract_host(host, 'pool', True))

    def test_extract_host_missing_pool(self):
        host = 'Host@Backend'
        self.assertIsNone(
            share_utils.extract_host(host, 'pool'))

    def test_extract_host_missing_pool_use_default_pool(self):
        host = 'Host@Backend'
        self.assertEqual(
            '_pool0', share_utils.extract_host(host, 'pool', True))

    def test_extract_host_with_default_pool(self):
        host = 'Host'
        # Default_pool_name doesn't work for level other than 'pool'
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'host', True))
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'host', False))
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'backend', True))
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'backend', False))

    def test_extract_host_with_pool(self):
        host = 'Host@Backend#Pool'
        self.assertEqual(
            'Host@Backend', share_utils.extract_host(host))
        self.assertEqual(
            'Host', share_utils.extract_host(host, 'host'))
        self.assertEqual(
            'Host@Backend', share_utils.extract_host(host, 'backend'),)
        self.assertEqual(
            'Pool', share_utils.extract_host(host, 'pool'))
        self.assertEqual(
            'Pool', share_utils.extract_host(host, 'pool', True))

    def test_append_host_with_host_and_pool(self):
        host = 'Host'
        pool = 'Pool'
        expected = 'Host#Pool'
        self.assertEqual(expected,
                         share_utils.append_host(host, pool))

    def test_append_host_with_host(self):
        host = 'Host'
        pool = None
        expected = 'Host'
        self.assertEqual(expected,
                         share_utils.append_host(host, pool))

    def test_append_host_with_pool(self):
        host = None
        pool = 'pool'
        expected = None
        self.assertEqual(expected,
                         share_utils.append_host(host, pool))

    def test_append_host_with_no_values(self):
        host = None
        pool = None
        expected = None
        self.assertEqual(expected,
                         share_utils.append_host(host, pool))

    def test_get_active_replica_success(self):
        replica_list = [{'id': '123456',
                         'replica_state': constants.REPLICA_STATE_IN_SYNC},
                        {'id': '654321',
                         'replica_state': constants.REPLICA_STATE_ACTIVE},
                        ]
        replica = share_utils.get_active_replica(replica_list)
        self.assertEqual('654321', replica['id'])

    def test_get_active_replica_not_exist(self):
        replica_list = [{'id': '123456',
                         'replica_state': constants.REPLICA_STATE_IN_SYNC},
                        {'id': '654321',
                         'replica_state': constants.REPLICA_STATE_OUT_OF_SYNC},
                        ]
        replica = share_utils.get_active_replica(replica_list)
        self.assertIsNone(replica)


class NotifyUsageTestCase(test.TestCase):
    @mock.patch('manila.share.utils._usage_from_share')
    @mock.patch('manila.share.utils.CONF')
    @mock.patch('manila.share.utils.rpc')
    def test_notify_about_share_usage(self, mock_rpc, mock_conf, mock_usage):
        mock_conf.host = 'host1'
        output = share_utils.notify_about_share_usage(mock.sentinel.context,
                                                      mock.sentinel.share,
                                                      mock.sentinel.
                                                      share_instance,
                                                      'test_suffix')
        self.assertIsNone(output)
        mock_usage.assert_called_once_with(mock.sentinel.share,
                                           mock.sentinel.share_instance)
        mock_rpc.get_notifier.assert_called_once_with('share',
                                                      'host1')
        mock_rpc.get_notifier.return_value.info.assert_called_once_with(
            mock.sentinel.context,
            'share.test_suffix',
            mock_usage.return_value)

    @mock.patch('manila.share.utils._usage_from_share')
    @mock.patch('manila.share.utils.CONF')
    @mock.patch('manila.share.utils.rpc')
    def test_notify_about_share_usage_with_kwargs(self, mock_rpc, mock_conf,
                                                  mock_usage):
        mock_conf.host = 'host1'
        output = share_utils.notify_about_share_usage(mock.sentinel.context,
                                                      mock.sentinel.share,
                                                      mock.sentinel.
                                                      share_instance,
                                                      'test_suffix',
                                                      extra_usage_info={
                                                          'a': 'b', 'c': 'd'},
                                                      host='host2')
        self.assertIsNone(output)
        mock_usage.assert_called_once_with(mock.sentinel.share,
                                           mock.sentinel.share_instance,
                                           a='b', c='d')
        mock_rpc.get_notifier.assert_called_once_with('share',
                                                      'host2')
        mock_rpc.get_notifier.return_value.info.assert_called_once_with(
            mock.sentinel.context,
            'share.test_suffix',
            mock_usage.return_value)
