# Copyright (c) 2016 by Tegile Systems, Inc.
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
Share driver Test for Tegile storage.
"""

import ddt
import mock
from oslo_config import cfg
import requests
import six

from manila.common import constants as const
from manila import context
from manila import exception
from manila.exception import TegileAPIException
from manila.share.configuration import Configuration
from manila.share.drivers.tegile import tegile
from manila import test


CONF = cfg.CONF

test_config = Configuration(None)
test_config.tegile_nas_server = 'some-ip'
test_config.tegile_nas_login = 'some-user'
test_config.tegile_nas_password = 'some-password'
test_config.reserved_share_percentage = 10
test_config.max_over_subscription_ratio = 30.0

test_share = {
    'host': 'node#fake_pool',
    'name': 'testshare',
    'id': 'a24c2ee8-525a-4406-8ccd-8d38688f8e9e',
    'share_proto': 'NFS',
    'size': 10,
}

test_share_cifs = {
    'host': 'node#fake_pool',
    'name': 'testshare',
    'id': 'a24c2ee8-525a-4406-8ccd-8d38688f8e9e',
    'share_proto': 'CIFS',
    'size': 10,
}

test_share_fail = {
    'host': 'node#fake_pool',
    'name': 'testshare',
    'id': 'a24c2ee8-525a-4406-8ccd-8d38688f8e9e',
    'share_proto': 'OTHER',
    'size': 10,
}

test_snapshot = {
    'name': 'testSnap',
    'id': '07ae9978-5445-405e-8881-28f2adfee732',
    'share': test_share,
    'share_name': 'snapshotted',
    'display_name': 'disp',
    'display_description': 'disp-desc',
}

array_stats = {
    'total_capacity_gb': 4569.199686084874,
    'free_capacity_gb': 4565.381390112452,
    'pools': [
        {
            'total_capacity_gb': 913.5,
            'QoS_support': False,
            'free_capacity_gb': 911.812650680542,
            'reserved_percentage': 0,
            'pool_name': 'pyramid',
        },
        {
            'total_capacity_gb': 2742.1996604874,
            'QoS_support': False,
            'free_capacity_gb': 2740.148867149747,
            'reserved_percentage': 0,
            'pool_name': 'cobalt',
        },
        {
            'total_capacity_gb': 913.5,
            'QoS_support': False,
            'free_capacity_gb': 913.4198722839355,
            'reserved_percentage': 0,
            'pool_name': 'test',
        },
    ],
}


fake_tegile_backend_fail = mock.Mock(
    side_effect=TegileAPIException(response="Fake Exception"))


class FakeResponse(object):
    def __init__(self, status, json_output):
        self.status_code = status
        self.text = 'Random text'
        self._json = json_output

    def json(self):
        return self._json

    def close(self):
        pass


@ddt.ddt
class TegileShareDriverTestCase(test.TestCase):
    def __init__(self, *args, **kwds):
        super(TegileShareDriverTestCase, self).__init__(*args, **kwds)
        self._ctxt = context.get_admin_context()
        self.configuration = test_config

    def setUp(self):
        CONF.set_default('driver_handles_share_servers', False)
        self._driver = tegile.TegileShareDriver(
            configuration=self.configuration)
        self._driver._default_project = 'fake_project'
        super(TegileShareDriverTestCase, self).setUp()

    def test_create_share(self):
        api_return_value = (test_config.tegile_nas_server +
                            " " + test_share['name'])
        mock_api = self.mock_object(self._driver, '_api',
                                    mock.Mock(
                                        return_value=api_return_value))

        result = self._driver.create_share(self._ctxt, test_share)

        expected = {
            'is_admin_only': False,
            'metadata': {
                'preferred': True,
            },
            'path': 'some-ip:testshare',
        }
        self.assertEqual(expected, result)

        create_params = (
            'fake_pool',
            'fake_project',
            test_share['name'],
            test_share['share_proto'],
        )
        mock_api.assert_called_once_with('createShare', create_params)

    def test_create_share_fail(self):
        mock_api = self.mock_object(self._driver, '_api',
                                    mock.Mock(
                                        side_effect=TegileAPIException(
                                            response="Fake Exception")))

        self.assertRaises(TegileAPIException,
                          self._driver.create_share,
                          self._ctxt,
                          test_share)

        create_params = (
            'fake_pool',
            'fake_project',
            test_share['name'],
            test_share['share_proto'],
        )
        mock_api.assert_called_once_with('createShare', create_params)

    def test_delete_share(self):
        fake_share_info = ('fake_pool', 'fake_project', test_share['name'])
        mock_params = self.mock_object(self._driver,
                                       '_get_pool_project_share_name',
                                       mock.Mock(return_value=fake_share_info))
        mock_api = self.mock_object(self._driver, '_api')

        self._driver.delete_share(self._ctxt, test_share)

        delete_path = '%s/%s/%s/%s' % (
            'fake_pool', 'Local', 'fake_project', test_share['name'])
        delete_params = (delete_path, True, False)
        mock_api.assert_called_once_with('deleteShare', delete_params)
        mock_params.assert_called_once_with(test_share)

    def test_delete_share_fail(self):
        mock_api = self.mock_object(self._driver, '_api',
                                    mock.Mock(
                                        side_effect=TegileAPIException(
                                            response="Fake Exception")))

        self.assertRaises(TegileAPIException,
                          self._driver.delete_share,
                          self._ctxt,
                          test_share)

        delete_path = '%s/%s/%s/%s' % (
            'fake_pool', 'Local', 'fake_project', test_share['name'])
        delete_params = (delete_path, True, False)
        mock_api.assert_called_once_with('deleteShare', delete_params)

    def test_create_snapshot(self):
        mock_api = self.mock_object(self._driver, '_api')
        fake_share_info = ('fake_pool', 'fake_project', test_share['name'])
        mock_params = self.mock_object(self._driver,
                                       '_get_pool_project_share_name',
                                       mock.Mock(return_value=fake_share_info))

        self._driver.create_snapshot(self._ctxt, test_snapshot)

        share = {
            'poolName': 'fake_pool',
            'projectName': 'fake_project',
            'name': test_share['name'],
            'availableSize': 0,
            'totalSize': 0,
            'datasetPath': '%s/%s/%s' % (
                'fake_pool',
                'Local',
                'fake_project',
            ),
            'mountpoint': test_share['name'],
            'local': 'true',
        }
        create_params = (share, test_snapshot['name'], False)
        mock_api.assert_called_once_with('createShareSnapshot', create_params)
        mock_params.assert_called_once_with(test_share)

    def test_create_snapshot_fail(self):
        mock_api = self.mock_object(self._driver, '_api',
                                    mock.Mock(
                                        side_effect=TegileAPIException(
                                            response="Fake Exception")))

        self.assertRaises(TegileAPIException,
                          self._driver.create_snapshot,
                          self._ctxt,
                          test_snapshot)

        share = {
            'poolName': 'fake_pool',
            'projectName': 'fake_project',
            'name': test_share['name'],
            'availableSize': 0,
            'totalSize': 0,
            'datasetPath': '%s/%s/%s' % (
                'fake_pool',
                'Local',
                'fake_project',
            ),
            'mountpoint': test_share['name'],
            'local': 'true',
        }
        create_params = (share, test_snapshot['name'], False)
        mock_api.assert_called_once_with('createShareSnapshot', create_params)

    def test_delete_snapshot(self):
        fake_share_info = ('fake_pool', 'fake_project', test_share['name'])
        mock_params = self.mock_object(self._driver,
                                       '_get_pool_project_share_name',
                                       mock.Mock(return_value=fake_share_info))
        mock_api = self.mock_object(self._driver, '_api')

        self._driver.delete_snapshot(self._ctxt, test_snapshot)

        delete_snap_path = ('%s/%s/%s/%s@%s%s' % (
            'fake_pool',
            'Local',
            'fake_project',
            test_share['name'],
            'Manual-S-',
            test_snapshot['name'],
        ))

        delete_params = (delete_snap_path, False)
        mock_api.assert_called_once_with('deleteShareSnapshot', delete_params)
        mock_params.assert_called_once_with(test_share)

    def test_delete_snapshot_fail(self):
        mock_api = self.mock_object(self._driver, '_api',
                                    mock.Mock(
                                        side_effect=TegileAPIException(
                                            response="Fake Exception")))

        self.assertRaises(TegileAPIException,
                          self._driver.delete_snapshot,
                          self._ctxt,
                          test_snapshot)

        delete_snap_path = ('%s/%s/%s/%s@%s%s' % (
            'fake_pool',
            'Local',
            'fake_project',
            test_share['name'],
            'Manual-S-',
            test_snapshot['name'],
        ))
        delete_params = (delete_snap_path, False)
        mock_api.assert_called_once_with('deleteShareSnapshot', delete_params)

    def test_create_share_from_snapshot(self):
        api_return_value = (test_config.tegile_nas_server +
                            " " + test_share['name'])
        mock_api = self.mock_object(self._driver, '_api',
                                    mock.Mock(
                                        return_value=api_return_value))
        fake_share_info = ('fake_pool', 'fake_project', test_share['name'])
        mock_params = self.mock_object(self._driver,
                                       '_get_pool_project_share_name',
                                       mock.Mock(return_value=fake_share_info))

        result = self._driver.create_share_from_snapshot(self._ctxt,
                                                         test_share,
                                                         test_snapshot)

        expected = {
            'is_admin_only': False,
            'metadata': {
                'preferred': True,
            },
            'path': 'some-ip:testshare',
        }
        self.assertEqual(expected, result)

        create_params = (
            '%s/%s/%s/%s@%s%s' % (
                'fake_pool',
                'Local',
                'fake_project',
                test_snapshot['share_name'],
                'Manual-S-',
                test_snapshot['name'],
            ),
            test_share['name'],
            True,
        )
        mock_api.assert_called_once_with('cloneShareSnapshot', create_params)
        mock_params.assert_called_once_with(test_share)

    def test_create_share_from_snapshot_fail(self):
        mock_api = self.mock_object(self._driver, '_api',
                                    mock.Mock(
                                        side_effect=TegileAPIException(
                                            response="Fake Exception")))

        self.assertRaises(TegileAPIException,
                          self._driver.create_share_from_snapshot,
                          self._ctxt,
                          test_share,
                          test_snapshot)

        create_params = (
            '%s/%s/%s/%s@%s%s' % (
                'fake_pool',
                'Local',
                'fake_project',
                test_snapshot['share_name'],
                'Manual-S-',
                test_snapshot['name'],
            ),
            test_share['name'],
            True,
        )
        mock_api.assert_called_once_with('cloneShareSnapshot', create_params)

    def test_ensure_share(self):
        api_return_value = (test_config.tegile_nas_server +
                            " " + test_share['name'])
        mock_api = self.mock_object(self._driver, '_api',
                                    mock.Mock(
                                        return_value=api_return_value))
        fake_share_info = ('fake_pool', 'fake_project', test_share['name'])
        mock_params = self.mock_object(self._driver,
                                       '_get_pool_project_share_name',
                                       mock.Mock(return_value=fake_share_info))

        result = self._driver.ensure_share(self._ctxt, test_share)

        expected = [
            {
                'is_admin_only': False,
                'metadata': {
                    'preferred':
                        True,
                },
                'path': 'some-ip:testshare',
            },
        ]
        self.assertEqual(expected, result)

        ensure_params = [
            '%s/%s/%s/%s' % (
                'fake_pool', 'Local', 'fake_project', test_share['name'])]
        mock_api.assert_called_once_with('getShareIPAndMountPoint',
                                         ensure_params)
        mock_params.assert_called_once_with(test_share)

    def test_ensure_share_fail(self):
        mock_api = self.mock_object(self._driver, '_api',
                                    mock.Mock(
                                        side_effect=TegileAPIException(
                                            response="Fake Exception")))
        self.assertRaises(TegileAPIException,
                          self._driver.ensure_share,
                          self._ctxt,
                          test_share)

        ensure_params = [
            '%s/%s/%s/%s' % (
                'fake_pool', 'Local', 'fake_project', test_share['name'])]
        mock_api.assert_called_once_with('getShareIPAndMountPoint',
                                         ensure_params)

    def test_get_share_stats(self):
        mock_api = self.mock_object(self._driver, '_api',
                                    mock.Mock(
                                        return_value=array_stats))

        result_dict = self._driver.get_share_stats(True)

        expected_dict = {
            'driver_handles_share_servers': False,
            'driver_version': '1.0.0',
            'free_capacity_gb': 4565.381390112452,
            'pools': [
                {
                    'allocated_capacity_gb': 0.0,
                    'compression': True,
                    'dedupe': True,
                    'free_capacity_gb': 911.812650680542,
                    'pool_name': 'pyramid',
                    'qos': False,
                    'reserved_percentage': 10,
                    'thin_provisioning': True,
                    'max_over_subscription_ratio': 30.0,
                    'total_capacity_gb': 913.5},
                {
                    'allocated_capacity_gb': 0.0,
                    'compression': True,
                    'dedupe': True,
                    'free_capacity_gb': 2740.148867149747,
                    'pool_name': 'cobalt',
                    'qos': False,
                    'reserved_percentage': 10,
                    'thin_provisioning': True,
                    'max_over_subscription_ratio': 30.0,
                    'total_capacity_gb': 2742.1996604874
                },
                {
                    'allocated_capacity_gb': 0.0,
                    'compression': True,
                    'dedupe': True,
                    'free_capacity_gb': 913.4198722839355,
                    'pool_name': 'test',
                    'qos': False,
                    'reserved_percentage': 10,
                    'thin_provisioning': True,
                    'max_over_subscription_ratio': 30.0,
                    'total_capacity_gb': 913.5}, ],
            'qos': False,
            'reserved_percentage': 0,
            'replication_domain': None,
            'share_backend_name': 'Tegile',
            'snapshot_support': True,
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': 4569.199686084874,
            'vendor_name': 'Tegile Systems Inc.',
        }
        self.assertSubDictMatch(expected_dict, result_dict)

        mock_api.assert_called_once_with(fine_logging=False,
                                         method='getArrayStats',
                                         request_type='get')

    def test_get_share_stats_fail(self):
        mock_api = self.mock_object(self._driver, '_api',
                                    mock.Mock(
                                        side_effect=TegileAPIException(
                                            response="Fake Exception")))

        self.assertRaises(TegileAPIException,
                          self._driver.get_share_stats,
                          True)

        mock_api.assert_called_once_with(fine_logging=False,
                                         method='getArrayStats',
                                         request_type='get')

    def test_get_pool(self):
        result = self._driver.get_pool(test_share)

        expected = 'fake_pool'
        self.assertEqual(expected, result)

    def test_extend_share(self):
        fake_share_info = ('fake_pool', 'fake_project', test_share['name'])
        mock_params = self.mock_object(self._driver,
                                       '_get_pool_project_share_name',
                                       mock.Mock(return_value=fake_share_info))
        mock_api = self.mock_object(self._driver, '_api')

        self._driver.extend_share(test_share, 12)

        extend_path = '%s/%s/%s/%s' % (
            'fake_pool', 'Local', 'fake_project', test_share['name'])
        extend_params = (extend_path, six.text_type(12), 'GB')
        mock_api.assert_called_once_with('resizeShare', extend_params)
        mock_params.assert_called_once_with(test_share)

    def test_extend_share_fail(self):
        mock_api = self.mock_object(self._driver, '_api',
                                    mock.Mock(
                                        side_effect=TegileAPIException(
                                            response="Fake Exception")))

        self.assertRaises(TegileAPIException,
                          self._driver.extend_share,
                          test_share, 30)

        extend_path = '%s/%s/%s/%s' % (
            'fake_pool', 'Local', 'fake_project', test_share['name'])
        extend_params = (extend_path, six.text_type(30), 'GB')
        mock_api.assert_called_once_with('resizeShare', extend_params)

    def test_shrink_share(self):
        fake_share_info = ('fake_pool', 'fake_project', test_share['name'])
        mock_params = self.mock_object(self._driver,
                                       '_get_pool_project_share_name',
                                       mock.Mock(return_value=fake_share_info))
        mock_api = self.mock_object(self._driver, '_api')

        self._driver.shrink_share(test_share, 15)

        shrink_path = '%s/%s/%s/%s' % (
            'fake_pool', 'Local', 'fake_project', test_share['name'])
        shrink_params = (shrink_path, six.text_type(15), 'GB')
        mock_api.assert_called_once_with('resizeShare', shrink_params)
        mock_params.assert_called_once_with(test_share)

    def test_shrink_share_fail(self):
        mock_api = self.mock_object(self._driver, '_api',
                                    mock.Mock(
                                        side_effect=TegileAPIException(
                                            response="Fake Exception")))

        self.assertRaises(TegileAPIException,
                          self._driver.shrink_share,
                          test_share, 30)

        shrink_path = '%s/%s/%s/%s' % (
            'fake_pool', 'Local', 'fake_project', test_share['name'])
        shrink_params = (shrink_path, six.text_type(30), 'GB')
        mock_api.assert_called_once_with('resizeShare', shrink_params)

    @ddt.data('ip', 'user')
    def test_allow_access(self, access_type):
        fake_share_info = ('fake_pool', 'fake_project', test_share['name'])
        mock_params = self.mock_object(self._driver,
                                       '_get_pool_project_share_name',
                                       mock.Mock(return_value=fake_share_info))
        mock_api = self.mock_object(self._driver, '_api')

        access = {
            'access_type': access_type,
            'access_level': const.ACCESS_LEVEL_RW,
            'access_to': 'some-ip',
        }

        self._driver._allow_access(self._ctxt, test_share, access)

        allow_params = (
            '%s/%s/%s/%s' % (
                'fake_pool',
                'Local',
                'fake_project',
                test_share['name'],
            ),
            test_share['share_proto'],
            access_type,
            access['access_to'],
            access['access_level'],
        )
        mock_api.assert_called_once_with('shareAllowAccess', allow_params)
        mock_params.assert_called_once_with(test_share)

    @ddt.data({'access_type': 'other', 'to': 'some-ip', 'share': test_share,
               'exception_type': exception.InvalidShareAccess},
              {'access_type': 'ip', 'to': 'some-ip', 'share': test_share,
               'exception_type': exception.TegileAPIException},
              {'access_type': 'ip', 'to': 'some-ip', 'share': test_share_cifs,
               'exception_type': exception.InvalidShareAccess},
              {'access_type': 'ip', 'to': 'some-ip', 'share': test_share_fail,
               'exception_type': exception.InvalidShareAccess})
    @ddt.unpack
    def test_allow_access_fail(self, access_type, to, share, exception_type):
        self.mock_object(self._driver, '_api',
                         mock.Mock(
                             side_effect=TegileAPIException(
                                 response="Fake Exception")))

        access = {
            'access_type': access_type,
            'access_level': const.ACCESS_LEVEL_RW,
            'access_to': to,
        }

        self.assertRaises(exception_type,
                          self._driver._allow_access,
                          self._ctxt,
                          share,
                          access)

    @ddt.data('ip', 'user')
    def test_deny_access(self, access_type):
        fake_share_info = ('fake_pool', 'fake_project', test_share['name'])
        mock_params = self.mock_object(self._driver,
                                       '_get_pool_project_share_name',
                                       mock.Mock(return_value=fake_share_info))
        mock_api = self.mock_object(self._driver, '_api')

        access = {
            'access_type': access_type,
            'access_level': const.ACCESS_LEVEL_RW,
            'access_to': 'some-ip',
        }

        self._driver._deny_access(self._ctxt, test_share, access)

        deny_params = (
            '%s/%s/%s/%s' % (
                'fake_pool',
                'Local',
                'fake_project',
                test_share['name'],
            ),
            test_share['share_proto'],
            access_type,
            access['access_to'],
            access['access_level'],
        )
        mock_api.assert_called_once_with('shareDenyAccess', deny_params)
        mock_params.assert_called_once_with(test_share)

    @ddt.data({'access_type': 'other', 'to': 'some-ip', 'share': test_share,
               'exception_type': exception.InvalidShareAccess},
              {'access_type': 'ip', 'to': 'some-ip', 'share': test_share,
               'exception_type': exception.TegileAPIException},
              {'access_type': 'ip', 'to': 'some-ip', 'share': test_share_cifs,
               'exception_type': exception.InvalidShareAccess},
              {'access_type': 'ip', 'to': 'some-ip', 'share': test_share_fail,
               'exception_type': exception.InvalidShareAccess})
    @ddt.unpack
    def test_deny_access_fail(self, access_type, to, share, exception_type):
        self.mock_object(self._driver, '_api',
                         mock.Mock(
                             side_effect=TegileAPIException(
                                 response="Fake Exception")))

        access = {
            'access_type': access_type,
            'access_level': const.ACCESS_LEVEL_RW,
            'access_to': to,
        }

        self.assertRaises(exception_type,
                          self._driver._deny_access,
                          self._ctxt,
                          share,
                          access)

    @ddt.data({'access_rules': [{'access_type': 'ip',
                                 'access_level': const.ACCESS_LEVEL_RW,
                                 'access_to': 'some-ip',
                                 }, ], 'add_rules': None,
               'delete_rules': None, 'call_name': 'shareAllowAccess'},
              {'access_rules': [], 'add_rules':
                  [{'access_type': 'ip',
                    'access_level': const.ACCESS_LEVEL_RW,
                    'access_to': 'some-ip'}, ], 'delete_rules': [],
               'call_name': 'shareAllowAccess'},
              {'access_rules': [], 'add_rules': [], 'delete_rules':
                  [{'access_type': 'ip',
                    'access_level': const.ACCESS_LEVEL_RW,
                    'access_to': 'some-ip', }, ],
               'call_name': 'shareDenyAccess'})
    @ddt.unpack
    def test_update_access(self, access_rules, add_rules,
                           delete_rules, call_name):
        fake_share_info = ('fake_pool', 'fake_project', test_share['name'])
        mock_params = self.mock_object(self._driver,
                                       '_get_pool_project_share_name',
                                       mock.Mock(return_value=fake_share_info))
        mock_api = self.mock_object(self._driver, '_api')

        self._driver.update_access(self._ctxt,
                                   test_share,
                                   access_rules=access_rules,
                                   add_rules=add_rules,
                                   delete_rules=delete_rules)

        allow_params = (
            '%s/%s/%s/%s' % (
                'fake_pool',
                'Local',
                'fake_project',
                test_share['name'],
            ),
            test_share['share_proto'],
            'ip',
            'some-ip',
            const.ACCESS_LEVEL_RW,
        )
        if not (add_rules or delete_rules):
            clear_params = (
                '%s/%s/%s/%s' % (
                    'fake_pool',
                    'Local',
                    'fake_project',
                    test_share['name'],
                ),
                test_share['share_proto'],
            )
            mock_api.assert_has_calls([mock.call('clearAccessRules',
                                                 clear_params),
                                       mock.call(call_name,
                                                 allow_params)])
            mock_params.assert_called_with(test_share)
        else:
            mock_api.assert_called_once_with(call_name, allow_params)
            mock_params.assert_called_once_with(test_share)

    @ddt.data({'path': r'\\some-ip\shareName', 'share_proto': 'CIFS',
               'host': 'some-ip'},
              {'path': 'some-ip:shareName', 'share_proto': 'NFS',
               'host': 'some-ip'},
              {'path': 'some-ip:shareName', 'share_proto': 'NFS',
               'host': None})
    @ddt.unpack
    def test_get_location_path(self, path, share_proto, host):
        self._driver._hostname = 'some-ip'

        result = self._driver._get_location_path('shareName',
                                                 share_proto,
                                                 host)
        expected = {
            'is_admin_only': False,
            'metadata': {
                'preferred': True,
            },
            'path': path,
        }
        self.assertEqual(expected, result)

    def test_get_location_path_fail(self):
        self.assertRaises(exception.InvalidInput,
                          self._driver._get_location_path,
                          'shareName',
                          'SOME',
                          'some-ip')

    def test_get_network_allocations_number(self):
        result = self._driver.get_network_allocations_number()

        expected = 0
        self.assertEqual(expected, result)


class TegileAPIExecutorTestCase(test.TestCase):
    def setUp(self):
        self._api = tegile.TegileAPIExecutor("TestCase",
                                             test_config.tegile_nas_server,
                                             test_config.tegile_nas_login,
                                             test_config.tegile_nas_password)
        super(TegileAPIExecutorTestCase, self).setUp()

    def test_send_api_post(self):
        json_output = {'value': 'abc'}

        self.mock_object(requests, 'post',
                         mock.Mock(return_value=FakeResponse(200,
                                                             json_output)))
        result = self._api(method="Test", request_type='post', params='[]',
                           fine_logging=True)

        self.assertEqual(json_output, result)

    def test_send_api_get(self):
        json_output = {'value': 'abc'}

        self.mock_object(requests, 'get',
                         mock.Mock(return_value=FakeResponse(200,
                                                             json_output)))

        result = self._api(method="Test",
                           request_type='get',
                           fine_logging=False)

        self.assertEqual(json_output, result)

    def test_send_api_get_fail(self):
        self.mock_object(requests, 'get',
                         mock.Mock(return_value=FakeResponse(404, [])))

        self.assertRaises(TegileAPIException,
                          self._api,
                          method="Test",
                          request_type='get',
                          fine_logging=False)

    def test_send_api_value_error_fail(self):
        json_output = {'value': 'abc'}

        self.mock_object(requests, 'post',
                         mock.Mock(return_value=FakeResponse(200,
                                                             json_output)))
        self.mock_object(FakeResponse, 'json',
                         mock.Mock(side_effect=ValueError))

        result = self._api(method="Test",
                           request_type='post',
                           fine_logging=False)

        expected = ''
        self.assertEqual(expected, result)
