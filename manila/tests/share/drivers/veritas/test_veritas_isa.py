# Copyright 2017 Veritas Technologies LLC.
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
Unit tests for Veritas Manila driver.
"""
import hashlib
import json

import mock
from oslo_config import cfg
import requests
import six

from manila import context
from manila import exception
from manila.share import configuration as conf
from manila.share.drivers.veritas import veritas_isa
from manila import test


CONF = cfg.CONF
FAKE_BACKEND = 'fake_backend'


class MockResponse(object):
    def __init__(self):
        self.status_code = 200

    def json(self):
        data = {'fake_key': 'fake_val'}
        return json.dumps(data)


class ACCESSShareDriverTestCase(test.TestCase):
    """Tests ACCESSShareDriver."""

    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'NFS',
        'export_locations': [{'path': '10.20.30.40:/vx/fake_location'}],
        'snapshot_id': False
    }

    share2 = {
        'id': 'fakeid2',
        'name': 'fakename2',
        'size': 4,
        'share_proto': 'NFS',
    }

    share3 = {
        'id': 'fakeid3',
        'name': 'fakename3',
        'size': 2,
        'share_proto': 'NFS',
        'export_location': '/vx/fake_location',
        'snapshot_id': True
    }

    snapshot = {
        'id': 'fakesnapshotid',
        'share_name': 'fakename',
        'share_id': 'fakeid',
        'name': 'fakesnapshotname',
        'share_size': 1,
        'share_proto': 'NFS',
        'snapshot_id': 'fake_snap_id',
    }

    access = {
        'id': 'fakeaccid',
        'access_type': 'ip',
        'access_to': '10.0.0.2',
        'access_level': 'rw',
        'state': 'active',
    }

    access2 = {
        'id': 'fakeaccid2',
        'access_type': 'user',
        'access_to': '10.0.0.3',
        'access_level': 'rw',
        'state': 'active',
    }

    access3 = {
        'id': 'fakeaccid3',
        'access_type': 'ip',
        'access_to': '10.0.0.4',
        'access_level': 'rw+',
        'state': 'active',
    }

    access4 = {
        'id': 'fakeaccid',
        'access_type': 'ip',
        'access_to': '10.0.0.2',
        'access_level': 'ro',
        'state': 'active',
    }

    def setUp(self):
        super(ACCESSShareDriverTestCase, self).setUp()
        self._create_fake_config()
        lcfg = self.configuration
        self._context = context.get_admin_context()
        self._driver = veritas_isa.ACCESSShareDriver(False, configuration=lcfg)
        self._driver.do_setup(self._context)

    def _create_fake_config(self):
        def _safe_get(opt):
            return getattr(self.configuration, opt)

        self.mock_object(veritas_isa.ACCESSShareDriver, '_authenticate_access')
        self.configuration = mock.Mock(spec=conf.Configuration)
        self.configuration.safe_get = mock.Mock(side_effect=_safe_get)
        self.configuration.va_server_ip = '1.1.1.1'
        self.configuration.va_pool = 'pool1'
        self.configuration.va_user = 'user'
        self.configuration.va_pwd = 'passwd'
        self.configuration.va_port = 14161
        self.configuration.va_ssl = 'False'
        self.configuration.va_fstype = 'simple'
        self.configuration.network_config_group = 'fake_network_config_group'
        self.configuration.admin_network_config_group = (
            'fake_admin_network_config_group')
        self.configuration.driver_handles_share_servers = False
        self.configuration.share_backend_name = FAKE_BACKEND
        self.configuration.replication_domain = 'Disable'
        self.configuration.filter_function = 'Disable'
        self.configuration.goodness_function = 'Disable'

    def test_create_share(self):
        self.mock_object(self._driver, '_get_va_share_name')
        self.mock_object(self._driver, '_get_va_share_path')
        self.mock_object(self._driver, '_get_vip')
        self.mock_object(self._driver, '_access_api')
        length = len(self.share['name'])
        index = int(length / 2)
        name1 = self.share['name'][:index]
        name2 = self.share['name'][index:]
        crc1 = hashlib.md5(name1.encode('utf-8')).hexdigest()[:8]
        crc2 = hashlib.md5(name2.encode('utf-8')).hexdigest()[:8]

        share_name_to_ret = crc1 + '-' + crc2
        share_path_to_ret = '/vx/' + crc1 + '-' + crc2

        self._driver._get_va_share_name.return_value = share_name_to_ret
        self._driver._get_va_share_path.return_value = share_path_to_ret

        self._driver._get_vip.return_value = '1.1.1.1'
        self._driver.create_share(self._context, self.share)

        self.assertEqual(1, self._driver._get_vip.call_count)
        self.assertEqual(1, self._driver._get_va_share_name.call_count)
        self.assertEqual(1, self._driver._get_va_share_path.call_count)

    def test_create_share_negative(self):
        self.mock_object(self._driver, '_access_api')

        self._driver._access_api.return_value = False

        self.assertRaises(exception.ShareBackendException,
                          self._driver.create_share,
                          self._context,
                          self.share)

    def test_create_share_from_snapshot(self):
        self.mock_object(self._driver, '_get_vip')

        sharename = self._driver._get_va_share_name(
            self.snapshot['share_name'])
        snapname = self._driver._get_va_snap_name(self.snapshot['name'])
        sharepath = self._driver._get_va_share_path(sharename)
        self._driver._get_vip.return_value = '1.1.1.1'
        vip = self._driver._get_vip()
        location = (six.text_type(vip) + ':' +
                    six.text_type(sharepath) + ':' + six.text_type(snapname))

        ret = self._driver.create_share_from_snapshot(self._context,
                                                      self.share,
                                                      self.snapshot)
        self.assertEqual(location, ret)

    def test_delete_share(self):
        self.mock_object(self._driver, '_access_api')
        self.mock_object(self._driver, '_does_item_exist_at_va_backend')
        self._driver._does_item_exist_at_va_backend.return_value = True
        self._driver.delete_share(self._context, self.share)
        self.assertEqual(2, self._driver._access_api.call_count)

    def test_delete_share_negative(self):
        self.mock_object(self._driver, '_access_api')
        self.mock_object(self._driver, '_does_item_exist_at_va_backend')

        self._driver._does_item_exist_at_va_backend.return_value = True
        self._driver._access_api.return_value = False

        self.assertRaises(exception.ShareBackendException,
                          self._driver.delete_share,
                          self._context, self.share)

    def test_delete_share_if_share_created_from_snap(self):
        self.mock_object(self._driver, '_access_api')
        self.mock_object(self._driver, '_does_item_exist_at_va_backend')

        self._driver.delete_share(self._context, self.share3)
        self.assertEqual(0,
                         (self._driver.
                          _does_item_exist_at_va_backend.call_count))
        self.assertEqual(0, self._driver._access_api.call_count)

    def test_delete_share_if_not_present_at_backend(self):
        self.mock_object(self._driver, '_does_item_exist_at_va_backend')
        self.mock_object(self._driver, '_access_api')

        self._driver._does_item_exist_at_va_backend.return_value = False
        self._driver.delete_share(self._context, self.share)
        self.assertEqual(1,
                         (self._driver.
                          _does_item_exist_at_va_backend.call_count))
        self.assertEqual(0, self._driver._access_api.call_count)

    def test_create_snapshot(self):
        self.mock_object(self._driver, '_access_api')
        self._driver.create_snapshot(self._context, self.snapshot)
        self.assertEqual(2, self._driver._access_api.call_count)

    def test_create_snapshot_negative(self):
        self.mock_object(self._driver, '_access_api')

        self._driver._access_api.return_value = False

        self.assertRaises(exception.ShareBackendException,
                          self._driver.create_snapshot,
                          self._context,
                          self.snapshot)

    def test_delete_snapshot(self):
        self.mock_object(self._driver, '_access_api')
        self.mock_object(self._driver, '_does_item_exist_at_va_backend')

        self._driver._does_item_exist_at_va_backend.return_value = True
        self._driver.delete_snapshot(self._context, self.snapshot)
        self.assertEqual(2, self._driver._access_api.call_count)

    def test_delete_snapshot_negative(self):
        self.mock_object(self._driver, '_access_api')
        self.mock_object(self._driver, '_does_item_exist_at_va_backend')

        self._driver._does_item_exist_at_va_backend.return_value = True
        self._driver._access_api.return_value = False

        self.assertRaises(exception.ShareBackendException,
                          self._driver.delete_snapshot,
                          self._context, self.snapshot)

    def test_delete_snapshot_if_not_present_at_backend(self):
        self.mock_object(self._driver, '_does_item_exist_at_va_backend')
        self.mock_object(self._driver, '_access_api')

        self._driver._does_item_exist_at_va_backend.return_value = False
        self._driver.delete_snapshot(self._context, self.snapshot)
        self.assertEqual(1,
                         (self._driver.
                          _does_item_exist_at_va_backend.call_count))
        self.assertEqual(0, self._driver._access_api.call_count)

    def test_update_access_for_allow(self):
        self.mock_object(self._driver, '_access_api')
        self._driver.update_access(self._context, self.share, [],
                                   [self.access], [])
        self.assertEqual(2, self._driver._access_api.call_count)

    def test_update_access_for_allow_negative(self):
        self.mock_object(self._driver, '_access_api')
        self._driver._access_api.return_value = False
        self.assertRaises(exception.ShareBackendException,
                          self._driver.update_access,
                          self._context,
                          self.share, [], [self.access], [])

        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.update_access,
                          self._context,
                          self.share, [], [self.access2], [])

        self.assertRaises(exception.InvalidShareAccessLevel,
                          self._driver.update_access,
                          self._context,
                          self.share, [], [self.access3], [])

    def test_update_access_for_deny(self):
        self.mock_object(self._driver, '_access_api')
        self._driver.update_access(self._context, self.share,
                                   [], [], [self.access])
        self.assertEqual(2, self._driver._access_api.call_count)

    def test_update_access_for_deny_negative(self):
        self.mock_object(self._driver, '_access_api')
        self._driver._access_api.return_value = False
        self.assertRaises(exception.ShareBackendException,
                          self._driver.update_access,
                          self._context,
                          self.share, [], [], [self.access])

    def test_update_access_for_deny_for_invalid_access_type(self):
        self.mock_object(self._driver, '_access_api')
        self._driver.update_access(self._context, self.share,
                                   [], [], [self.access2])
        self.assertEqual(0, self._driver._access_api.call_count)

    def test_update_access_for_empty_rule_list(self):
        self.mock_object(self._driver, '_allow_access')
        self.mock_object(self._driver, '_deny_access')
        self._driver.update_access(self._context, self.share,
                                   [], [], [])
        self.assertEqual(0, self._driver._allow_access.call_count)
        self.assertEqual(0, self._driver._deny_access.call_count)

    def test_update_access_for_access_rules(self):
        self.mock_object(self._driver, '_fetch_existing_rule')
        self.mock_object(self._driver, '_allow_access')
        self.mock_object(self._driver, '_deny_access')

        existing_a_rules = [{'access_level': 'rw',
                             'access_type': 'ip',
                             'access_to': '10.0.0.2'},
                            {'access_level': 'rw',
                             'access_type': 'ip',
                             'access_to': '10.0.0.3'}]

        self._driver._fetch_existing_rule.return_value = existing_a_rules
        d_rule = self._driver._return_access_lists_difference(existing_a_rules,
                                                              [self.access4])

        a_rule = self._driver._return_access_lists_difference([self.access4],
                                                              existing_a_rules)
        self._driver.update_access(self._context, self.share,
                                   [self.access4], [], [])

        self.assertEqual(d_rule, existing_a_rules)
        self.assertEqual(a_rule, [self.access4])
        self.assertEqual(1, self._driver._allow_access.call_count)
        self.assertEqual(2, self._driver._deny_access.call_count)

    def test_extend_share(self):
        self.mock_object(self._driver, '_access_api')
        new_size = 3
        self._driver.extend_share(self.share, new_size)
        self.assertEqual(1, self._driver._access_api.call_count)

    def test_extend_share_negative(self):
        self.mock_object(self._driver, '_access_api')

        new_size = 3
        self._driver._access_api.return_value = False
        self.assertRaises(exception.ShareBackendException,
                          self._driver.extend_share,
                          self.share, new_size)

    def test_shrink_share(self):
        self.mock_object(self._driver, '_access_api')
        new_size = 3
        self._driver.shrink_share(self.share2, new_size)
        self.assertEqual(1, self._driver._access_api.call_count)

    def test_shrink_share_negative(self):
        self.mock_object(self._driver, '_access_api')

        new_size = 3
        self._driver._access_api.return_value = False
        self.assertRaises(exception.ShareBackendException,
                          self._driver.shrink_share,
                          self.share2, new_size)

    def test__get_access_pool_details(self):
        self.mock_object(self._driver, '_access_api')

        pool_details = []
        pool_details_dict = {}
        pool_details_dict['device_group_name'] = 'fake_pool'
        pool_details_dict['capacity'] = 10737418240
        pool_details_dict['used_size'] = 9663676416
        pool_details.append(pool_details_dict)

        pool_details_dict2 = {}
        pool_details_dict2['device_group_name'] = self.configuration.va_pool
        pool_details_dict2['capacity'] = 10737418240
        pool_details_dict2['used_size'] = 9663676416
        pool_details.append(pool_details_dict2)

        self._driver._access_api.return_value = pool_details
        total_space, free_space = self._driver._get_access_pool_details()
        self.assertEqual(10, total_space)
        self.assertEqual(1, free_space)

    def test__get_access_pool_details_negative(self):
        self.mock_object(self._driver, '_access_api')

        pool_details = []
        self._driver._access_api.return_value = pool_details
        self.assertRaises(exception.ShareBackendException,
                          self._driver._get_access_pool_details)

    def test__update_share_stats(self):
        self.mock_object(self._driver, '_authenticate_access')
        self.mock_object(self._driver, '_get_access_pool_details')

        self._driver._get_access_pool_details.return_value = (10, 9)
        self._driver._update_share_stats()
        data = {
            'share_backend_name': FAKE_BACKEND,
            'vendor_name': 'Veritas',
            'driver_version': '1.0',
            'storage_protocol': 'NFS',
            'total_capacity_gb': 10,
            'free_capacity_gb': 9,
            'reserved_percentage': 0,
            'QoS_support': False,
            'create_share_from_snapshot_support': True,
            'driver_handles_share_servers': False,
            'filter_function': 'Disable',
            'goodness_function': 'Disable',
            'ipv4_support': True,
            'ipv6_support': False,
            'mount_snapshot_support': False,
            'pools': None,
            'qos': False,
            'replication_domain': 'Disable',
            'revert_to_snapshot_support': False,
            'share_group_stats': {'consistent_snapshot_support': None},
            'snapshot_support': True
        }

        self.assertEqual(data, self._driver._stats)

    def test__get_vip(self):
        self.mock_object(self._driver, '_get_access_ips')

        pool_list = []
        ip1 = {'isconsoleip': 1, 'type': 'Virtual',
               'status': 'ONLINE', 'ip': '1.1.1.2'}
        ip2 = {'isconsoleip': 0, 'type': 'Virtual',
               'status': 'ONLINE', 'ip': '1.1.1.4'}
        ip3 = {'isconsoleip': 0, 'type': 'Virtual',
               'status': 'OFFLINE', 'ip': '1.1.1.5'}
        ip4 = {'isconsoleip': 0, 'type': 'Physical',
               'status': 'OFFLINE', 'ip': '1.1.1.6'}

        pool_list = [ip1, ip2, ip3, ip4]

        self._driver._get_access_ips.return_value = pool_list
        vip = self._driver._get_vip()
        self.assertEqual('1.1.1.4', vip)

    def test__get_access_ips(self):
        self.mock_object(self._driver, '_access_api')
        ip_list = ['1.1.1.2', '1.1.2.3', '1.1.1.4']
        self._driver._access_api.return_value = ip_list
        ret_value = self._driver._get_access_ips(self._driver.session,
                                                 self._driver.host)
        self.assertEqual(ret_value, ip_list)

    def test__access_api(self):
        self.mock_object(requests, 'session')

        provider = '%s:%s' % (self._driver.host, self._driver._port)
        path = '/fake/path'
        input_data = {}
        mock_response = MockResponse()
        session = requests.session

        data = {'fake_key': 'fake_val'}
        json_data = json.dumps(data)

        session.request.return_value = mock_response
        ret_value = self._driver._access_api(session, provider, path,
                                             json.dumps(input_data), 'GET')

        self.assertEqual(json_data, ret_value)

    def test__access_api_ret_for_update_object(self):
        self.mock_object(requests, 'session')

        provider = '%s:%s' % (self._driver.host, self._driver._port)
        path = self._driver._update_object
        input_data = None
        mock_response = MockResponse()
        session = requests.session

        session.request.return_value = mock_response
        ret = self._driver._access_api(session, provider, path,
                                       input_data, 'GET')

        self.assertTrue(ret)

    def test__access_api_negative(self):
        session = self._driver.session
        provider = '%s:%s' % (self._driver.host, self._driver._port)
        path = '/fake/path'
        input_data = {}
        ret_value = self._driver._access_api(session, provider, path,
                                             json.dumps(input_data), 'GET')
        self.assertEqual(False, ret_value)

    def test__get_api(self):
        provider = '%s:%s' % (self._driver.host, self._driver._port)
        tail = '/fake/path'
        ret = self._driver._get_api(provider, tail)

        api_root = 'https://%s/api' % (provider)
        to_be_ret = api_root + tail
        self.assertEqual(to_be_ret, ret)

    def test__does_item_exist_at_va_backend(self):
        self.mock_object(self._driver, '_access_api')
        item_name = 'fake_item'
        path = '/fake/path'
        fake_item_list = [{'name': item_name}]
        self._driver._access_api.return_value = fake_item_list
        ret_value = self._driver._does_item_exist_at_va_backend(item_name,
                                                                path)
        self.assertTrue(ret_value)

    def test__does_item_exist_at_va_backend_negative(self):
        self.mock_object(self._driver, '_access_api')
        item_name = 'fake_item'
        path = '/fake/path'
        fake_item_list = [{'name': 'item2'}]
        self._driver._access_api.return_value = fake_item_list
        ret_value = self._driver._does_item_exist_at_va_backend(item_name,
                                                                path)
        self.assertEqual(False, ret_value)

    def test__fetch_existing_rule(self):
        self.mock_object(self._driver, '_access_api')
        fake_share = 'fake-share'
        fake_access_list = []
        list1 = []
        list1.append({
            'status': 'online',
            'name': '/vx/fake-share',
            'host_name': '10.0.0.1',
            'privilege': 'rw'
        })
        list1.append({
            'status': 'online',
            'name': '/vx/fake-share',
            'host_name': '10.0.0.2',
            'privilege': 'rw'
        })
        list1.append({
            'status': 'online',
            'name': '/vx/fake-share',
            'host_name': '10.0.0.3',
            'privilege': 'ro'
        })
        list1.append({
            'status': 'online',
            'name': '/vx/fake-share2',
            'host_name': '10.0.0.4',
            'privilege': 'rw'
        })

        fake_access_list.append({
            'shareType': 'NFS',
            'shares': list1
        })

        fake_access_list.append({
            'shareType': 'CIFS',
            'shares': []
        })

        ret_access_list = []
        ret_access_list.append({
            'access_to': '10.0.0.1',
            'access_level': 'rw',
            'access_type': 'ip'
        })

        ret_access_list.append({
            'access_to': '10.0.0.2',
            'access_level': 'rw',
            'access_type': 'ip'
        })

        ret_access_list.append({
            'access_to': '10.0.0.3',
            'access_level': 'ro',
            'access_type': 'ip'
        })

        self._driver._access_api.return_value = fake_access_list
        ret_value = self._driver._fetch_existing_rule(fake_share)
        self.assertEqual(ret_access_list, ret_value)
