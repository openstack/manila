# Copyright 2016 Nexenta Systems, Inc.
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

import base64
import json
import mock
from mock import patch
from mock import PropertyMock
from oslo_serialization import jsonutils
from oslo_utils import units

from manila import context
from manila import exception
from manila.share import configuration as conf
from manila.share.drivers.nexenta.ns4 import nexenta_nas
from manila import test

PATH_TO_RPC = 'requests.post'
CODE = PropertyMock(return_value=200)


class FakeResponse(object):

    def __init__(self, response={}):
        self.content = json.dumps(response)
        super(FakeResponse, self).__init__()

    def close(self):
        pass


class RequestParams(object):
    def __init__(self, scheme, host, port, path, user, password):
        self.scheme = scheme.lower()
        self.host = host
        self.port = port
        self.path = path
        self.user = user
        self.password = password

    @property
    def url(self):
        return '%s://%s:%s%s' % (self.scheme, self.host, self.port, self.path)

    @property
    def headers(self):
        auth = base64.b64encode(
            ('%s:%s' % (self.user, self.password)).encode('utf-8'))
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Basic %s' % auth,
        }
        return headers

    def build_post_args(self, obj, method, *args):
        data = jsonutils.dumps({
            'object': obj,
            'method': method,
            'params': args,
        })
        return data


class TestNexentaNasDriver(test.TestCase):

    def _get_share_path(self, share_name):
        return '%s/%s/%s' % (self.volume, self.share, share_name)

    def setUp(self):
        def _safe_get(opt):
            return getattr(self.cfg, opt)

        self.cfg = mock.Mock(spec=conf.Configuration)
        self.cfg.nexenta_host = '1.1.1.1'
        super(TestNexentaNasDriver, self).setUp()

        self.ctx = context.get_admin_context()
        self.cfg.safe_get = mock.Mock(side_effect=_safe_get)
        self.cfg.nexenta_rest_port = 1000
        self.cfg.reserved_share_percentage = 0
        self.cfg.max_over_subscription_ratio = 0
        self.cfg.nexenta_rest_protocol = 'auto'
        self.cfg.nexenta_volume = 'volume'
        self.cfg.nexenta_nfs_share = 'nfs_share'
        self.cfg.nexenta_user = 'user'
        self.cfg.nexenta_password = 'password'
        self.cfg.nexenta_thin_provisioning = False
        self.cfg.enabled_share_protocols = 'NFS'
        self.cfg.nexenta_mount_point_base = '$state_path/mnt'
        self.cfg.share_backend_name = 'NexentaStor'
        self.cfg.nexenta_dataset_compression = 'on'
        self.cfg.nexenta_smb = 'on'
        self.cfg.nexenta_nfs = 'on'
        self.cfg.nexenta_dataset_dedupe = 'on'

        self.cfg.network_config_group = 'DEFAULT'
        self.cfg.admin_network_config_group = (
            'fake_admin_network_config_group')
        self.cfg.driver_handles_share_servers = False

        self.request_params = RequestParams(
            'http', self.cfg.nexenta_host, self.cfg.nexenta_rest_port,
            '/rest/nms/', self.cfg.nexenta_user, self.cfg.nexenta_password)

        self.drv = nexenta_nas.NexentaNasDriver(configuration=self.cfg)
        self.drv.do_setup(self.ctx)

        self.volume = self.cfg.nexenta_volume
        self.share = self.cfg.nexenta_nfs_share

    @patch(PATH_TO_RPC)
    def test_check_for_setup_error__volume_doesnt_exist(self, post):
        post.return_value = FakeResponse()

        self.assertRaises(
            exception.NexentaException, self.drv.check_for_setup_error)

    @patch(PATH_TO_RPC)
    def test_check_for_setup_error__folder_doesnt_exist(self, post):
        folder = '%s/%s' % (self.volume, self.share)
        create_folder_props = {
            'recordsize': '4K',
            'quota': '1G',
            'compression': self.cfg.nexenta_dataset_compression,
            'sharesmb': self.cfg.nexenta_smb,
            'sharenfs': self.cfg.nexenta_nfs,
        }

        share_opts = {
            'read_write': '*',
            'read_only': '',
            'root': 'nobody',
            'extra_options': 'anon=0',
            'recursive': 'true',
            'anonymous_rw': 'true',
        }

        def my_side_effect(*args, **kwargs):
            if kwargs['data'] == self.request_params.build_post_args(
                    'volume', 'object_exists', self.volume):
                return FakeResponse({'result': 'OK'})
            elif kwargs['data'] == self.request_params.build_post_args(
                    'folder', 'object_exists', folder):
                return FakeResponse()
            elif kwargs['data'] == self.request_params.build_post_args(
                    'folder', 'create_with_props', self.volume, self.share,
                    create_folder_props):
                return FakeResponse()
            elif kwargs['data'] == self.request_params.build_post_args(
                    'netstorsvc', 'share_folder',
                    'svc:/network/nfs/server:default', folder, share_opts):
                return FakeResponse()
            else:
                raise exception.ManilaException('Unexpected request')
        post.side_effect = my_side_effect

        self.assertRaises(
            exception.ManilaException, self.drv.check_for_setup_error)
        post.assert_any_call(
            self.request_params.url, data=self.request_params.build_post_args(
                'volume', 'object_exists', self.volume),
            headers=self.request_params.headers)
        post.assert_any_call(
            self.request_params.url, data=self.request_params.build_post_args(
                'folder', 'object_exists', folder),
            headers=self.request_params.headers)

    @patch(PATH_TO_RPC)
    def test_create_share(self, post):
        share = {
            'name': 'share',
            'size': 1,
            'share_proto': self.cfg.enabled_share_protocols
        }
        self.cfg.nexenta_thin_provisioning = False
        path = '%s/%s/%s' % (self.volume, self.share, share['name'])
        location = {'path': '%s:/volumes/%s' % (self.cfg.nexenta_host, path)}
        post.return_value = FakeResponse()

        self.assertEqual([location],
                         self.drv.create_share(self.ctx, share))

    @patch(PATH_TO_RPC)
    def test_create_share__wrong_proto(self, post):
        share = {
            'name': 'share',
            'size': 1,
            'share_proto': 'A_VERY_WRONG_PROTO'
        }
        post.return_value = FakeResponse()

        self.assertRaises(exception.InvalidShare, self.drv.create_share,
                          self.ctx, share)

    @patch(PATH_TO_RPC)
    def test_create_share__thin_provisioning(self, post):
        share = {'name': 'share', 'size': 1,
                 'share_proto': self.cfg.enabled_share_protocols}
        create_folder_props = {
            'recordsize': '4K',
            'quota': '1G',
            'compression': self.cfg.nexenta_dataset_compression,
        }
        parent_path = '%s/%s' % (self.volume, self.share)
        post.return_value = FakeResponse()
        self.cfg.nexenta_thin_provisioning = True

        self.drv.create_share(self.ctx, share)

        post.assert_called_with(
            self.request_params.url,
            data=self.request_params.build_post_args(
                'folder',
                'create_with_props',
                parent_path,
                share['name'],
                create_folder_props),
            headers=self.request_params.headers)

    @patch(PATH_TO_RPC)
    def test_create_share__thick_provisioning(self, post):
        share = {
            'name': 'share',
            'size': 1,
            'share_proto': self.cfg.enabled_share_protocols
        }
        quota = '%sG' % share['size']
        create_folder_props = {
            'recordsize': '4K',
            'quota': quota,
            'compression': self.cfg.nexenta_dataset_compression,
            'reservation': quota,
        }
        parent_path = '%s/%s' % (self.volume, self.share)
        post.return_value = FakeResponse()
        self.cfg.nexenta_thin_provisioning = False

        self.drv.create_share(self.ctx, share)

        post.assert_called_with(
            self.request_params.url,
            data=self.request_params.build_post_args(
                'folder',
                'create_with_props',
                parent_path,
                share['name'],
                create_folder_props),
            headers=self.request_params.headers)

    @patch(PATH_TO_RPC)
    def test_create_share_from_snapshot(self, post):
        share = {
            'name': 'share',
            'size': 1,
            'share_proto': self.cfg.enabled_share_protocols
        }
        snapshot = {'name': 'sn1', 'share_name': share['name']}
        post.return_value = FakeResponse()
        path = '%s/%s/%s' % (self.volume, self.share, share['name'])
        location = {'path': '%s:/volumes/%s' % (self.cfg.nexenta_host, path)}
        snapshot_name = '%s/%s/%s@%s' % (
            self.volume, self.share, snapshot['share_name'], snapshot['name'])

        self.assertEqual([location], self.drv.create_share_from_snapshot(
            self.ctx, share, snapshot))
        post.assert_any_call(
            self.request_params.url,
            data=self.request_params.build_post_args(
                'folder',
                'clone',
                snapshot_name,
                '%s/%s/%s' % (self.volume, self.share, share['name'])),
            headers=self.request_params.headers)

    @patch(PATH_TO_RPC)
    def test_delete_share(self, post):
        share = {
            'name': 'share',
            'size': 1,
            'share_proto': self.cfg.enabled_share_protocols
        }
        post.return_value = FakeResponse()
        folder = '%s/%s/%s' % (self.volume, self.share, share['name'])

        self.drv.delete_share(self.ctx, share)

        post.assert_any_call(
            self.request_params.url,
            data=self.request_params.build_post_args(
                'folder',
                'destroy',
                folder.strip(),
                '-r'),
            headers=self.request_params.headers)

    @patch(PATH_TO_RPC)
    def test_delete_share__exists_error(self, post):
        share = {
            'name': 'share',
            'size': 1,
            'share_proto': self.cfg.enabled_share_protocols
        }
        post.return_value = FakeResponse()
        post.side_effect = exception.NexentaException('does not exist')

        self.drv.delete_share(self.ctx, share)

    @patch(PATH_TO_RPC)
    def test_delete_share__some_error(self, post):
        share = {
            'name': 'share',
            'size': 1,
            'share_proto': self.cfg.enabled_share_protocols
        }
        post.return_value = FakeResponse()
        post.side_effect = exception.ManilaException('Some error')

        self.assertRaises(
            exception.ManilaException, self.drv.delete_share, self.ctx, share)

    @patch(PATH_TO_RPC)
    def test_extend_share__thin_provisoning(self, post):
        share = {
            'name': 'share',
            'size': 1,
            'share_proto': self.cfg.enabled_share_protocols
        }
        new_size = 5
        quota = '%sG' % new_size
        post.return_value = FakeResponse()
        self.cfg.nexenta_thin_provisioning = True

        self.drv.extend_share(share, new_size)

        post.assert_called_with(
            self.request_params.url,
            data=self.request_params.build_post_args(
                'folder',
                'set_child_prop',
                '%s/%s/%s' % (self.volume, self.share, share['name']),
                'quota', quota),
            headers=self.request_params.headers)

    @patch(PATH_TO_RPC)
    def test_extend_share__thick_provisoning(self, post):
        share = {
            'name': 'share',
            'size': 1,
            'share_proto': self.cfg.enabled_share_protocols
        }
        new_size = 5
        post.return_value = FakeResponse()
        self.cfg.nexenta_thin_provisioning = False

        self.drv.extend_share(share, new_size)

        post.assert_not_called()

    @patch(PATH_TO_RPC)
    def test_create_snapshot(self, post):
        snapshot = {'share_name': 'share', 'name': 'share@first'}
        post.return_value = FakeResponse()
        folder = '%s/%s/%s' % (self.volume, self.share, snapshot['share_name'])

        self.drv.create_snapshot(self.ctx, snapshot)

        post.assert_called_with(
            self.request_params.url, data=self.request_params.build_post_args(
                'folder', 'create_snapshot', folder, snapshot['name'], '-r'),
            headers=self.request_params.headers)

    @patch(PATH_TO_RPC)
    def test_delete_snapshot(self, post):
        snapshot = {'share_name': 'share', 'name': 'share@first'}
        post.return_value = FakeResponse()

        self.drv.delete_snapshot(self.ctx, snapshot)

        post.assert_called_with(
            self.request_params.url, data=self.request_params.build_post_args(
                'snapshot', 'destroy', '%s@%s' % (
                    self._get_share_path(snapshot['share_name']),
                    snapshot['name']),
                ''),
            headers=self.request_params.headers)

    @patch(PATH_TO_RPC)
    def test_delete_snapshot__nexenta_error_1(self, post):
        snapshot = {'share_name': 'share', 'name': 'share@first'}
        post.return_value = FakeResponse()
        post.side_effect = exception.NexentaException('does not exist')

        self.drv.delete_snapshot(self.ctx, snapshot)

    @patch(PATH_TO_RPC)
    def test_delete_snapshot__nexenta_error_2(self, post):
        snapshot = {'share_name': 'share', 'name': 'share@first'}
        post.return_value = FakeResponse()
        post.side_effect = exception.NexentaException('has dependent clones')

        self.drv.delete_snapshot(self.ctx, snapshot)

    @patch(PATH_TO_RPC)
    def test_delete_snapshot__some_error(self, post):
        snapshot = {'share_name': 'share', 'name': 'share@first'}
        post.return_value = FakeResponse()
        post.side_effect = exception.ManilaException('Some error')

        self.assertRaises(exception.ManilaException, self.drv.delete_snapshot,
                          self.ctx, snapshot)

    @patch(PATH_TO_RPC)
    def test_update_access__unsupported_access_type(self, post):
        share = {
            'name': 'share',
            'share_proto': self.cfg.enabled_share_protocols
        }
        access = {
            'access_type': 'group',
            'access_to': 'ordinary_users',
            'access_level': 'rw'
        }

        self.assertRaises(exception.InvalidShareAccess,
                          self.drv.update_access,
                          self.ctx,
                          share,
                          [access],
                          None,
                          None)

    @patch(PATH_TO_RPC)
    def test_update_access__cidr(self, post):
        share = {
            'name': 'share',
            'share_proto': self.cfg.enabled_share_protocols
        }
        access1 = {
            'access_type': 'ip',
            'access_to': '1.1.1.1/24',
            'access_level': 'rw'
        }
        access2 = {
            'access_type': 'ip',
            'access_to': '1.2.3.4',
            'access_level': 'rw'
        }
        access_rules = [access1, access2]

        share_opts = {
            'auth_type': 'none',
            'read_write': '%s:%s' % (
                access1['access_to'], access2['access_to']),
            'read_only': '',
            'recursive': 'true',
            'anonymous_rw': 'true',
            'anonymous': 'true',
            'extra_options': 'anon=0',
        }

        def my_side_effect(*args, **kwargs):
            if kwargs['data'] == self.request_params.build_post_args(
                    'netstorsvc', 'share_folder',
                    'svc:/network/nfs/server:default',
                    self._get_share_path(share['name']), share_opts):
                return FakeResponse()
            else:
                raise exception.ManilaException('Unexpected request')

        post.return_value = FakeResponse()
        post.side_effect = my_side_effect

        self.drv.update_access(self.ctx, share, access_rules, None, None)

        post.assert_called_with(
            self.request_params.url, data=self.request_params.build_post_args(
                'netstorsvc', 'share_folder',
                'svc:/network/nfs/server:default',
                self._get_share_path(share['name']), share_opts),
            headers=self.request_params.headers)
        self.assertRaises(exception.ManilaException, self.drv.update_access,
                          self.ctx, share,
                          [access1, {'access_type': 'ip',
                                     'access_to': '2.2.2.2',
                                     'access_level': 'rw'}],
                          None, None)

    @patch(PATH_TO_RPC)
    def test_update_access__add_one_ip_to_empty_access_list(self, post):
        share = {'name': 'share',
                 'share_proto': self.cfg.enabled_share_protocols}
        access = {
            'access_type': 'ip',
            'access_to': '1.1.1.1',
            'access_level': 'rw'
        }

        rw_list = None
        share_opts = {
            'auth_type': 'none',
            'read_write': access['access_to'],
            'read_only': '',
            'recursive': 'true',
            'anonymous_rw': 'true',
            'anonymous': 'true',
            'extra_options': 'anon=0',
        }

        def my_side_effect(*args, **kwargs):
            if kwargs['data'] == self.request_params.build_post_args(
                    'netstorsvc', 'get_shareopts',
                    'svc:/network/nfs/server:default',
                    self._get_share_path(share['name'])):
                return FakeResponse({'result': {'read_write': rw_list}})
            elif kwargs['data'] == self.request_params.build_post_args(
                    'netstorsvc', 'share_folder',
                    'svc:/network/nfs/server:default',
                    self._get_share_path(share['name']), share_opts):
                return FakeResponse()
            else:
                raise exception.ManilaException('Unexpected request')
        post.return_value = FakeResponse()

        self.drv.update_access(self.ctx, share, [access], None, None)

        post.assert_called_with(
            self.request_params.url, data=self.request_params.build_post_args(
                'netstorsvc', 'share_folder',
                'svc:/network/nfs/server:default',
                self._get_share_path(share['name']), share_opts),
            headers=self.request_params.headers)

        post.side_effect = my_side_effect

        self.assertRaises(exception.ManilaException, self.drv.update_access,
                          self.ctx, share,
                          [{'access_type': 'ip',
                            'access_to': '1111',
                            'access_level': 'rw'}],
                          None, None)

    @patch(PATH_TO_RPC)
    def test_deny_access__unsupported_access_type(self, post):
        share = {'name': 'share',
                 'share_proto': self.cfg.enabled_share_protocols}
        access = {
            'access_type': 'group',
            'access_to': 'ordinary_users',
            'access_level': 'rw'
        }

        self.assertRaises(exception.InvalidShareAccess, self.drv.update_access,
                          self.ctx, share, [access], None, None)

    def test_share_backend_name(self):
        self.assertEqual('NexentaStor', self.drv.share_backend_name)

    @patch(PATH_TO_RPC)
    def test_get_capacity_info(self, post):
        post.return_value = FakeResponse({'result': {
            'available': 9 * units.Gi, 'used': 1 * units.Gi}})

        self.assertEqual(
            (10, 9, 1), self.drv.helper._get_capacity_info())

    @patch('manila.share.drivers.nexenta.ns4.nexenta_nfs_helper.NFSHelper.'
           '_get_capacity_info')
    @patch('manila.share.driver.ShareDriver._update_share_stats')
    def test_update_share_stats(self, super_stats, info):
        info.return_value = (100, 90, 10)
        stats = {
            'vendor_name': 'Nexenta',
            'storage_protocol': 'NFS',
            'nfs_mount_point_base': self.cfg.nexenta_mount_point_base,
            'driver_version': '1.0',
            'share_backend_name': self.cfg.share_backend_name,
            'pools': [{
                'total_capacity_gb': 100,
                'free_capacity_gb': 90,
                'pool_name': 'volume',
                'reserved_percentage': (
                    self.cfg.reserved_share_percentage),
                'compression': True,
                'dedupe': True,
                'thin_provisioning': self.cfg.nexenta_thin_provisioning,
                'max_over_subscription_ratio': (
                    self.cfg.safe_get(
                        'max_over_subscription_ratio')),
            }],
        }

        self.drv._update_share_stats()

        self.assertEqual(stats, self.drv._stats)
