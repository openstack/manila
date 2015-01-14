# Copyright (c) 2014, Oracle and/or its affiliates. All rights reserved.
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
Unit tests for Oracle's ZFSSA Manila driver.
"""
import mock
from oslo_config import cfg

from manila import context
from manila import exception
from manila.share import configuration as conf
from manila.share.drivers.zfssa import zfssashare
from manila import test
from manila.tests import fake_zfssa


CONF = cfg.CONF


class ZFSSAShareDriverTestCase(test.TestCase):
    """Tests ZFSSAShareDriver."""

    share = {
        'id': 'fakeid',
        'name': 'fakename',
        'size': 1,
        'share_proto': 'NFS',
        'export_location': '127.0.0.1:/mnt/nfs/volume-00002',
    }

    snapshot = {
        'id': 'fakesnapshotid',
        'share_name': 'fakename',
        'share_id': 'fakeid',
        'name': 'fakesnapshotname',
        'share_size': 1,
        'share_proto': 'NFS',
        'export_location': '127.0.0.1:/mnt/nfs/volume-00002',
    }

    access = {
        'id': 'fakeaccid',
        'access_type': 'ip',
        'access_to': '10.0.0.2',
        'state': 'active',
    }

    @mock.patch.object(zfssashare, 'factory_zfssa')
    def setUp(self, _factory_zfssa):
        super(ZFSSAShareDriverTestCase, self).setUp()
        self._create_fake_config()
        lcfg = self.configuration
        self.mountpoint = '/export/' + lcfg.zfssa_nas_mountpoint
        _factory_zfssa.return_value = fake_zfssa.FakeZFSSA()
        _factory_zfssa.set_host(lcfg.zfssa_host)
        _factory_zfssa.login(lcfg.zfssa_auth_user)
        self._context = context.get_admin_context()
        self._driver = zfssashare.ZFSSAShareDriver(False, configuration=lcfg)
        self._driver.do_setup(self._context)

    def _create_fake_config(self):
        def _safe_get(opt):
            return getattr(self.configuration, opt)

        self.configuration = mock.Mock(spec=conf.Configuration)
        self.configuration.safe_get = mock.Mock(side_effect=_safe_get)
        self.configuration.zfssa_host = '1.1.1.1'
        self.configuration.zfssa_data_ip = '1.1.1.1'
        self.configuration.zfssa_auth_user = 'user'
        self.configuration.zfssa_auth_password = 'passwd'
        self.configuration.zfssa_pool = 'pool'
        self.configuration.zfssa_project = 'project'
        self.configuration.zfssa_nas_mountpoint = 'project'
        self.configuration.zfssa_nas_checksum = 'fletcher4'
        self.configuration.zfssa_nas_logbias = 'latency'
        self.configuration.zfssa_nas_compression = 'off'
        self.configuration.zfssa_nas_vscan = 'false'
        self.configuration.zfssa_nas_rstchown = 'true'
        self.configuration.zfssa_nas_quota_snap = 'true'
        self.configuration.zfssa_rest_timeout = 60
        self.configuration.network_config_group = 'fake_network_config_group'
        self.configuration.driver_handles_share_servers = False

    def test_create_share(self):
        self.stubs.Set(self._driver.zfssa, 'create_share', mock.Mock())
        self.stubs.Set(self._driver, '_export_location', mock.Mock())
        lcfg = self.configuration
        arg = {
            'host': lcfg.zfssa_data_ip,
            'mountpoint': self.mountpoint,
            'name': self.share['id'],
        }
        location = ("%(host)s:%(mountpoint)s/%(name)s" % arg)
        self._driver._export_location.return_value = location
        arg = self._driver.create_arg(self.share['size'])
        arg.update(self._driver.default_args)
        arg.update({'name': self.share['id']})
        ret = self._driver.create_share(self._context, self.share)
        self._driver.zfssa.create_share.assert_called_with(lcfg.zfssa_pool,
                                                           lcfg.zfssa_project,
                                                           arg)
        self.assertEqual(location, ret)
        self.assertEqual(1, self._driver.zfssa.create_share.call_count)
        self.assertEqual(1, self._driver._export_location.call_count)

    def test_create_share_from_snapshot(self):
        self.stubs.Set(self._driver.zfssa, 'clone_snapshot', mock.Mock())
        self.stubs.Set(self._driver, '_export_location', mock.Mock())
        lcfg = self.configuration
        arg = {
            'host': lcfg.zfssa_data_ip,
            'mountpoint': self.mountpoint,
            'name': self.share['id'],
        }
        location = ("%(host)s:%(mountpoint)s/%(name)s" % arg)
        self._driver._export_location.return_value = location
        arg = self._driver.create_arg(self.share['size'])
        details = {
            'share': self.share['id'],
            'project': lcfg.zfssa_project,
        }
        arg.update(details)
        ret = self._driver.create_share_from_snapshot(self._context,
                                                      self.share,
                                                      self.snapshot)
        self.assertEqual(location, ret)
        self.assertEqual(1, self._driver.zfssa.clone_snapshot.call_count)
        self.assertEqual(1, self._driver._export_location.call_count)
        self._driver.zfssa.clone_snapshot.assert_called_with(
            lcfg.zfssa_pool,
            lcfg.zfssa_project,
            self.snapshot,
            self.share,
            arg)

    def test_delete_share(self):
        self.stubs.Set(self._driver.zfssa, 'delete_share', mock.Mock())
        self._driver.delete_share(self._context, self.share)
        self.assertEqual(1, self._driver.zfssa.delete_share.call_count)
        lcfg = self.configuration
        self._driver.zfssa.delete_share.assert_called_with(lcfg.zfssa_pool,
                                                           lcfg.zfssa_project,
                                                           self.share['id'])

    def test_create_snapshot(self):
        self.stubs.Set(self._driver.zfssa, 'create_snapshot', mock.Mock())
        lcfg = self.configuration
        self._driver.create_snapshot(self._context, self.snapshot)
        self.assertEqual(1, self._driver.zfssa.create_snapshot.call_count)
        self._driver.zfssa.create_snapshot.assert_called_with(
            lcfg.zfssa_pool,
            lcfg.zfssa_project,
            self.snapshot['share_id'],
            self.snapshot['id'])

    def test_delete_snapshot(self):
        self.stubs.Set(self._driver.zfssa, 'delete_snapshot', mock.Mock())
        self._driver.delete_snapshot(self._context, self.snapshot)
        self.assertEqual(1, self._driver.zfssa.delete_snapshot.call_count)

    def test_delete_snapshot_negative(self):
        self.stubs.Set(self._driver.zfssa, 'has_clones', mock.Mock())
        self._driver.zfssa.has_clones.return_value = True
        self.assertRaises(exception.ShareSnapshotIsBusy,
                          self._driver.delete_snapshot,
                          self._context,
                          self.snapshot)

    def test_ensure_share(self):
        self.stubs.Set(self._driver.zfssa, 'get_share', mock.Mock())
        lcfg = self.configuration
        self._driver.ensure_share(self._context, self.share)
        self.assertEqual(1, self._driver.zfssa.get_share.call_count)
        self._driver.zfssa.get_share.assert_called_with(
            lcfg.zfssa_pool,
            lcfg.zfssa_project,
            self.share['id'])

        self._driver.zfssa.get_share.return_value = None
        self.assertRaises(exception.ManilaException,
                          self._driver.ensure_share,
                          self._context,
                          self.share)

    def test_allow_access(self):
        self.stubs.Set(self._driver.zfssa, 'allow_access_nfs', mock.Mock())
        lcfg = self.configuration
        self._driver.allow_access(self._context, self.share, self.access)
        self.assertEqual(1, self._driver.zfssa.allow_access_nfs.call_count)
        self._driver.zfssa.allow_access_nfs.assert_called_with(
            lcfg.zfssa_pool,
            lcfg.zfssa_project,
            self.share['id'],
            self.access)

    def test_deny_access(self):
        self.stubs.Set(self._driver.zfssa, 'deny_access_nfs', mock.Mock())
        lcfg = self.configuration
        self._driver.deny_access(self._context, self.share, self.access)
        self.assertEqual(1, self._driver.zfssa.deny_access_nfs.call_count)
        self._driver.zfssa.deny_access_nfs.assert_called_with(
            lcfg.zfssa_pool,
            lcfg.zfssa_project,
            self.share['id'],
            self.access)
