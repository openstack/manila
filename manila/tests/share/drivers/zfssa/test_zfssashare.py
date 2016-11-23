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
from oslo_utils import units

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
        'export_location': '/mnt/nfs/volume-00002',
    }

    share2 = {
        'id': 'fakeid2',
        'name': 'fakename2',
        'size': 4,
        'share_proto': 'CIFS',
        'export_location': '/mnt/nfs/volume-00003',
        'space_data': 3006477107
    }

    snapshot = {
        'id': 'fakesnapshotid',
        'share_name': 'fakename',
        'share_id': 'fakeid',
        'name': 'fakesnapshotname',
        'share_size': 1,
        'share_proto': 'NFS',
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

        self.fake_proto_share = {
            'id': self.share['id'],
            'share_proto': 'fake_proto',
            'export_locations': [{'path': self.share['export_location']}],
        }

        self.test_share = {
            'id': self.share['id'],
            'share_proto': 'NFS',
            'export_locations': [{'path': self.share['export_location']}],
        }

        self.test_share2 = {
            'id': self.share2['id'],
            'share_proto': 'CIFS',
            'export_locations': [{'path': self.share2['export_location']}],
        }

        self.driver_options = {'zfssa_name': self.share['name']}

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
        self.configuration.admin_network_config_group = (
            'fake_admin_network_config_group')
        self.configuration.driver_handles_share_servers = False
        self.configuration.zfssa_manage_policy = 'strict'

    def test_create_share(self):
        self.mock_object(self._driver.zfssa, 'create_share')
        self.mock_object(self._driver, '_export_location')
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
        self.mock_object(self._driver.zfssa, 'clone_snapshot')
        self.mock_object(self._driver, '_export_location')
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
        self.mock_object(self._driver.zfssa, 'delete_share')
        self._driver.delete_share(self._context, self.share)
        self.assertEqual(1, self._driver.zfssa.delete_share.call_count)
        lcfg = self.configuration
        self._driver.zfssa.delete_share.assert_called_with(lcfg.zfssa_pool,
                                                           lcfg.zfssa_project,
                                                           self.share['id'])

    def test_create_snapshot(self):
        self.mock_object(self._driver.zfssa, 'create_snapshot')
        lcfg = self.configuration
        self._driver.create_snapshot(self._context, self.snapshot)
        self.assertEqual(1, self._driver.zfssa.create_snapshot.call_count)
        self._driver.zfssa.create_snapshot.assert_called_with(
            lcfg.zfssa_pool,
            lcfg.zfssa_project,
            self.snapshot['share_id'],
            self.snapshot['id'])

    def test_delete_snapshot(self):
        self.mock_object(self._driver.zfssa, 'delete_snapshot')
        self._driver.delete_snapshot(self._context, self.snapshot)
        self.assertEqual(1, self._driver.zfssa.delete_snapshot.call_count)

    def test_delete_snapshot_negative(self):
        self.mock_object(self._driver.zfssa, 'has_clones')
        self._driver.zfssa.has_clones.return_value = True
        self.assertRaises(exception.ShareSnapshotIsBusy,
                          self._driver.delete_snapshot,
                          self._context,
                          self.snapshot)

    def test_ensure_share(self):
        self.mock_object(self._driver.zfssa, 'get_share')
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
        self.mock_object(self._driver.zfssa, 'allow_access_nfs')
        lcfg = self.configuration
        self._driver.allow_access(self._context, self.share, self.access)
        self.assertEqual(1, self._driver.zfssa.allow_access_nfs.call_count)
        self._driver.zfssa.allow_access_nfs.assert_called_with(
            lcfg.zfssa_pool,
            lcfg.zfssa_project,
            self.share['id'],
            self.access)

    def test_deny_access(self):
        self.mock_object(self._driver.zfssa, 'deny_access_nfs')
        lcfg = self.configuration
        self._driver.deny_access(self._context, self.share, self.access)
        self.assertEqual(1, self._driver.zfssa.deny_access_nfs.call_count)
        self._driver.zfssa.deny_access_nfs.assert_called_with(
            lcfg.zfssa_pool,
            lcfg.zfssa_project,
            self.share['id'],
            self.access)

    def test_extend_share_negative(self):
        self.mock_object(self._driver.zfssa, 'modify_share')
        new_size = 3
        # Not enough space in project, expect an exception:
        self.mock_object(self._driver.zfssa, 'get_project_stats')
        self._driver.zfssa.get_project_stats.return_value = 1 * units.Gi

        self.assertRaises(exception.ShareExtendingError,
                          self._driver.extend_share,
                          self.share,
                          new_size)

    def test_extend_share(self):
        self.mock_object(self._driver.zfssa, 'modify_share')
        new_size = 3
        lcfg = self.configuration
        self.mock_object(self._driver.zfssa, 'get_project_stats')
        self._driver.zfssa.get_project_stats.return_value = 10 * units.Gi

        arg = self._driver.create_arg(new_size)
        self._driver.extend_share(self.share, new_size)

        self.assertEqual(1, self._driver.zfssa.modify_share.call_count)
        self._driver.zfssa.modify_share.assert_called_with(
            lcfg.zfssa_pool,
            lcfg.zfssa_project,
            self.share['id'],
            arg)

    def test_shrink_share_negative(self):
        self.mock_object(self._driver.zfssa, 'modify_share')
        # Used space is larger than 2GB
        new_size = 2
        self.mock_object(self._driver.zfssa, 'get_share')
        self._driver.zfssa.get_share.return_value = self.share2

        self.assertRaises(exception.ShareShrinkingPossibleDataLoss,
                          self._driver.shrink_share,
                          self.share2,
                          new_size)

    def test_shrink_share(self):
        self.mock_object(self._driver.zfssa, 'modify_share')
        new_size = 3
        lcfg = self.configuration
        self.mock_object(self._driver.zfssa, 'get_share')
        self._driver.zfssa.get_share.return_value = self.share2

        arg = self._driver.create_arg(new_size)
        self._driver.shrink_share(self.share2, new_size)

        self.assertEqual(1, self._driver.zfssa.modify_share.call_count)
        self._driver.zfssa.modify_share.assert_called_with(
            lcfg.zfssa_pool,
            lcfg.zfssa_project,
            self.share2['id'],
            arg)

    def test_manage_invalid_option(self):
        self.mock_object(self._driver, '_get_share_details')

        # zfssa_name not in driver_options:
        self.assertRaises(exception.ShareBackendException,
                          self._driver.manage_existing,
                          self.share,
                          {})

    def test_manage_no_share_details(self):
        self.mock_object(self._driver, '_get_share_details')
        self._driver._get_share_details.side_effect = (
            exception.ShareResourceNotFound(share_id=self.share['name']))

        self.assertRaises(exception.ShareResourceNotFound,
                          self._driver.manage_existing,
                          self.share,
                          self.driver_options)

    def test_manage_invalid_size(self):
        details = {
            'quota': 10,  # 10 bytes
            'reservation': 10,
        }
        self.mock_object(self._driver, '_get_share_details')
        self._driver._get_share_details.return_value = details

        self.mock_object(self._driver.zfssa, 'get_project_stats')
        self._driver.zfssa.get_project_stats.return_value = 900

        # Share size is less than 1GB, but there is not enough free space
        self.assertRaises(exception.ManageInvalidShare,
                          self._driver.manage_existing,
                          self.test_share,
                          self.driver_options)

    def test_manage_invalid_protocol(self):
        self.mock_object(self._driver, '_get_share_details')
        self._driver._get_share_details.return_value = {
            'quota': self.share['size'] * units.Gi,
            'reservation': self.share['size'] * units.Gi,
            'custom:manila_managed': False,
        }

        self.assertRaises(exception.ManageInvalidShare,
                          self._driver.manage_existing,
                          self.fake_proto_share,
                          self.driver_options)

    def test_manage_unmanage_no_schema(self):
        self.mock_object(self._driver, '_get_share_details')
        self._driver._get_share_details.return_value = {}

        # Share does not have custom:manila_managed property
        # Test manage_existing():
        self.assertRaises(exception.ManageInvalidShare,
                          self._driver.manage_existing,
                          self.test_share,
                          self.driver_options)

        # Test unmanage():
        self.assertRaises(exception.UnmanageInvalidShare,
                          self._driver.unmanage,
                          self.test_share)

    def test_manage_round_up_size(self):
        details = {
            'quota': 100,
            'reservation': 50,
            'custom:manila_managed': False,
        }
        self.mock_object(self._driver, '_get_share_details')
        self._driver._get_share_details.return_value = details

        self.mock_object(self._driver.zfssa, 'get_project_stats')
        self._driver.zfssa.get_project_stats.return_value = 1 * units.Gi

        ret = self._driver.manage_existing(self.test_share,
                                           self.driver_options)

        # Expect share size is 1GB
        self.assertEqual(1, ret['size'])

    def test_manage_not_enough_space(self):
        details = {
            'quota': 3.5 * units.Gi,
            'reservation': 3.5 * units.Gi,
            'custom:manila_managed': False,
        }
        self.mock_object(self._driver, '_get_share_details')
        self._driver._get_share_details.return_value = details

        self.mock_object(self._driver.zfssa, 'get_project_stats')
        self._driver.zfssa.get_project_stats.return_value = 0.1 * units.Gi

        self.assertRaises(exception.ManageInvalidShare,
                          self._driver.manage_existing,
                          self.test_share,
                          self.driver_options)

    def test_manage_unmanage_NFS(self):
        lcfg = self.configuration
        details = {
            # Share size is 1GB
            'quota': self.share['size'] * units.Gi,
            'reservation': self.share['size'] * units.Gi,
            'custom:manila_managed': False,
        }
        arg = {
            'host': lcfg.zfssa_data_ip,
            'mountpoint': self.share['export_location'],
            'name': self.share['id'],
        }
        export_loc = "%(host)s:%(mountpoint)s/%(name)s" % arg
        self.mock_object(self._driver, '_get_share_details')
        self._driver._get_share_details.return_value = details

        ret = self._driver.manage_existing(self.test_share,
                                           self.driver_options)

        self.assertEqual(export_loc, ret['export_locations'])
        self.assertEqual(1, ret['size'])

    def test_manage_unmanage_CIFS(self):
        lcfg = self.configuration
        details = {
            # Share size is 1GB
            'quota': self.share2['size'] * units.Gi,
            'reservation': self.share2['size'] * units.Gi,
            'custom:manila_managed': False,
        }
        arg = {
            'host': lcfg.zfssa_data_ip,
            'name': self.share2['id'],
        }
        export_loc = "\\\\%(host)s\\%(name)s" % arg
        self.mock_object(self._driver, '_get_share_details')
        self._driver._get_share_details.return_value = details

        ret = self._driver.manage_existing(self.test_share2,
                                           self.driver_options)

        self.assertEqual(export_loc, ret['export_locations'])
        self.assertEqual(4, ret['size'])

    def test_unmanage_NFS(self):
        self.mock_object(self._driver.zfssa, 'modify_share')
        lcfg = self.configuration
        details = {
            'quota': self.share['size'] * units.Gi,
            'reservation': self.share['size'] * units.Gi,
            'custom:manila_managed': True,
        }

        arg = {
            'custom:manila_managed': False,
            'sharenfs': 'off',
        }

        self.mock_object(self._driver, '_get_share_details')
        self._driver._get_share_details.return_value = details

        self._driver.unmanage(self.test_share)

        self._driver.zfssa.modify_share.assert_called_with(
            lcfg.zfssa_pool,
            lcfg.zfssa_project,
            self.test_share['id'],
            arg)

    def test_unmanage_CIFS(self):
        self.mock_object(self._driver.zfssa, 'modify_share')
        lcfg = self.configuration
        details = {
            'quota': self.share2['size'] * units.Gi,
            'reservation': self.share2['size'] * units.Gi,
            'custom:manila_managed': True,
        }

        arg = {
            'custom:manila_managed': False,
            'sharesmb': 'off',
        }

        self.mock_object(self._driver, '_get_share_details')
        self._driver._get_share_details.return_value = details

        self._driver.unmanage(self.test_share2)

        self._driver.zfssa.modify_share.assert_called_with(
            lcfg.zfssa_pool,
            lcfg.zfssa_project,
            self.test_share2['id'],
            arg)

    def test_verify_share_to_manage_loose_policy(self):
        # Temporarily change policy to loose
        self.configuration.zfssa_manage_policy = 'loose'

        ret = self._driver._verify_share_to_manage('sharename', {})

        self.assertIsNone(ret)
        # Change it back to strict
        self.configuration.zfssa_manage_policy = 'strict'

    def test_verify_share_to_manage_no_property(self):
        self.configuration.zfssa_manage_policy = 'strict'
        self.assertRaises(exception.ManageInvalidShare,
                          self._driver._verify_share_to_manage,
                          'sharename',
                          {})

    def test_verify_share_to_manage_alredy_managed(self):
        details = {'custom:manila_managed': True}

        self.assertRaises(exception.ManageInvalidShare,
                          self._driver._verify_share_to_manage,
                          'sharename',
                          details)
