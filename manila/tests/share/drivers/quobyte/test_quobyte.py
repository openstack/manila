# Copyright (c) 2015 Quobyte, Inc.
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

import mock
from oslo_config import cfg
import six

from manila import context
from manila import exception
from manila.share import configuration as config
from manila.share import driver
from manila.share.drivers.quobyte import jsonrpc
from manila.share.drivers.quobyte import quobyte
from manila import test
from manila.tests import fake_share

CONF = cfg.CONF


def fake_rpc_handler(name, *args):
    if name == 'resolveVolumeName':
        return None
    elif name == 'createVolume':
        return {'volume_uuid': 'voluuid'}
    elif name == 'exportVolume':
        return {'nfs_server_ip': 'fake_location',
                'nfs_export_path': '/fake_share'}


class QuobyteShareDriverTestCase(test.TestCase):
    """Tests QuobyteShareDriver."""

    def setUp(self):
        super(QuobyteShareDriverTestCase, self).setUp()

        self._context = context.get_admin_context()

        CONF.set_default('driver_handles_share_servers', False)

        self.fake_conf = config.Configuration(None)
        self._driver = quobyte.QuobyteShareDriver(configuration=self.fake_conf)
        self._driver.rpc = mock.Mock()
        self.share = fake_share.fake_share(share_proto='NFS')
        self.access = fake_share.fake_access()

    @mock.patch('manila.share.drivers.quobyte.jsonrpc.JsonRpc', mock.Mock())
    def test_do_setup_success(self):
        self._driver.rpc.call = mock.Mock(return_value=None)

        self._driver.do_setup(self._context)

        self._driver.rpc.call.assert_called_with('getInformation', {})

    @mock.patch('manila.share.drivers.quobyte.jsonrpc.JsonRpc.__init__',
                mock.Mock(return_value=None))
    @mock.patch.object(jsonrpc.JsonRpc, 'call',
                       side_effect=exception.QBRpcException)
    def test_do_setup_failure(self, mock_call):
        self.assertRaises(exception.QBException,
                          self._driver.do_setup, self._context)

    def test_create_share_new_volume(self):
        self._driver.rpc.call = mock.Mock(wraps=fake_rpc_handler)

        result = self._driver.create_share(self._context, self.share)

        self.assertEqual(self.share['export_location'], result)
        self._driver.rpc.call.assert_has_calls([
            mock.call('createVolume', dict(
                name=self.share['name'],
                tenant_domain=self.share['project_id'],
                root_user_id=self.fake_conf.quobyte_default_volume_user,
                root_group_id=self.fake_conf.quobyte_default_volume_group,
                configuration_name=self.fake_conf.quobyte_volume_configuration
            )),
            mock.call('exportVolume',
                      dict(protocol='NFS', volume_uuid='voluuid'))])

    def test_create_share_existing_volume(self):
        self._driver.rpc.call = mock.Mock(wraps=fake_rpc_handler)

        self._driver.create_share(self._context, self.share)

        self._driver.rpc.call.assert_called_with(
            'exportVolume', dict(protocol='NFS', volume_uuid='voluuid'))

    def test_create_share_wrong_protocol(self):
        share = {'share_proto': 'WRONG_PROTOCOL'}

        self.assertRaises(exception.QBException,
                          self._driver.create_share,
                          context=None,
                          share=share)

    def test_delete_share_existing_volume(self):
        def rpc_handler(name, *args):
            if name == 'resolveVolumeName':
                return {'volume_uuid': 'voluuid'}
            elif name == 'exportVolume':
                return {}

        self._driver.configuration.quobyte_delete_shares = True
        self._driver.rpc.call = mock.Mock(wraps=rpc_handler)

        self._driver.delete_share(self._context, self.share)

        self._driver.rpc.call.assert_has_calls([
            mock.call('resolveVolumeName',
                      {'volume_name': 'fakename',
                       'tenant_domain': 'fake_project_uuid'}),
            mock.call('deleteVolume', {'volume_uuid': 'voluuid'}),
            mock.call('exportVolume', {'volume_uuid': 'voluuid',
                                       'remove_export': True})])

    def test_delete_share_existing_volume_disabled(self):
        def rpc_handler(name, *args):
            if name == 'resolveVolumeName':
                return {'volume_uuid': 'voluuid'}
            elif name == 'exportVolume':
                return {}

        CONF.set_default('quobyte_delete_shares', False)
        self._driver.rpc.call = mock.Mock(wraps=rpc_handler)

        self._driver.delete_share(self._context, self.share)

        self._driver.rpc.call.assert_called_with(
            'exportVolume', {'volume_uuid': 'voluuid',
                             'remove_export': True})

    @mock.patch.object(quobyte.LOG, 'warning')
    def test_delete_share_nonexisting_volume(self, mock_warning):
        def rpc_handler(name, *args):
            if name == 'resolveVolumeName':
                return None

        self._driver.rpc.call = mock.Mock(wraps=rpc_handler)

        self._driver.delete_share(self._context, self.share)

        mock_warning.assert_called_with(
            'No volume found for share fake_project_uuid/fakename')

    def test_allow_access(self):
        def rpc_handler(name, *args):
            if name == 'resolveVolumeName':
                return {'volume_uuid': 'voluuid'}
            elif name == 'exportVolume':
                return {'nfs_server_ip': '10.10.1.1',
                        'nfs_export_path': '/voluuid'}

        self._driver.rpc.call = mock.Mock(wraps=rpc_handler)

        self._driver.allow_access(self._context, self.share, self.access)

        self._driver.rpc.call.assert_called_with(
            'exportVolume', {'volume_uuid': 'voluuid',
                             'read_only': False,
                             'add_allow_ip': '10.0.0.1'})

    def test_allow_ro_access(self):
        def rpc_handler(name, *args):
            if name == 'resolveVolumeName':
                return {'volume_uuid': 'voluuid'}
            elif name == 'exportVolume':
                return {'nfs_server_ip': '10.10.1.1',
                        'nfs_export_path': '/voluuid'}

        self._driver.rpc.call = mock.Mock(wraps=rpc_handler)
        ro_access = fake_share.fake_access(access_level='ro')

        self._driver.allow_access(self._context, self.share, ro_access)

        self._driver.rpc.call.assert_called_with(
            'exportVolume', {'volume_uuid': 'voluuid',
                             'read_only': True,
                             'add_allow_ip': '10.0.0.1'})

    def test_allow_access_nonip(self):
        self._driver.rpc.call = mock.Mock(wraps=fake_rpc_handler)

        self.access = fake_share.fake_access(**{"access_type":
                                                "non_existant_access_type"})

        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.allow_access,
                          self._context, self.share, self.access)

    def test_deny_access(self):
        def rpc_handler(name, *args):
            if name == 'resolveVolumeName':
                return {'volume_uuid': 'voluuid'}
            elif name == 'exportVolume':
                return {'nfs_server_ip': '10.10.1.1',
                        'nfs_export_path': '/voluuid'}

        self._driver.rpc.call = mock.Mock(wraps=rpc_handler)

        self._driver.deny_access(self._context, self.share, self.access)

        self._driver.rpc.call.assert_called_with(
            'exportVolume',
            {'volume_uuid': 'voluuid', 'remove_allow_ip': '10.0.0.1'})

    @mock.patch.object(quobyte.LOG, 'debug')
    def test_deny_access_nonip(self, mock_debug):
        self._driver.rpc.call = mock.Mock(wraps=fake_rpc_handler)
        self.access = fake_share.fake_access(
            access_type="non_existant_access_type")

        self._driver.deny_access(self._context, self.share, self.access)

        mock_debug.assert_called_with(
            'Quobyte driver only supports ip access control. '
            'Ignoring deny access call for %s , %s',
            'fakename', 'fake_project_uuid')

    def test_resolve_volume_name(self):
        self._driver.rpc.call = mock.Mock(
            return_value={'volume_uuid': 'fake_uuid'})

        self._driver._resolve_volume_name('fake_vol_name', 'fake_domain_name')

        self._driver.rpc.call.assert_called_with(
            'resolveVolumeName',
            {'volume_name': 'fake_vol_name',
             'tenant_domain': 'fake_domain_name'})

    def test_resolve_volume_name_NOENT(self):
        self._driver.rpc.call = mock.Mock(
            return_value=None)

        self.assertIsNone(
            self._driver._resolve_volume_name('fake_vol_name',
                                              'fake_domain_name'))

    def test_resolve_volume_name_other_error(self):
        self._driver.rpc.call = mock.Mock(
            side_effect=exception.QBRpcException(
                result='fubar',
                qbcode=666))

        self.assertRaises(exception.QBRpcException,
                          self._driver._resolve_volume_name,
                          volume_name='fake_vol_name',
                          tenant_domain='fake_domain_name')

    @mock.patch.object(driver.ShareDriver, '_update_share_stats')
    def test_update_share_stats(self, mock_uss):
        self._driver._get_capacities = mock.Mock(return_value=[42, 23])

        self._driver._update_share_stats()

        mock_uss.assert_called_once_with(
            dict(storage_protocol='NFS',
                 vendor_name='Quobyte',
                 share_backend_name=self._driver.backend_name,
                 driver_version=self._driver.DRIVER_VERSION,
                 total_capacity_gb=42,
                 free_capacity_gb=23,
                 reserved_percentage=0))

    def test_get_capacities_gb(self):
        capval = 42115548133
        useval = 19695128917
        self._driver.rpc.call = mock.Mock(
            return_value={'total_logical_capacity': six.text_type(capval),
                          'total_logical_usage': six.text_type(useval)})

        self.assertEqual((39.223160718, 20.880642548),
                         self._driver._get_capacities())

    @mock.patch.object(quobyte.QuobyteShareDriver,
                       "_resolve_volume_name",
                       return_value="fake_uuid")
    def test_ensure_share(self, mock_qb_resolve_volname):
        self._driver.rpc.call = mock.Mock(wraps=fake_rpc_handler)

        result = self._driver.ensure_share(self._context, self.share, None)

        self.assertEqual(self.share["export_location"], result)
        (mock_qb_resolve_volname.
         assert_called_once_with(self.share['name'],
                                 self.share['project_id']))
        self._driver.rpc.call.assert_has_calls([
            mock.call('exportVolume', dict(
                volume_uuid="fake_uuid",
                protocol='NFS'
            ))])

    @mock.patch.object(quobyte.QuobyteShareDriver,
                       "_resolve_volume_name",
                       return_value=None)
    def test_ensure_deleted_share(self, mock_qb_resolve_volname):
        self._driver.rpc.call = mock.Mock(wraps=fake_rpc_handler)

        self.assertRaises(exception.ShareResourceNotFound,
                          self._driver.ensure_share,
                          self._context, self.share, None)
        (mock_qb_resolve_volname.
         assert_called_once_with(self.share['name'],
                                 self.share['project_id']))

    @mock.patch.object(quobyte.QuobyteShareDriver, "_resize_share")
    def test_extend_share(self, mock_qsd_resize_share):
        self._driver.extend_share(ext_share=self.share,
                                  ext_size=2,
                                  share_server=None)
        mock_qsd_resize_share.assert_called_once_with(share=self.share,
                                                      new_size=2)

    def test_resize_share(self):
        self._driver.rpc.call = mock.Mock(wraps=fake_rpc_handler)

        self._driver._resize_share(share=self.share, new_size=7)

        self._driver.rpc.call.assert_has_calls([
            mock.call('setQuota',
                      {"consumer": {"type": 3,
                                    "identifier": self.share["name"]},
                       "limits": {"type": 5, "value": 7}})])

    @mock.patch.object(quobyte.QuobyteShareDriver, "_resize_share")
    def test_shrink_share(self, mock_qsd_resize_share):
        self._driver.shrink_share(shrink_share=self.share,
                                  shrink_size=3,
                                  share_server=None)
        mock_qsd_resize_share.assert_called_once_with(share=self.share,
                                                      new_size=3)
