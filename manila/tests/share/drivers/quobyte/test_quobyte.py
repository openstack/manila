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
from oslo_utils import units
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


def fake_rpc_handler(name, *args, **kwargs):
    if name == 'resolveVolumeName':
        return None
    elif name == 'createVolume':
        return {'volume_uuid': 'voluuid'}
    elif name == 'exportVolume':
        return {'nfs_server_ip': 'fake_location',
                'nfs_export_path': '/fake_share'}
    elif name == 'getConfiguration':
        return {
            "tenant_configuration": [{
                "domain_name": "fake_domain_name",
                "volume_access": [
                    {"volume_uuid": "fake_id_1",
                     "restrict_to_network": "10.0.0.1",
                     "read_only": False},
                    {"volume_uuid": "fake_id_1",
                     "restrict_to_network": "10.0.0.2",
                     "read_only": False},
                    {"volume_uuid": "fake_id_2",
                     "restrict_to_network": "10.0.0.3",
                     "read_only": False}
                ]},
                {"domain_name": "fake_domain_name_2",
                 "volume_access": [
                     {"volume_uuid": "fake_id_3",
                      "restrict_to_network": "10.0.0.4",
                      "read_only": False},
                     {"volume_uuid": "fake_id_3",
                      "restrict_to_network": "10.0.0.5",
                      "read_only": True},
                     {"volume_uuid": "fake_id_4",
                      "restrict_to_network": "10.0.0.6",
                      "read_only": False}
                 ]}
            ]
        }
    else:
        return "Unknown fake rpc handler call"


def create_fake_access(access_adr,
                       access_id='fake_access_id',
                       access_type='ip',
                       access_level='rw'):
    return {
        'access_id': access_id,
        'access_type': access_type,
        'access_to': access_adr,
        'access_level': access_level
    }


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

    @mock.patch.object(quobyte.QuobyteShareDriver, "_resize_share")
    def test_create_share_new_volume(self, qb_resize_mock):
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
        qb_resize_mock.assert_called_once_with(self.share, self.share['size'])

    @mock.patch.object(quobyte.QuobyteShareDriver, "_resize_share")
    def test_create_share_existing_volume(self, qb_resize_mock):
        self._driver.rpc.call = mock.Mock(wraps=fake_rpc_handler)

        self._driver.create_share(self._context, self.share)

        resolv_params = {'tenant_domain': 'fake_project_uuid',
                         'volume_name': 'fakename'}
        sett_params = {'tenant': {'tenant_id': 'fake_project_uuid'}}
        create_params = dict(
            name='fakename',
            tenant_domain='fake_project_uuid',
            root_user_id='root',
            root_group_id='root',
            configuration_name='BASE')
        self._driver.rpc.call.assert_has_calls([
            mock.call('resolveVolumeName', resolv_params,
                      [jsonrpc.ERROR_ENOENT, jsonrpc.ERROR_ENTITY_NOT_FOUND]),
            mock.call('setTenant', sett_params,
                      expected_errors=[jsonrpc.ERROR_GARBAGE_ARGS]),
            mock.call('createVolume', create_params),
            mock.call('exportVolume', dict(protocol='NFS',
                                           volume_uuid='voluuid'))])
        qb_resize_mock.assert_called_once_with(self.share, self.share['size'])

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

        resolv_params = {'volume_name': 'fakename',
                         'tenant_domain': 'fake_project_uuid'}
        self._driver.rpc.call.assert_has_calls([
            mock.call('resolveVolumeName', resolv_params,
                      [jsonrpc.ERROR_ENOENT, jsonrpc.ERROR_ENTITY_NOT_FOUND]),
            mock.call('deleteVolume', {'volume_uuid': 'voluuid'})])

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
            'exportVolume', {'volume_uuid': 'voluuid', 'remove_export': True})

    @mock.patch.object(quobyte.LOG, 'warning')
    def test_delete_share_nonexisting_volume(self, mock_warning):
        def rpc_handler(name, *args):
            if name == 'resolveVolumeName':
                return None

        self._driver.rpc.call = mock.Mock(wraps=rpc_handler)

        self._driver.delete_share(self._context, self.share)

        mock_warning.assert_called_with(
            'No volume found for share %(project_id)s/%(name)s',
            {'project_id': 'fake_project_uuid', 'name': 'fakename'})

    def test_allow_access(self):
        def rpc_handler(name, *args):
            if name == 'resolveVolumeName':
                return {'volume_uuid': 'voluuid'}
            elif name == 'exportVolume':
                return {'nfs_server_ip': '10.10.1.1',
                        'nfs_export_path': '/voluuid'}

        self._driver.rpc.call = mock.Mock(wraps=rpc_handler)

        self._driver._allow_access(self._context, self.share, self.access)

        exp_params = {'volume_uuid': 'voluuid',
                      'read_only': False,
                      'add_allow_ip': '10.0.0.1'}
        self._driver.rpc.call.assert_called_with('exportVolume', exp_params)

    def test_allow_ro_access(self):
        def rpc_handler(name, *args):
            if name == 'resolveVolumeName':
                return {'volume_uuid': 'voluuid'}
            elif name == 'exportVolume':
                return {'nfs_server_ip': '10.10.1.1',
                        'nfs_export_path': '/voluuid'}

        self._driver.rpc.call = mock.Mock(wraps=rpc_handler)
        ro_access = fake_share.fake_access(access_level='ro')

        self._driver._allow_access(self._context, self.share, ro_access)

        exp_params = {'volume_uuid': 'voluuid',
                      'read_only': True,
                      'add_allow_ip': '10.0.0.1'}
        self._driver.rpc.call.assert_called_with('exportVolume', exp_params)

    def test_allow_access_nonip(self):
        self._driver.rpc.call = mock.Mock(wraps=fake_rpc_handler)

        self.access = fake_share.fake_access(**{"access_type":
                                                "non_existant_access_type"})

        self.assertRaises(exception.InvalidShareAccess,
                          self._driver._allow_access,
                          self._context, self.share, self.access)

    def test_deny_access(self):
        def rpc_handler(name, *args):
            if name == 'resolveVolumeName':
                return {'volume_uuid': 'voluuid'}
            elif name == 'exportVolume':
                return {'nfs_server_ip': '10.10.1.1',
                        'nfs_export_path': '/voluuid'}

        self._driver.rpc.call = mock.Mock(wraps=rpc_handler)

        self._driver._deny_access(self._context, self.share, self.access)

        self._driver.rpc.call.assert_called_with(
            'exportVolume',
            {'volume_uuid': 'voluuid', 'remove_allow_ip': '10.0.0.1'})

    @mock.patch.object(quobyte.LOG, 'debug')
    def test_deny_access_nonip(self, mock_debug):
        self._driver.rpc.call = mock.Mock(wraps=fake_rpc_handler)
        self.access = fake_share.fake_access(
            access_type="non_existant_access_type")

        self._driver._deny_access(self._context, self.share, self.access)

        mock_debug.assert_called_with(
            'Quobyte driver only supports ip access control. '
            'Ignoring deny access call for %s , %s',
            'fakename', 'fake_project_uuid')

    def test_resolve_volume_name(self):
        self._driver.rpc.call = mock.Mock(
            return_value={'volume_uuid': 'fake_uuid'})

        self._driver._resolve_volume_name('fake_vol_name', 'fake_domain_name')

        exp_params = {'volume_name': 'fake_vol_name',
                      'tenant_domain': 'fake_domain_name'}
        self._driver.rpc.call.assert_called_with(
            'resolveVolumeName', exp_params,
            [jsonrpc.ERROR_ENOENT, jsonrpc.ERROR_ENTITY_NOT_FOUND])

    def test_resolve_volume_name_NOENT(self):
        self._driver.rpc.call = mock.Mock(
            return_value=None)

        self.assertIsNone(
            self._driver._resolve_volume_name('fake_vol_name',
                                              'fake_domain_name'))
        self._driver.rpc.call.assert_called_once_with(
            'resolveVolumeName',
            dict(volume_name='fake_vol_name',
                 tenant_domain='fake_domain_name'),
            [jsonrpc.ERROR_ENOENT, jsonrpc.ERROR_ENTITY_NOT_FOUND]
        )

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
        replfact = 3
        self._driver._get_qb_replication_factor = mock.Mock(
            return_value=replfact)
        self._driver.rpc.call = mock.Mock(
            return_value={'total_physical_capacity': six.text_type(capval),
                          'total_physical_usage': six.text_type(useval)})

        self.assertEqual((39.223160718, 6.960214182),
                         self._driver._get_capacities())

    def test_get_capacities_gb_full(self):
        capval = 1024 * 1024 * 1024 * 3
        useval = 1024 * 1024 * 1024 * 3 + 1
        replfact = 1
        self._driver._get_qb_replication_factor = mock.Mock(
            return_value=replfact)
        self._driver.rpc.call = mock.Mock(
            return_value={'total_physical_capacity': six.text_type(capval),
                          'total_physical_usage': six.text_type(useval)})

        self.assertEqual((3.0, 0), self._driver._get_capacities())

    def test_get_replication(self):
        fakerepl = 42
        self._driver.configuration.quobyte_volume_configuration = 'fakeVolConf'
        self._driver.rpc.call = mock.Mock(
            return_value={'configuration':
                          {'volume_metadata_configuration':
                           {'replication_factor':
                            six.text_type(fakerepl)}}})

        self.assertEqual(fakerepl, self._driver._get_qb_replication_factor())

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

    @mock.patch.object(quobyte.QuobyteShareDriver, "_resolve_volume_name",
                       return_value="fake_volume_uuid")
    def test_resize_share(self, mock_qb_resolv):
        self._driver.rpc.call = mock.Mock(wraps=fake_rpc_handler)
        manila_size = 7
        newsize_bytes = manila_size * units.Gi

        self._driver._resize_share(share=self.share, new_size=manila_size)

        exp_params = {
            "quotas": [{
                "consumer": [{
                    "type": "VOLUME",
                    "identifier": "fake_volume_uuid",
                    "tenant_id": self.share["project_id"]
                }],
                "limits": [{
                    "type": "LOGICAL_DISK_SPACE",
                    "value": newsize_bytes,
                }],
            }]}
        self._driver.rpc.call.assert_has_calls([
            mock.call('setQuota', exp_params)])
        mock_qb_resolv.assert_called_once_with(self.share['name'],
                                               self.share['project_id'])

    @mock.patch.object(quobyte.QuobyteShareDriver,
                       "_resolve_volume_name",
                       return_value="fake_id_3")
    def test_fetch_existing_access(self, mock_qb_resolve_volname):
        self._driver.rpc.call = mock.Mock(wraps=fake_rpc_handler)
        old_access_1 = create_fake_access(access_id="old_1",
                                          access_adr="10.0.0.4")
        old_access_2 = create_fake_access(access_id="old_2",
                                          access_adr="10.0.0.5")

        exist_list = self._driver._fetch_existing_access(context=self._context,
                                                         share=self.share)

        # assert expected result here
        self.assertEqual([old_access_1['access_to'],
                          old_access_2['access_to']],
                         [e.get('access_to') for e in exist_list])
        (mock_qb_resolve_volname.
         assert_called_once_with(self.share['name'],
                                 self.share['project_id']))

    @mock.patch.object(quobyte.QuobyteShareDriver, "_resize_share")
    def test_shrink_share(self, mock_qsd_resize_share):
        self._driver.shrink_share(shrink_share=self.share,
                                  shrink_size=3,
                                  share_server=None)
        mock_qsd_resize_share.assert_called_once_with(share=self.share,
                                                      new_size=3)

    def test_subtract_access_lists(self):
        access_1 = create_fake_access(access_id="new_1",
                                      access_adr="10.0.0.5",
                                      access_type="rw",)
        access_2 = create_fake_access(access_id="old_1",
                                      access_adr="10.0.0.1",
                                      access_type="rw")
        access_3 = create_fake_access(access_id="old_2",
                                      access_adr="10.0.0.3",
                                      access_type="ro")
        access_4 = create_fake_access(access_id="new_2",
                                      access_adr="10.0.0.6",
                                      access_type="rw")
        access_5 = create_fake_access(access_id="old_3",
                                      access_adr="10.0.0.4",
                                      access_type="rw")
        min_list = [access_1, access_2, access_3, access_4]
        sub_list = [access_5, access_3, access_2]

        self.assertEqual([access_1, access_4],
                         self._driver._subtract_access_lists(min_list,
                                                             sub_list))

    def test_subtract_access_lists_level(self):
        access_1 = create_fake_access(access_id="new_1",
                                      access_adr="10.0.0.5",
                                      access_level="rw")
        access_2 = create_fake_access(access_id="old_1",
                                      access_adr="10.0.0.1",
                                      access_level="rw")
        access_3 = create_fake_access(access_id="old_2",
                                      access_adr="10.0.0.3",
                                      access_level="rw")
        access_4 = create_fake_access(access_id="new_2",
                                      access_adr="10.0.0.6",
                                      access_level="rw")
        access_5 = create_fake_access(access_id="old_2_ro",
                                      access_adr="10.0.0.3",
                                      access_level="ro")
        min_list = [access_1, access_2, access_3, access_4]
        sub_list = [access_5, access_2]

        self.assertEqual([access_1, access_3, access_4],
                         self._driver._subtract_access_lists(min_list,
                                                             sub_list))

    def test_subtract_access_lists_type(self):
        access_1 = create_fake_access(access_id="new_1",
                                      access_adr="10.0.0.5",
                                      access_type="ip")
        access_2 = create_fake_access(access_id="old_1",
                                      access_adr="10.0.0.1",
                                      access_type="ip")
        access_3 = create_fake_access(access_id="old_2",
                                      access_adr="10.0.0.3",
                                      access_type="ip")
        access_4 = create_fake_access(access_id="new_2",
                                      access_adr="10.0.0.6",
                                      access_type="ip")
        access_5 = create_fake_access(access_id="old_2_ro",
                                      access_adr="10.0.0.3",
                                      access_type="other")
        min_list = [access_1, access_2, access_3, access_4]
        sub_list = [access_5, access_2]

        self.assertEqual([access_1, access_3, access_4],
                         self._driver._subtract_access_lists(min_list,
                                                             sub_list))

    @mock.patch.object(quobyte.QuobyteShareDriver, "_allow_access")
    @mock.patch.object(quobyte.QuobyteShareDriver, "_deny_access")
    def test_update_access_add_delete(self, qb_deny_mock, qb_allow_mock):
        access_1 = create_fake_access(access_id="new_1",
                                      access_adr="10.0.0.5",
                                      access_level="rw")
        access_2 = create_fake_access(access_id="old_1",
                                      access_adr="10.0.0.1",
                                      access_level="rw")
        access_3 = create_fake_access(access_id="old_2",
                                      access_adr="10.0.0.3",
                                      access_level="rw")

        self._driver.update_access(self._context,
                                   self.share,
                                   access_rules=None,
                                   add_rules=[access_1],
                                   delete_rules=[access_2, access_3])

        qb_allow_mock.assert_called_once_with(self._context,
                                              self.share, access_1)
        deny_calls = [mock.call(self._context, self.share, access_2),
                      mock.call(self._context, self.share, access_3)]
        qb_deny_mock.assert_has_calls(deny_calls)

    @mock.patch.object(quobyte.LOG, "warning")
    def test_update_access_no_rules(self, qb_log_mock):
        self._driver.update_access(context=None, share=None, access_rules=[],
                                   add_rules=[], delete_rules=[])

        qb_log_mock.assert_has_calls([mock.ANY])

    @mock.patch.object(quobyte.QuobyteShareDriver, "_subtract_access_lists")
    @mock.patch.object(quobyte.QuobyteShareDriver, "_fetch_existing_access")
    @mock.patch.object(quobyte.QuobyteShareDriver, "_allow_access")
    def test_update_access_recovery_additionals(self,
                                                qb_allow_mock,
                                                qb_exist_mock,
                                                qb_subtr_mock):
        new_access_1 = create_fake_access(access_id="new_1",
                                          access_adr="10.0.0.2")
        old_access = create_fake_access(access_id="fake_access_id",
                                        access_adr="10.0.0.1")
        new_access_2 = create_fake_access(access_id="new_2",
                                          access_adr="10.0.0.3")
        add_access_rules = [new_access_1,
                            old_access,
                            new_access_2]
        qb_exist_mock.return_value = [old_access]
        qb_subtr_mock.side_effect = [[new_access_1, new_access_2], []]

        self._driver.update_access(self._context, self.share,
                                   access_rules=add_access_rules, add_rules=[],
                                   delete_rules=[])

        assert_calls = [mock.call(self._context, self.share, new_access_1),
                        mock.call(self._context, self.share, new_access_2)]
        qb_allow_mock.assert_has_calls(assert_calls, any_order=True)
        qb_exist_mock.assert_called_once_with(self._context, self.share)

    @mock.patch.object(quobyte.QuobyteShareDriver, "_subtract_access_lists")
    @mock.patch.object(quobyte.QuobyteShareDriver, "_fetch_existing_access")
    @mock.patch.object(quobyte.QuobyteShareDriver, "_deny_access")
    def test_update_access_recovery_superfluous(self,
                                                qb_deny_mock,
                                                qb_exist_mock,
                                                qb_subtr_mock):

        old_access_1 = create_fake_access(access_id="old_1",
                                          access_adr="10.0.0.1")
        missing_access_1 = create_fake_access(access_id="mis_1",
                                              access_adr="10.0.0.2")
        old_access_2 = create_fake_access(access_id="old_2",
                                          access_adr="10.0.0.3")
        qb_exist_mock.side_effect = [[old_access_1, old_access_2]]
        qb_subtr_mock.side_effect = [[], [missing_access_1]]
        old_access_rules = [old_access_1, old_access_2]

        self._driver.update_access(self._context, self.share,
                                   access_rules=old_access_rules, add_rules=[],
                                   delete_rules=[])

        qb_deny_mock.assert_called_once_with(self._context,
                                             self.share,
                                             (missing_access_1))
        qb_exist_mock.assert_called_once_with(self._context, self.share)

    @mock.patch.object(quobyte.QuobyteShareDriver, "_subtract_access_lists")
    @mock.patch.object(quobyte.QuobyteShareDriver, "_fetch_existing_access")
    @mock.patch.object(quobyte.QuobyteShareDriver, "_deny_access")
    @mock.patch.object(quobyte.QuobyteShareDriver, "_allow_access")
    def test_update_access_recovery_add_superfluous(self,
                                                    qb_allow_mock,
                                                    qb_deny_mock,
                                                    qb_exist_mock,
                                                    qb_subtr_mock):
        new_access_1 = create_fake_access(access_id="new_1",
                                          access_adr="10.0.0.5")
        old_access_1 = create_fake_access(access_id="old_1",
                                          access_adr="10.0.0.1")
        old_access_2 = create_fake_access(access_id="old_2",
                                          access_adr="10.0.0.3")
        old_access_3 = create_fake_access(access_id="old_3",
                                          access_adr="10.0.0.4")
        miss_access_1 = create_fake_access(access_id="old_3",
                                           access_adr="10.0.0.4")
        new_access_2 = create_fake_access(access_id="new_2",
                                          access_adr="10.0.0.3",
                                          access_level="ro")
        new_access_rules = [new_access_1, old_access_1, old_access_2,
                            old_access_3, new_access_2]
        qb_exist_mock.return_value = [old_access_1, old_access_2,
                                      old_access_3, miss_access_1]
        qb_subtr_mock.side_effect = [[new_access_1, new_access_2],
                                     [miss_access_1, old_access_2]]

        self._driver.update_access(self._context, self.share,
                                   new_access_rules, add_rules=[],
                                   delete_rules=[])

        a_calls = [mock.call(self._context, self.share, new_access_1),
                   mock.call(self._context, self.share, new_access_2)]
        qb_allow_mock.assert_has_calls(a_calls)
        b_calls = [mock.call(self._context, self.share, miss_access_1),
                   mock.call(self._context, self.share, old_access_2)]
        qb_deny_mock.assert_has_calls(b_calls)
        qb_exist_mock.assert_called_once_with(self._context, self.share)
