# Copyright (c) 2016 Hitachi Data Systems, Inc.
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

import ddt
import mock
from oslo_config import cfg

from manila import exception
import manila.share.configuration
import manila.share.driver
from manila.share.drivers.hitachi.hsp import driver
from manila.share.drivers.hitachi.hsp import rest
from manila import test
from manila.tests import fake_share
from manila.tests.share.drivers.hitachi.hsp import fakes

from manila.common import constants
from oslo_utils import units

CONF = cfg.CONF


@ddt.ddt
class HitachiHSPTestCase(test.TestCase):
    def setUp(self):
        super(HitachiHSPTestCase, self).setUp()
        CONF.set_default('driver_handles_share_servers', False)
        CONF.hitachi_hsp_host = '172.24.47.190'
        CONF.hitachi_hsp_username = 'hsp_user'
        CONF.hitachi_hsp_password = 'hsp_password'
        CONF.hitachi_hsp_job_timeout = 300

        self.fake_el = [{
            "path": CONF.hitachi_hsp_host + ":/fakeinstanceid",
            "metadata": {},
            "is_admin_only": False,
        }]
        self.fake_share = fake_share.fake_share(share_proto='nfs')
        self.fake_share_instance = fake_share.fake_share_instance(
            base_share=self.fake_share, export_locations=self.fake_el)

        self.fake_conf = manila.share.configuration.Configuration(None)
        self.fake_private_storage = mock.Mock()
        self.mock_object(rest.HSPRestBackend, "get_cluster",
                         mock.Mock(return_value=fakes.hsp_cluster))
        self._driver = driver.HitachiHSPDriver(
            configuration=self.fake_conf,
            private_storage=self.fake_private_storage)
        self._driver.backend_name = "HSP"
        self.mock_log = self.mock_object(driver, 'LOG')

    @ddt.data(None, exception.HSPBackendException(
        message="Duplicate NFS access rule exists."))
    def test_update_access_add(self, add_rule):
        access = {
            'access_type': 'ip',
            'access_to': '172.24.10.10',
            'access_level': 'rw',
        }

        access_list = [access]

        self.mock_object(rest.HSPRestBackend, "get_file_system",
                         mock.Mock(return_value=fakes.file_system))
        self.mock_object(rest.HSPRestBackend, "get_share",
                         mock.Mock(return_value=fakes.share))
        self.mock_object(rest.HSPRestBackend, "add_access_rule", mock.Mock(
            side_effect=add_rule))

        self._driver.update_access('context', self.fake_share_instance, [],
                                   access_list, [])

        self.assertTrue(self.mock_log.debug.called)

        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])
        rest.HSPRestBackend.get_share.assert_called_once_with(
            fakes.file_system['id'])
        rest.HSPRestBackend.add_access_rule.assert_called_once_with(
            fakes.share['id'], access['access_to'],
            (access['access_level'] == constants.ACCESS_LEVEL_RW))

    def test_update_access_add_exception(self):
        access = {
            'access_type': 'ip',
            'access_to': '172.24.10.10',
            'access_level': 'rw',
        }

        access_list = [access]

        self.mock_object(rest.HSPRestBackend, "get_file_system",
                         mock.Mock(return_value=fakes.file_system))
        self.mock_object(rest.HSPRestBackend, "get_share",
                         mock.Mock(return_value=fakes.share))
        self.mock_object(rest.HSPRestBackend, "add_access_rule",
                         mock.Mock(side_effect=exception.HSPBackendException(
                             message="HSP Backend Exception: error adding "
                                     "rule.")))

        self.assertRaises(exception.HSPBackendException,
                          self._driver.update_access, 'context',
                          self.fake_share_instance, [], access_list, [])

        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])
        rest.HSPRestBackend.get_share.assert_called_once_with(
            fakes.file_system['id'])
        rest.HSPRestBackend.add_access_rule.assert_called_once_with(
            fakes.share['id'], access['access_to'],
            (access['access_level'] == constants.ACCESS_LEVEL_RW))

    def test_update_access_recovery(self):
        access1 = {
            'access_type': 'ip',
            'access_to': '172.24.10.10',
            'access_level': 'rw',
        }
        access2 = {
            'access_type': 'ip',
            'access_to': '188.100.20.10',
            'access_level': 'ro',
        }

        access_list = [access1, access2]

        self.mock_object(rest.HSPRestBackend, "get_file_system",
                         mock.Mock(return_value=fakes.file_system))
        self.mock_object(rest.HSPRestBackend, "get_share",
                         mock.Mock(return_value=fakes.share))
        self.mock_object(rest.HSPRestBackend, "get_access_rules",
                         mock.Mock(side_effect=[fakes.hsp_rules, []]))
        self.mock_object(rest.HSPRestBackend, "delete_access_rule")
        self.mock_object(rest.HSPRestBackend, "add_access_rule")

        self._driver.update_access('context', self.fake_share_instance,
                                   access_list, [], [])

        self.assertTrue(self.mock_log.debug.called)

        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])
        rest.HSPRestBackend.get_share.assert_called_once_with(
            fakes.file_system['id'])
        rest.HSPRestBackend.get_access_rules.assert_has_calls([
            mock.call(fakes.share['id'])])
        rest.HSPRestBackend.delete_access_rule.assert_called_once_with(
            fakes.share['id'],
            fakes.share['id'] + fakes.hsp_rules[0]['host-specification'])
        rest.HSPRestBackend.add_access_rule.assert_has_calls([
            mock.call(fakes.share['id'], access1['access_to'], True),
            mock.call(fakes.share['id'], access2['access_to'], False)
        ], any_order=True)

    @ddt.data(None, exception.HSPBackendException(
        message="No matching access rule found."))
    def test_update_access_delete(self, delete_rule):
        access1 = {
            'access_type': 'ip',
            'access_to': '172.24.44.200',
            'access_level': 'rw',
        }
        access2 = {
            'access_type': 'something',
            'access_to': '188.100.20.10',
            'access_level': 'ro',
        }

        delete_rules = [access1, access2]

        self.mock_object(rest.HSPRestBackend, "get_file_system",
                         mock.Mock(return_value=fakes.file_system))
        self.mock_object(rest.HSPRestBackend, "get_share",
                         mock.Mock(return_value=fakes.share))
        self.mock_object(rest.HSPRestBackend, "delete_access_rule",
                         mock.Mock(side_effect=delete_rule))
        self.mock_object(rest.HSPRestBackend, "get_access_rules",
                         mock.Mock(return_value=fakes.hsp_rules))

        self._driver.update_access('context', self.fake_share_instance, [], [],
                                   delete_rules)

        self.assertTrue(self.mock_log.debug.called)

        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])
        rest.HSPRestBackend.get_share.assert_called_once_with(
            fakes.file_system['id'])
        rest.HSPRestBackend.delete_access_rule.assert_called_once_with(
            fakes.share['id'], fakes.hsp_rules[0]['name'])
        rest.HSPRestBackend.get_access_rules.assert_called_once_with(
            fakes.share['id'])

    def test_update_access_delete_exception(self):
        access1 = {
            'access_type': 'ip',
            'access_to': '172.24.10.10',
            'access_level': 'rw',
        }
        access2 = {
            'access_type': 'something',
            'access_to': '188.100.20.10',
            'access_level': 'ro',
        }

        delete_rules = [access1, access2]

        self.mock_object(rest.HSPRestBackend, "get_file_system",
                         mock.Mock(return_value=fakes.file_system))
        self.mock_object(rest.HSPRestBackend, "get_share",
                         mock.Mock(return_value=fakes.share))
        self.mock_object(rest.HSPRestBackend, "delete_access_rule",
                         mock.Mock(side_effect=exception.HSPBackendException(
                             message="HSP Backend Exception: error deleting "
                                     "rule.")))
        self.mock_object(rest.HSPRestBackend, 'get_access_rules',
                         mock.Mock(return_value=[]))

        self.assertRaises(exception.HSPBackendException,
                          self._driver.update_access, 'context',
                          self.fake_share_instance, [], [], delete_rules)

        self.assertTrue(self.mock_log.debug.called)

        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])
        rest.HSPRestBackend.get_share.assert_called_once_with(
            fakes.file_system['id'])
        rest.HSPRestBackend.delete_access_rule.assert_called_once_with(
            fakes.share['id'], fakes.share['id'] + access1['access_to'])
        rest.HSPRestBackend.get_access_rules.assert_called_once_with(
            fakes.share['id'])

    @ddt.data(True, False)
    def test_update_access_ip_exception(self, is_recovery):
        access = {
            'access_type': 'something',
            'access_to': '172.24.10.10',
            'access_level': 'rw',
        }

        access_list = [access]

        self.mock_object(rest.HSPRestBackend, "get_file_system",
                         mock.Mock(return_value=fakes.file_system))
        self.mock_object(rest.HSPRestBackend, "get_share",
                         mock.Mock(return_value=fakes.share))
        self.mock_object(rest.HSPRestBackend, "get_access_rules",
                         mock.Mock(return_value=fakes.hsp_rules))

        if is_recovery:
            access_args = [access_list, [], []]
        else:
            access_args = [[], access_list, []]

        self.assertRaises(exception.InvalidShareAccess,
                          self._driver.update_access, 'context',
                          self.fake_share_instance, *access_args)

        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])
        rest.HSPRestBackend.get_share.assert_called_once_with(
            fakes.file_system['id'])

        if is_recovery:
            rest.HSPRestBackend.get_access_rules.assert_called_once_with(
                fakes.share['id'])

    def test_update_access_not_found_exception(self):
        access_list = []

        self.mock_object(rest.HSPRestBackend, "get_file_system", mock.Mock(
            side_effect=exception.HSPItemNotFoundException(msg='fake')))

        self.assertRaises(exception.ShareResourceNotFound,
                          self._driver.update_access, 'context',
                          self.fake_share_instance, access_list, [], [])

        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])

    def test_create_share(self):
        self.mock_object(rest.HSPRestBackend, "add_file_system", mock.Mock())
        self.mock_object(rest.HSPRestBackend, "get_file_system",
                         mock.Mock(return_value=fakes.file_system))
        self.mock_object(rest.HSPRestBackend, "add_share", mock.Mock())

        result = self._driver.create_share('context', self.fake_share_instance)

        self.assertEqual(self.fake_el, result)
        self.assertTrue(self.mock_log.debug.called)

        rest.HSPRestBackend.add_file_system.assert_called_once_with(
            self.fake_share_instance['id'],
            self.fake_share_instance['size'] * units.Gi)
        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])
        rest.HSPRestBackend.add_share.assert_called_once_with(
            self.fake_share_instance['id'], fakes.file_system['id'])

    def test_create_share_export_error(self):
        self.mock_object(rest.HSPRestBackend, "add_file_system", mock.Mock())
        self.mock_object(rest.HSPRestBackend, "get_file_system",
                         mock.Mock(return_value=fakes.file_system))
        self.mock_object(rest.HSPRestBackend, "add_share", mock.Mock(
            side_effect=exception.HSPBackendException(msg='fake')))
        self.mock_object(rest.HSPRestBackend, "delete_file_system",
                         mock.Mock())

        self.assertRaises(exception.HSPBackendException,
                          self._driver.create_share, 'context',
                          self.fake_share_instance)
        self.assertTrue(self.mock_log.debug.called)
        self.assertTrue(self.mock_log.exception.called)

        rest.HSPRestBackend.add_file_system.assert_called_once_with(
            self.fake_share_instance['id'],
            self.fake_share_instance['size'] * units.Gi)
        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])
        rest.HSPRestBackend.add_share.assert_called_once_with(
            self.fake_share_instance['id'], fakes.file_system['id'])
        rest.HSPRestBackend.delete_file_system.assert_called_once_with(
            fakes.file_system['id'])

    def test_create_share_invalid_share_protocol(self):
        self.assertRaises(exception.InvalidShare,
                          self._driver.create_share, 'context',
                          fakes.invalid_share)

    @ddt.data(None, exception.HSPBackendException(
        message="No matching access rule found."))
    def test_delete_share(self, delete_rule):
        self.mock_object(rest.HSPRestBackend, "get_file_system",
                         mock.Mock(return_value=fakes.file_system))
        self.mock_object(rest.HSPRestBackend, "get_share",
                         mock.Mock(return_value=fakes.share))
        self.mock_object(rest.HSPRestBackend, "delete_share")
        self.mock_object(rest.HSPRestBackend, "delete_file_system")
        self.mock_object(rest.HSPRestBackend, "get_access_rules",
                         mock.Mock(return_value=[fakes.hsp_rules[0]]))
        self.mock_object(rest.HSPRestBackend, "delete_access_rule", mock.Mock(
            side_effect=[exception.HSPBackendException(
                message="No matching access rule found."), delete_rule]))

        self._driver.delete_share('context', self.fake_share_instance)

        self.assertTrue(self.mock_log.debug.called)

        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])
        rest.HSPRestBackend.get_share.assert_called_once_with(
            fakes.file_system['id'])
        rest.HSPRestBackend.delete_share.assert_called_once_with(
            fakes.share['id'])
        rest.HSPRestBackend.delete_file_system.assert_called_once_with(
            fakes.file_system['id'])
        rest.HSPRestBackend.get_access_rules.assert_called_once_with(
            fakes.share['id'])
        rest.HSPRestBackend.delete_access_rule.assert_called_once_with(
            fakes.share['id'], fakes.hsp_rules[0]['name'])

    def test_delete_share_rule_exception(self):
        self.mock_object(rest.HSPRestBackend, "get_file_system",
                         mock.Mock(return_value=fakes.file_system))
        self.mock_object(rest.HSPRestBackend, "get_share",
                         mock.Mock(return_value=fakes.share))
        self.mock_object(rest.HSPRestBackend, "get_access_rules",
                         mock.Mock(return_value=[fakes.hsp_rules[0]]))
        self.mock_object(rest.HSPRestBackend, "delete_access_rule",
                         mock.Mock(side_effect=exception.HSPBackendException(
                             message="Internal Server Error.")))

        self.assertRaises(exception.HSPBackendException,
                          self._driver.delete_share, 'context',
                          self.fake_share_instance)

        self.assertTrue(self.mock_log.debug.called)

        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])
        rest.HSPRestBackend.get_share.assert_called_once_with(
            fakes.file_system['id'])
        rest.HSPRestBackend.get_access_rules.assert_called_once_with(
            fakes.share['id'])
        rest.HSPRestBackend.delete_access_rule.assert_called_once_with(
            fakes.share['id'], fakes.hsp_rules[0]['name'])

    def test_delete_share_already_deleted(self):
        self.mock_object(rest.HSPRestBackend, "get_file_system", mock.Mock(
            side_effect=exception.HSPItemNotFoundException(msg='fake')))

        self.mock_object(driver.LOG, "info")

        self._driver.delete_share('context', self.fake_share_instance)

        self.assertTrue(self.mock_log.info.called)

        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])

    def test_extend_share(self):
        new_size = 2

        self.mock_object(rest.HSPRestBackend, "get_file_system",
                         mock.Mock(return_value=fakes.file_system))
        self.mock_object(rest.HSPRestBackend, "resize_file_system",
                         mock.Mock())

        self._driver.extend_share(self.fake_share_instance, new_size)

        self.assertTrue(self.mock_log.info.called)

        rest.HSPRestBackend.get_cluster.assert_called_once_with()
        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])
        rest.HSPRestBackend.resize_file_system.assert_called_once_with(
            fakes.file_system['id'], new_size * units.Gi)

    def test_extend_share_with_no_available_space_in_fs(self):
        new_size = 150

        self.assertRaises(exception.HSPBackendException,
                          self._driver.extend_share, self.fake_share_instance,
                          new_size)

        rest.HSPRestBackend.get_cluster.assert_called_once_with()

    def test_shrink_share(self):
        new_size = 70

        self.mock_object(rest.HSPRestBackend, "get_file_system",
                         mock.Mock(return_value=fakes.file_system))
        self.mock_object(rest.HSPRestBackend, "resize_file_system",
                         mock.Mock())

        self._driver.shrink_share(self.fake_share_instance, new_size)

        self.assertTrue(self.mock_log.info.called)

        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])
        rest.HSPRestBackend.resize_file_system.assert_called_once_with(
            fakes.file_system['id'], new_size * units.Gi)

    def test_shrink_share_new_size_lower_than_usage(self):
        new_size = 20

        self.mock_object(rest.HSPRestBackend, "get_file_system",
                         mock.Mock(return_value=fakes.file_system))

        self.assertRaises(exception.ShareShrinkingPossibleDataLoss,
                          self._driver.shrink_share, self.fake_share_instance,
                          new_size)

        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])

    def test_manage_existing(self):
        self.mock_object(self.fake_private_storage, "update")
        self.mock_object(rest.HSPRestBackend, "get_share",
                         mock.Mock(return_value=fakes.share))
        self.mock_object(rest.HSPRestBackend, "rename_file_system",
                         mock.Mock())
        self.mock_object(rest.HSPRestBackend, "get_file_system",
                         mock.Mock(return_value=fakes.file_system))

        result = self._driver.manage_existing(self.fake_share_instance,
                                              'option')

        expected = {
            'size': fakes.file_system['properties']['quota'] / units.Gi,
            'export_locations': self.fake_el,
        }

        self.assertTrue(self.mock_log.info.called)
        self.assertEqual(expected, result)

        rest.HSPRestBackend.get_share.assert_called_once_with(
            name=self.fake_share_instance['id'])
        rest.HSPRestBackend.rename_file_system.assert_called_once_with(
            fakes.file_system['id'], self.fake_share_instance['id'])
        rest.HSPRestBackend.get_file_system.assert_called_once_with(
            self.fake_share_instance['id'])

    def test_manage_existing_wrong_share_id(self):
        self.mock_object(rest.HSPRestBackend, "get_share", mock.Mock(
            side_effect=exception.HSPItemNotFoundException(msg='fake')))

        self.assertRaises(exception.ManageInvalidShare,
                          self._driver.manage_existing,
                          self.fake_share_instance,
                          'option')

        rest.HSPRestBackend.get_share.assert_called_once_with(
            name=self.fake_share_instance['id'])

    def test_unmanage(self):
        self.mock_object(self.fake_private_storage, "get",
                         mock.Mock(
                             return_value='original_name'))
        self.mock_object(self.fake_private_storage, "delete")

        self._driver.unmanage(self.fake_share_instance)

        self.assertTrue(self.mock_log.info.called)

    def test__update_share_stats(self):
        mock__update_share_stats = self.mock_object(
            manila.share.driver.ShareDriver, '_update_share_stats')
        self.mock_object(self.fake_private_storage, 'get', mock.Mock(
            return_value={'provisioned': 0}
        ))

        self._driver._update_share_stats()

        rest.HSPRestBackend.get_cluster.assert_called_once_with()
        mock__update_share_stats.assert_called_once_with(fakes.stats_data)
        self.assertTrue(self.mock_log.info.called)

    def test_get_default_filter_function(self):
        expected = "share.size >= 128"

        actual = self._driver.get_default_filter_function()

        self.assertEqual(expected, actual)
