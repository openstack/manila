# Copyright (c) 2014 Red Hat, Inc.
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

import copy
import errno
import os

import mock
from oslo_config import cfg

from manila import exception
from manila.share import configuration as config
from manila.share.drivers import ganesha
from manila import test
from manila.tests import fake_share

CONF = cfg.CONF


fake_basepath = '/fakepath'

fake_export_name = 'fakename--fakeaccid'

fake_output_template = {
    'EXPORT': {
        'Export_Id': 101,
        'Path': '/fakepath/fakename',
        'Pseudo': '/fakepath/fakename--fakeaccid',
        'Tag': 'fakeaccid',
        'CLIENT': {
            'Clients': '10.0.0.1'
        },
        'FSAL': 'fakefsal'
    }
}


class GaneshaNASHelperTestCase(test.TestCase):
    """Tests GaneshaNASHElper."""

    def setUp(self):
        super(GaneshaNASHelperTestCase, self).setUp()

        CONF.set_default('ganesha_config_path', '/fakedir0/fakeconfig')
        CONF.set_default('ganesha_db_path', '/fakedir1/fake.db')
        CONF.set_default('ganesha_export_dir', '/fakedir0/export.d')
        CONF.set_default('ganesha_export_template_dir',
                         '/fakedir2/faketempl.d')
        CONF.set_default('ganesha_service_name', 'ganesha.fakeservice')
        self._execute = mock.Mock(return_value=('', ''))
        self.fake_conf = config.Configuration(None)
        self.fake_conf_dir_path = '/fakedir0/exports.d'
        self._helper = ganesha.GaneshaNASHelper(
            self._execute, self.fake_conf, tag='faketag')
        self._helper.ganesha = mock.Mock()
        self._helper.export_template = {'key': 'value'}
        self.share = fake_share.fake_share()
        self.access = fake_share.fake_access()

    def test_load_conf_dir(self):
        fake_template1 = {'key': 'value1'}
        fake_template2 = {'key': 'value2'}
        fake_ls_dir = ['fakefile0.conf', 'fakefile1.json', 'fakefile2.txt']
        mock_ganesha_utils_patch = mock.Mock()

        def fake_patch_run(tmpl1, tmpl2):
            mock_ganesha_utils_patch(
                copy.deepcopy(tmpl1), copy.deepcopy(tmpl2))
            tmpl1.update(tmpl2)

        self.mock_object(ganesha.os, 'listdir',
                         mock.Mock(return_value=fake_ls_dir))
        self.mock_object(ganesha.LOG, 'info')
        self.mock_object(ganesha.ganesha_manager, 'parseconf',
                         mock.Mock(side_effect=[fake_template1,
                                                fake_template2]))
        self.mock_object(ganesha.ganesha_utils, 'patch',
                         mock.Mock(side_effect=fake_patch_run))
        with mock.patch('six.moves.builtins.open',
                        mock.mock_open()) as mockopen:
            mockopen().read.side_effect = ['fakeconf0', 'fakeconf1']
            ret = self._helper._load_conf_dir(self.fake_conf_dir_path)
            ganesha.os.listdir.assert_called_once_with(
                self.fake_conf_dir_path)
            ganesha.LOG.info.assert_called_once_with(
                mock.ANY, self.fake_conf_dir_path)
            mockopen.assert_has_calls([
                mock.call('/fakedir0/exports.d/fakefile0.conf'),
                mock.call('/fakedir0/exports.d/fakefile1.json')],
                any_order=True)
            ganesha.ganesha_manager.parseconf.assert_has_calls([
                mock.call('fakeconf0'), mock.call('fakeconf1')])
            mock_ganesha_utils_patch.assert_has_calls([
                mock.call({}, fake_template1),
                mock.call(fake_template1, fake_template2)])
            self.assertEqual(fake_template2, ret)

    def test_load_conf_dir_no_conf_dir_must_exist_false(self):
        self.mock_object(
            ganesha.os, 'listdir',
            mock.Mock(side_effect=OSError(errno.ENOENT,
                                          os.strerror(errno.ENOENT))))
        self.mock_object(ganesha.LOG, 'info')
        self.mock_object(ganesha.ganesha_manager, 'parseconf')
        self.mock_object(ganesha.ganesha_utils, 'patch')
        with mock.patch('six.moves.builtins.open',
                        mock.mock_open(read_data='fakeconf')) as mockopen:
            ret = self._helper._load_conf_dir(self.fake_conf_dir_path,
                                              must_exist=False)
            ganesha.os.listdir.assert_called_once_with(
                self.fake_conf_dir_path)
            ganesha.LOG.info.assert_called_once_with(
                mock.ANY, self.fake_conf_dir_path)
            self.assertFalse(mockopen.called)
            self.assertFalse(ganesha.ganesha_manager.parseconf.called)
            self.assertFalse(ganesha.ganesha_utils.patch.called)
            self.assertEqual({}, ret)

    def test_load_conf_dir_error_no_conf_dir_must_exist_true(self):
        self.mock_object(
            ganesha.os, 'listdir',
            mock.Mock(side_effect=OSError(errno.ENOENT,
                                          os.strerror(errno.ENOENT))))
        self.assertRaises(OSError, self._helper._load_conf_dir,
                          self.fake_conf_dir_path)
        ganesha.os.listdir.assert_called_once_with(self.fake_conf_dir_path)

    def test_load_conf_dir_error_conf_dir_present_must_exist_false(self):
        self.mock_object(
            ganesha.os, 'listdir',
            mock.Mock(side_effect=OSError(errno.EACCES,
                                          os.strerror(errno.EACCES))))
        self.assertRaises(OSError, self._helper._load_conf_dir,
                          self.fake_conf_dir_path, must_exist=False)
        ganesha.os.listdir.assert_called_once_with(self.fake_conf_dir_path)

    def test_load_conf_dir_error(self):
        self.mock_object(
            ganesha.os, 'listdir',
            mock.Mock(side_effect=RuntimeError('fake error')))
        self.assertRaises(RuntimeError, self._helper._load_conf_dir,
                          self.fake_conf_dir_path)
        ganesha.os.listdir.assert_called_once_with(self.fake_conf_dir_path)

    def test_init_helper(self):
        mock_template = mock.Mock()
        mock_ganesha_manager = mock.Mock()
        self.mock_object(ganesha.ganesha_manager, 'GaneshaManager',
                         mock.Mock(return_value=mock_ganesha_manager))
        self.mock_object(self._helper, '_load_conf_dir',
                         mock.Mock(return_value=mock_template))
        self.mock_object(self._helper, '_default_config_hook')
        ret = self._helper.init_helper()
        ganesha.ganesha_manager.GaneshaManager.assert_called_once_with(
            self._execute, 'faketag',
            ganesha_config_path='/fakedir0/fakeconfig',
            ganesha_export_dir='/fakedir0/export.d',
            ganesha_db_path='/fakedir1/fake.db',
            ganesha_service_name='ganesha.fakeservice')
        self._helper._load_conf_dir.assert_called_once_with(
            '/fakedir2/faketempl.d', must_exist=False)
        self.assertFalse(self._helper._default_config_hook.called)
        self.assertEqual(mock_ganesha_manager, self._helper.ganesha)
        self.assertEqual(mock_template, self._helper.export_template)
        self.assertIsNone(ret)

    def test_init_helper_conf_dir_empty(self):
        mock_template = mock.Mock()
        mock_ganesha_manager = mock.Mock()
        self.mock_object(ganesha.ganesha_manager, 'GaneshaManager',
                         mock.Mock(return_value=mock_ganesha_manager))
        self.mock_object(self._helper, '_load_conf_dir',
                         mock.Mock(return_value={}))
        self.mock_object(self._helper, '_default_config_hook',
                         mock.Mock(return_value=mock_template))
        ret = self._helper.init_helper()
        ganesha.ganesha_manager.GaneshaManager.assert_called_once_with(
            self._execute, 'faketag',
            ganesha_config_path='/fakedir0/fakeconfig',
            ganesha_export_dir='/fakedir0/export.d',
            ganesha_db_path='/fakedir1/fake.db',
            ganesha_service_name='ganesha.fakeservice')
        self._helper._load_conf_dir.assert_called_once_with(
            '/fakedir2/faketempl.d', must_exist=False)
        self._helper._default_config_hook.assert_called_once_with()
        self.assertEqual(mock_ganesha_manager, self._helper.ganesha)
        self.assertEqual(mock_template, self._helper.export_template)
        self.assertIsNone(ret)

    def test_default_config_hook(self):
        fake_template = {'key': 'value'}
        self.mock_object(ganesha.ganesha_utils, 'path_from',
                         mock.Mock(return_value='/fakedir3/fakeconfdir'))
        self.mock_object(self._helper, '_load_conf_dir',
                         mock.Mock(return_value=fake_template))
        ret = self._helper._default_config_hook()
        ganesha.ganesha_utils.path_from.assert_called_once_with(
            ganesha.__file__, 'conf')
        self._helper._load_conf_dir.assert_called_once_with(
            '/fakedir3/fakeconfdir')
        self.assertEqual(fake_template, ret)

    def test_fsal_hook(self):
        ret = self._helper._fsal_hook('/fakepath', self.share, self.access)
        self.assertEqual({}, ret)

    def test_allow_access(self):
        mock_ganesha_utils_patch = mock.Mock()

        def fake_patch_run(tmpl1, tmpl2, tmpl3):
            mock_ganesha_utils_patch(copy.deepcopy(tmpl1), tmpl2, tmpl3)
            tmpl1.update(tmpl3)

        self.mock_object(self._helper.ganesha, 'get_export_id',
                         mock.Mock(return_value=101))
        self.mock_object(self._helper, '_fsal_hook',
                         mock.Mock(return_value='fakefsal'))
        self.mock_object(ganesha.ganesha_utils, 'patch',
                         mock.Mock(side_effect=fake_patch_run))
        ret = self._helper.allow_access(fake_basepath, self.share,
                                        self.access)
        self._helper.ganesha.get_export_id.assert_called_once_with()
        self._helper._fsal_hook.assert_called_once_with(
            fake_basepath, self.share, self.access)
        mock_ganesha_utils_patch.assert_called_once_with(
            {}, self._helper.export_template, fake_output_template)
        self._helper._fsal_hook.assert_called_once_with(
            fake_basepath, self.share, self.access)
        self._helper.ganesha.add_export.assert_called_once_with(
            fake_export_name, fake_output_template)
        self.assertIsNone(ret)

    def test_allow_access_error_invalid_share(self):
        access = fake_share.fake_access(access_type='notip')
        self.assertRaises(exception.InvalidShareAccess,
                          self._helper.allow_access, '/fakepath',
                          self.share, access)

    def test_deny_access(self):
        ret = self._helper.deny_access('/fakepath', self.share, self.access)
        self._helper.ganesha.remove_export.assert_called_once_with(
            'fakename--fakeaccid')
        self.assertIsNone(ret)
