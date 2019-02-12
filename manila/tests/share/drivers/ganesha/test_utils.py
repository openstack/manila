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

import os

import ddt
import mock

from manila import exception
from manila.share.drivers.ganesha import utils as ganesha_utils
from manila import test
from manila.tests import fake_share


patch_test_dict1 = {'a': 1, 'b': {'c': 2}, 'd': 3, 'e': 4}
patch_test_dict2 = {'a': 11, 'b': {'f': 5}, 'd': {'g': 6}}
patch_test_dict3 = {'b': {'c': 22, 'h': {'i': 7}}, 'e': None}
patch_test_dict_result = {
    'a': 11,
    'b': {'c': 22, 'f': 5, 'h': {'i': 7}},
    'd': {'g': 6},
    'e': None,
}

walk_test_dict = {'a': {'b': {'c': {'d': {'e': 'f'}}}}}
walk_test_list = [('e', 'f')]


def fake_access(kwargs):
    fake_access_rule = fake_share.fake_access(**kwargs)
    fake_access_rule.to_dict = lambda: fake_access_rule.values
    return fake_access_rule


@ddt.ddt
class GaneshaUtilsTests(test.TestCase):
    """Tests Ganesha utility functions."""

    def test_patch(self):
        ret = ganesha_utils.patch(patch_test_dict1, patch_test_dict2,
                                  patch_test_dict3)
        self.assertEqual(patch_test_dict_result, ret)

    def test_walk(self):
        ret = [elem for elem in ganesha_utils.walk(walk_test_dict)]
        self.assertEqual(walk_test_list, ret)

    def test_path_from(self):
        self.mock_object(os.path, 'abspath',
                         lambda path: os.path.join('/foo/bar', path))
        ret = ganesha_utils.path_from('baz.py', '../quux', 'tic/tac/toe')
        self.assertEqual('/foo/quux/tic/tac/toe', os.path.normpath(ret))

    @ddt.data({'rule': {'access_type': 'ip',
                        'access_level': 'ro',
                        'access_to': '10.10.10.12'},
               'kwargs': {'abort': True}},
              {'rule': {'access_type': 'cert',
                        'access_level': 'ro',
                        'access_to': 'some-CN'},
               'kwargs': {'abort': False}},
              {'rule': {'access_type': 'ip',
                        'access_level': 'rw',
                        'access_to': '10.10.10.12'},
               'kwargs': {}})
    @ddt.unpack
    def test_get_valid_access_rules(self, rule, kwargs):
        supported = ['ip', 'ro']

        ret = ganesha_utils.validate_access_rule(
            *([[a] for a in supported] + [fake_access(rule)]), **kwargs)

        self.assertEqual(
            [rule['access_' + k] for k in ['type', 'level']] == supported, ret)

    @ddt.data({'rule': {'access_type': 'cert',
                        'access_level': 'ro',
                        'access_to': 'some-CN'},
               'trouble': exception.InvalidShareAccess},
              {'rule': {'access_type': 'ip',
                        'access_level': 'rw',
                        'access_to': '10.10.10.12'},
               'trouble': exception.InvalidShareAccessLevel})
    @ddt.unpack
    def test_get_valid_access_rules_fail(self, rule, trouble):
        self.assertRaises(trouble, ganesha_utils.validate_access_rule,
                          ['ip'], ['ro'], fake_access(rule), abort=True)

    @ddt.data({'rule': {'access_type': 'ip',
                        'access_level': 'rw',
                        'access_to': '10.10.10.12'},
               'result': {'access_type': 'ip',
                          'access_level': 'rw',
                          'access_to': '10.10.10.12'},
               },
              {'rule': {'access_type': 'ip',
                        'access_level': 'rw',
                        'access_to': '0.0.0.0/0'},
               'result': {'access_type': 'ip',
                          'access_level': 'rw',
                          'access_to': '0.0.0.0'},
               },
              )
    @ddt.unpack
    def test_fixup_access_rules(self, rule, result):

        self.assertEqual(result, ganesha_utils.fixup_access_rule(rule))


@ddt.ddt
class SSHExecutorTestCase(test.TestCase):
    """Tests SSHExecutor."""

    @ddt.data({'run_as_root': True, 'expected_prefix': 'sudo '},
              {'run_as_root': False, 'expected_prefix': ''})
    @ddt.unpack
    def test_call_ssh_exec_object_with_run_as_root(
            self, run_as_root, expected_prefix):
        with mock.patch.object(ganesha_utils.utils, 'SSHPool'):
            self.execute = ganesha_utils.SSHExecutor()
        fake_ssh_object = mock.Mock()
        self.mock_object(self.execute.pool, 'get',
                         mock.Mock(return_value=fake_ssh_object))
        self.mock_object(ganesha_utils.processutils, 'ssh_execute',
                         mock.Mock(return_value=('', '')))
        ret = self.execute('ls', run_as_root=run_as_root)
        self.assertEqual(('', ''), ret)
        self.execute.pool.get.assert_called_once_with()
        ganesha_utils.processutils.ssh_execute.assert_called_once_with(
            fake_ssh_object, expected_prefix + 'ls')
