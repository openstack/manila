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

from manila.share.drivers.ganesha import utils
from manila import test


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


class GaneshaUtilsTests(test.TestCase):
    """Tests Ganesha utility functions."""

    def test_patch(self):
        ret = utils.patch(patch_test_dict1, patch_test_dict2, patch_test_dict3)
        self.assertEqual(patch_test_dict_result, ret)

    def test_walk(self):
        ret = [elem for elem in utils.walk(walk_test_dict)]
        self.assertEqual(walk_test_list, ret)

    def test_path_from(self):
        self.mock_object(os.path, 'abspath',
                         lambda path: os.path.join('/foo/bar', path))
        ret = utils.path_from('baz.py', '../quux', 'tic/tac/toe')
        self.assertEqual('/foo/quux/tic/tac/toe', os.path.normpath(ret))
