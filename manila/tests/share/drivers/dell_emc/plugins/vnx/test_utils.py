# Copyright (c) 2016 EMC Corporation.
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

from manila.share.drivers.dell_emc.plugins.vnx import utils
from manila import test


@ddt.ddt
class VNXUtilsTestCase(test.TestCase):

    @ddt.data({'full': ['cge-1-0', 'cge-1-1', 'cge-3-0',
                        'cge-3-1', 'cge-12-3'],
               'matchers': ['cge-?-0', 'cge-3*', 'foo'],
               'matched': set(['cge-1-0', 'cge-3-0',
                               'cge-3-1']),
               'unmatched': set(['cge-1-1', 'cge-12-3'])},
              {'full': ['cge-1-0', 'cge-1-1'],
               'matchers': ['cge-1-0'],
               'matched': set(['cge-1-0']),
               'unmatched': set(['cge-1-1'])},
              {'full': ['cge-1-0', 'cge-1-1'],
               'matchers': ['foo'],
               'matched': set([]),
               'unmatched': set(['cge-1-0', 'cge-1-1'])})
    @ddt.unpack
    def test_do_match_any(self, full, matchers, matched, unmatched):
        real_matched, real_unmatched = utils.do_match_any(
            full, matchers)
        self.assertEqual(matched, real_matched)
        self.assertEqual(unmatched, real_unmatched)
