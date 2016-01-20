# Copyright 2011 OpenStack Foundation.
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

"""
Tests For Scheduler Host Filters.
"""
import ddt

from manila.scheduler.filters import extra_specs_ops
from manila import test


@ddt.ddt
class ExtraSpecsOpsTestCase(test.TestCase):
    def _do_extra_specs_ops_test(self, value, req, matches):
        assertion = self.assertTrue if matches else self.assertFalse
        assertion(extra_specs_ops.match(value, req))

    @ddt.unpack
    @ddt.data(
        ('1', '1', True),
        ('', '1', False),
        ('3', '1', False),
        ('222', '2', False),
        ('4', '> 2', False),
        ('123', '= 123', True),
        ('124', '= 123', True),
        ('34', '=234', False),
        ('34', '=', False),
        ('123', 's== 123', True),
        ('1234', 's== 123', False),
        ('1234', 's!= 123', True),
        ('123', 's!= 123', False),
        ('1000', 's>= 234', False),
        ('1234', 's<= 1000', False),
        ('2', 's< 12', False),
        ('12', 's> 2', False),
        ('12311321', '<in> 11', True),
        ('12311321', '<in> 12311321', True),
        ('12311321', '<in> 12311321 <in>', True),
        ('12310321', '<in> 11', False),
        ('12310321', '<in> 11 <in>', False),
        (True, 'True', True),
        (True, '<is> True', True),
        (True, '<is> False', False),
        (False, 'False', True),
        (False, '<is> False', True),
        (False, '<is> True', False),
        (False, 'Nonsense', False),
        (False, '<is> Nonsense', True),
        (True, 'False', False),
        (False, 'True', False),
        ('12', '<or> 11 <or> 12', True),
        ('13', '<or> 11 <or> 12', False),
        ('13', '<or> 11 <or> 12 <or>', False),
        ('2', '<= 10', True),
        ('3', '<= 2', False),
        ('3', '>= 1', True),
        ('2', '>= 3', False),
    )
    def test_extra_specs_matches_simple(self, value, req, matches):
        self._do_extra_specs_ops_test(
            value, req, matches)
