# Copyright 2016 EMC Corporation OpenStack Foundation.
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
Tests For utils.
"""

import ddt

from manila.scheduler import utils
from manila import test


@ddt.ddt
class UtilsTestCase(test.TestCase):
    """Test case for utils."""

    @ddt.data(
        ({'extra_specs': {'thin_provisioning': True}}, True),
        ({'extra_specs': {'thin_provisioning': False}}, False),
        ({'extra_specs': {'foo': 'bar'}}, True),
        ({'foo': 'bar'}, True),
        ({'extra_specs': {'thin_provisioning': '<is> True'}},
         True),
        ({'extra_specs': {'thin_provisioning': '<is> False'}},
         False),
        ({'extra_specs': {'thin_provisioning': '<not> True'}},
         False),
        ({'extra_specs': {}}, True),
        ({}, True),
    )
    @ddt.unpack
    def test_use_thin_logic(self, properties, use_thin):
        use_thin_logic = utils.use_thin_logic(properties)
        self.assertEqual(use_thin, use_thin_logic)

    @ddt.data(
        (True, True),
        (False, False),
        (None, False),
        ([True, False], True),
        ([True], True),
        ([False], False),
        ('wrong', False),
    )
    @ddt.unpack
    def test_thin_provisioning(self, thin_capabilities, thin):
        thin_provisioning = utils.thin_provisioning(thin_capabilities)
        self.assertEqual(thin, thin_provisioning)
