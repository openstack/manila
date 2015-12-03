# Copyright 2011-2012 OpenStack Foundation.
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
Tests For Scheduler weighers.
"""

from manila.scheduler.weighers import base
from manila import test
from manila.tests.scheduler import fakes


class TestWeightHandler(test.TestCase):
    def test_get_all_classes(self):
        namespace = "manila.tests.scheduler.fakes"
        handler = base.BaseWeightHandler(
            base.BaseWeigher, namespace)
        classes = handler.get_all_classes()
        self.assertTrue(fakes.FakeWeigher1 in classes)
        self.assertTrue(fakes.FakeWeigher2 in classes)
        self.assertFalse(fakes.FakeClass in classes)

    def test_no_multiplier(self):
        class FakeWeigher(base.BaseWeigher):
            def _weigh_object(self, *args, **kwargs):
                pass

        self.assertEqual(1.0,
                         FakeWeigher().weight_multiplier())

    def test_no_weight_object(self):
        class FakeWeigher(base.BaseWeigher):
            def weight_multiplier(self, *args, **kwargs):
                pass
        self.assertRaises(TypeError,
                          FakeWeigher)

    def test_normalization(self):
        # weight_list, expected_result, minval, maxval
        map_ = (
            ((), (), None, None),
            ((0.0, 0.0), (0.0, 0.0), None, None),
            ((1.0, 1.0), (0.0, 0.0), None, None),

            ((20.0, 50.0), (0.0, 1.0), None, None),
            ((20.0, 50.0), (0.0, 0.375), None, 100.0),
            ((20.0, 50.0), (0.4, 1.0), 0.0, None),
            ((20.0, 50.0), (0.2, 0.5), 0.0, 100.0),
        )
        for seq, result, minval, maxval in map_:
            ret = base.normalize(seq, minval=minval, maxval=maxval)
            self.assertEqual(result, tuple(ret))
