# Copyright 2024 VAST Data Inc.
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
import json
import pickle
from unittest import mock

import ddt

from manila.share.drivers.vastdata import driver_util
from manila import test


driver_util.CONF.debug = True


@ddt.ddt
class TestBunch(test.TestCase):
    def setUp(self):
        super(TestBunch, self).setUp()
        self.bunch = driver_util.Bunch(a=1, b=2)

    def test_bunch_getattr(self):
        self.assertEqual(self.bunch.a, 1)

    def test_bunch_setattr(self):
        self.bunch.c = 3
        self.assertEqual(self.bunch.c, 3)

    def test_bunch_delattr(self):
        del self.bunch.a
        self.assertRaises(AttributeError, lambda: self.bunch.a)

    def test_bunch_to_dict(self):
        self.assertEqual(self.bunch.to_dict(), {"a": 1, "b": 2})

    def test_bunch_from_dict(self):
        self.assertEqual(
            driver_util.Bunch.from_dict({"a": 1, "b": 2}), self.bunch
        )

    def test_bunch_to_json(self):
        self.assertEqual(self.bunch.to_json(), json.dumps({"a": 1, "b": 2}))

    def test_bunch_without(self):
        self.assertEqual(self.bunch.without("a"), driver_util.Bunch(b=2))

    def test_bunch_but_with(self):
        self.assertEqual(
            self.bunch.but_with(c=3), driver_util.Bunch(a=1, b=2, c=3)
        )

    def test_bunch_delattr_missing(self):
        self.assertRaises(
            AttributeError,
            lambda: self.bunch.__delattr__("non_existing_attribute")
        )

    def test_bunch_from_json(self):
        json_bunch = json.dumps({"a": 1, "b": 2})
        self.assertEqual(driver_util.Bunch.from_json(json_bunch), self.bunch)

    def test_bunch_render(self):
        self.assertEqual(self.bunch.render(), "a=1, b=2")

    def test_bunch_pickle(self):
        pickled_bunch = pickle.dumps(self.bunch)
        unpickled_bunch = pickle.loads(pickled_bunch)
        self.assertEqual(self.bunch, unpickled_bunch)

    @ddt.data(True, False)
    def test_bunch_copy(self, deep):
        copy_bunch = self.bunch.copy(deep=deep)
        self.assertEqual(copy_bunch, self.bunch)
        self.assertIsNot(copy_bunch, self.bunch)

    def test_name_starts_with_underscore_and_digit(self):
        bunch = driver_util.Bunch()
        bunch["1"] = "value"
        self.assertEqual(bunch._1, "value")

    def test_bunch_recursion(self):
        x = driver_util.Bunch(
            a="a", b="b", d=driver_util.Bunch(x="axe", y="why")
        )
        x.d.x = x
        x.d.y = x.b
        print(x)

    def test_bunch_repr(self):
        self.assertEqual(repr(self.bunch), "Bunch(a=1, b=2)")

    def test_getitem_with_integral_key(self):
        self.bunch["1"] = "value"
        self.assertEqual(self.bunch[1], "value")

    def test_bunch_dir(self):
        self.assertEqual(
            set(i for i in dir(self.bunch) if not i.startswith("_")),
            {
                "a",
                "b",
                "but_with",
                "clear",
                "copy",
                "from_dict",
                "from_json",
                "fromkeys",
                "get",
                "items",
                "keys",
                "pop",
                "popitem",
                "render",
                "setdefault",
                "to_dict",
                "to_json",
                "update",
                "values",
                "without",
            },
        )

    def test_bunch_edge_cases(self):
        # Test edge cases for attribute access, setting, and deletion
        self.bunch["key-with-special-chars_123"] = "value"
        self.assertEqual(self.bunch["key-with-special-chars_123"], "value")
        self.bunch["key-with-special-chars_123"] = None
        self.assertIsNone(self.bunch["key-with-special-chars_123"])
        del self.bunch["key-with-special-chars_123"]
        self.assertRaises(
            KeyError,
            lambda: self.bunch["key-with-special-chars_123"]
        )

    def test_bunch_deep_copy(self):
        nested_bunch = driver_util.Bunch(x=driver_util.Bunch(y=1))
        deep_copy = nested_bunch.copy(deep=True)
        self.assertIsNot(nested_bunch["x"], deep_copy["x"])
        self.assertEqual(nested_bunch["x"]["y"], deep_copy["x"]["y"])

    def test_bunch_serialization(self):
        # Test serialization with nested structures
        nested_bunch = driver_util.Bunch(a=1, b=driver_util.Bunch(c=2))
        self.assertEqual(nested_bunch.to_dict(), {"a": 1, "b": {"c": 2}})
        self.assertEqual(
            nested_bunch.to_json(),
            json.dumps({"a": 1, "b": {"c": 2}})
        )


class TestBunchify(test.TestCase):
    def test_bunchify(self):
        self.assertEqual(
            driver_util.bunchify({"a": 1, "b": 2}, c=3),
            driver_util.Bunch(a=1, b=2, c=3)
        )
        x = driver_util.bunchify(dict(a=[dict(b=5), 9, (1, 2)], c=8))
        self.assertEqual(x.a[0].b, 5)
        self.assertEqual(x.a[1], 9)
        self.assertIsInstance(x.a[2], tuple)
        self.assertEqual(x.c, 8)
        self.assertEqual(x.pop("c"), 8)

    def test_bunchify_edge_cases(self):
        # Test edge cases for bunchify function
        self.assertEqual(driver_util.bunchify({}), driver_util.Bunch())

    def test_bunchify_nested_structures(self):
        # Test bunchify with nested structures
        nested_dict = {"a": [{"b": 1}, 2]}
        self.assertEqual(driver_util.bunchify(nested_dict).a[0].b, 1)


class TestUnbunchify(test.TestCase):
    def test_unbunchify(self):
        self.assertEqual(
            driver_util.unbunchify(driver_util.Bunch(a=1, b=2)),
            {"a": 1, "b": 2}
        )


@ddt.ddt
class TestGenerateIpRange(test.TestCase):

    @ddt.data(
        (
            [["15.0.0.1", "15.0.0.4"], ["10.0.0.27", "10.0.0.30"]],
            [
                "15.0.0.1",
                "15.0.0.2",
                "15.0.0.3",
                "15.0.0.4",
                "10.0.0.27",
                "10.0.0.28",
                "10.0.0.29",
                "10.0.0.30",
            ],
        ),
        (
            [["15.0.0.1", "15.0.0.1"], ["10.0.0.20", "10.0.0.20"]],
            ["15.0.0.1", "10.0.0.20"],
        ),
        ([], []),
    )
    @ddt.unpack
    def test_generate_ip_range(self, ip_ranges, expected):
        ips = driver_util.generate_ip_range(ip_ranges)
        assert ips == expected

    def test_generate_ip_range_edge_cases(self):
        # Test edge cases for generate_ip_range function
        self.assertEqual(driver_util.generate_ip_range([]), [])
        self.assertEqual(driver_util.generate_ip_range(
            [["15.0.0.1", "15.0.0.1"]]), ["15.0.0.1"]
        )

    def test_generate_ip_range_large_range(self):
        # Test with a large range of IPs
        start_ip = "192.168.0.1"
        end_ip = "192.168.255.255"
        ips = driver_util.generate_ip_range([[start_ip, end_ip]])
        self.assertEqual(len(ips), 65535)


class MockClass1:
    def method1(self):
        return 1

    def _private_method(self):
        return 2


class TestDecorateMethodsWith(test.TestCase):

    def test_decorate_methods_with(self):
        decorated_cls = driver_util.decorate_methods_with(
            mock.Mock())(MockClass1)
        self.assertTrue(hasattr(decorated_cls, 'method1'))
        self.assertTrue(hasattr(decorated_cls, '_private_method'))


class MockClass2:
    @driver_util.verbose_driver_trace
    def method1(self):
        return 1


class TestVerboseDriverTrace(test.TestCase):

    def test_verbose_driver_trace_debug_true(self):
        mock_instance = MockClass2()
        with mock.patch.object(
                driver_util.LOG, 'debug') as mock_debug:
            mock_instance.method1()
            self.assertEqual(mock_debug.call_count, 2)
