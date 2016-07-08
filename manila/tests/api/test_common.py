# Copyright 2010 OpenStack LLC.
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
Test suites for 'common' code used throughout the OpenStack HTTP API.
"""

import ddt
import webob
import webob.exc

from manila.api import common
from manila import test
from manila.tests.api import fakes
from manila.tests.db import fakes as db_fakes


NS = "{http://docs.openstack.org/compute/api/v1.1}"
ATOMNS = "{http://www.w3.org/2005/Atom}"


class LimiterTest(test.TestCase):
    """Unit tests for the `manila.api.common.limited` method.

    Takes in a list of items and, depending on the 'offset' and
    'limit' GET params, returns a subset or complete set of the given
    items.
    """

    def setUp(self):
        """Run before each test."""
        super(LimiterTest, self).setUp()
        self.tiny = list(range(1))
        self.small = list(range(10))
        self.medium = list(range(1000))
        self.large = list(range(10000))

    def test_limiter_offset_zero(self):
        """Test offset key works with 0."""
        req = webob.Request.blank('/?offset=0')
        self.assertEqual(self.tiny, common.limited(self.tiny, req))
        self.assertEqual(self.small, common.limited(self.small, req))
        self.assertEqual(self.medium, common.limited(self.medium, req))
        self.assertEqual(self.large[:1000], common.limited(self.large, req))

    def test_limiter_offset_medium(self):
        """Test offset key works with a medium sized number."""
        req = webob.Request.blank('/?offset=10')
        self.assertEqual([], common.limited(self.tiny, req))
        self.assertEqual(self.small[10:], common.limited(self.small, req))
        self.assertEqual(self.medium[10:], common.limited(self.medium, req))
        self.assertEqual(self.large[10:1010], common.limited(self.large, req))

    def test_limiter_offset_over_max(self):
        """Test offset key works with a number over 1000 (max_limit)."""
        req = webob.Request.blank('/?offset=1001')
        self.assertEqual([], common.limited(self.tiny, req))
        self.assertEqual([], common.limited(self.small, req))
        self.assertEqual([], common.limited(self.medium, req))
        self.assertEqual(
            self.large[1001:2001], common.limited(self.large, req))

    def test_limiter_offset_blank(self):
        """Test offset key works with a blank offset."""
        req = webob.Request.blank('/?offset=')
        self.assertRaises(
            webob.exc.HTTPBadRequest, common.limited, self.tiny, req)

    def test_limiter_offset_bad(self):
        """Test offset key works with a BAD offset."""
        req = webob.Request.blank(u'/?offset=\u0020aa')
        self.assertRaises(
            webob.exc.HTTPBadRequest, common.limited, self.tiny, req)

    def test_limiter_nothing(self):
        """Test request with no offset or limit."""
        req = webob.Request.blank('/')
        self.assertEqual(self.tiny, common.limited(self.tiny, req))
        self.assertEqual(self.small, common.limited(self.small, req))
        self.assertEqual(self.medium, common.limited(self.medium, req))
        self.assertEqual(self.large[:1000], common.limited(self.large, req))

    def test_limiter_limit_zero(self):
        """Test limit of zero."""
        req = webob.Request.blank('/?limit=0')
        self.assertEqual(self.tiny, common.limited(self.tiny, req))
        self.assertEqual(self.small, common.limited(self.small, req))
        self.assertEqual(self.medium, common.limited(self.medium, req))
        self.assertEqual(self.large[:1000], common.limited(self.large, req))

    def test_limiter_limit_medium(self):
        """Test limit of 10."""
        req = webob.Request.blank('/?limit=10')
        self.assertEqual(self.tiny, common.limited(self.tiny, req))
        self.assertEqual(self.small, common.limited(self.small, req))
        self.assertEqual(self.medium[:10], common.limited(self.medium, req))
        self.assertEqual(self.large[:10], common.limited(self.large, req))

    def test_limiter_limit_over_max(self):
        """Test limit of 3000."""
        req = webob.Request.blank('/?limit=3000')
        self.assertEqual(self.tiny, common.limited(self.tiny, req))
        self.assertEqual(self.small, common.limited(self.small, req))
        self.assertEqual(self.medium, common.limited(self.medium, req))
        self.assertEqual(self.large[:1000], common.limited(self.large, req))

    def test_limiter_limit_and_offset(self):
        """Test request with both limit and offset."""
        items = list(range(2000))
        req = webob.Request.blank('/?offset=1&limit=3')
        self.assertEqual(items[1:4], common.limited(items, req))
        req = webob.Request.blank('/?offset=3&limit=0')
        self.assertEqual(items[3:1003], common.limited(items, req))
        req = webob.Request.blank('/?offset=3&limit=1500')
        self.assertEqual(items[3:1003], common.limited(items, req))
        req = webob.Request.blank('/?offset=3000&limit=10')
        self.assertEqual([], common.limited(items, req))

    def test_limiter_custom_max_limit(self):
        """Test a max_limit other than 1000."""
        items = list(range(2000))
        req = webob.Request.blank('/?offset=1&limit=3')
        self.assertEqual(
            items[1:4], common.limited(items, req, max_limit=2000))
        req = webob.Request.blank('/?offset=3&limit=0')
        self.assertEqual(
            items[3:], common.limited(items, req, max_limit=2000))
        req = webob.Request.blank('/?offset=3&limit=2500')
        self.assertEqual(
            items[3:], common.limited(items, req, max_limit=2000))
        req = webob.Request.blank('/?offset=3000&limit=10')
        self.assertEqual([], common.limited(items, req, max_limit=2000))

    def test_limiter_negative_limit(self):
        """Test a negative limit."""
        req = webob.Request.blank('/?limit=-3000')
        self.assertRaises(
            webob.exc.HTTPBadRequest, common.limited, self.tiny, req)

    def test_limiter_negative_offset(self):
        """Test a negative offset."""
        req = webob.Request.blank('/?offset=-30')
        self.assertRaises(
            webob.exc.HTTPBadRequest, common.limited, self.tiny, req)


class PaginationParamsTest(test.TestCase):
    """Unit tests for the `manila.api.common.get_pagination_params` method.

    Takes in a request object and returns 'marker' and 'limit' GET
    params.
    """

    def test_no_params(self):
        """Test no params."""
        req = webob.Request.blank('/')
        self.assertEqual({}, common.get_pagination_params(req))

    def test_valid_marker(self):
        """Test valid marker param."""
        req = webob.Request.blank(
            '/?marker=263abb28-1de6-412f-b00b-f0ee0c4333c2')
        self.assertEqual({'marker': '263abb28-1de6-412f-b00b-f0ee0c4333c2'},
                         common.get_pagination_params(req))

    def test_valid_limit(self):
        """Test valid limit param."""
        req = webob.Request.blank('/?limit=10')
        self.assertEqual({'limit': 10}, common.get_pagination_params(req))

    def test_invalid_limit(self):
        """Test invalid limit param."""
        req = webob.Request.blank('/?limit=-2')
        self.assertRaises(
            webob.exc.HTTPBadRequest, common.get_pagination_params, req)

    def test_valid_limit_and_marker(self):
        """Test valid limit and marker parameters."""
        marker = '263abb28-1de6-412f-b00b-f0ee0c4333c2'
        req = webob.Request.blank('/?limit=20&marker=%s' % marker)
        self.assertEqual({'marker': marker, 'limit': 20},
                         common.get_pagination_params(req))


@ddt.ddt
class MiscFunctionsTest(test.TestCase):

    def test_remove_major_version_from_href(self):
        fixture = 'http://www.testsite.com/v1/images'
        expected = 'http://www.testsite.com/images'
        actual = common.remove_version_from_href(fixture)
        self.assertEqual(expected, actual)

    def test_remove_version_from_href(self):
        fixture = 'http://www.testsite.com/v1.1/images'
        expected = 'http://www.testsite.com/images'
        actual = common.remove_version_from_href(fixture)
        self.assertEqual(expected, actual)

    def test_remove_version_from_href_2(self):
        fixture = 'http://www.testsite.com/v1.1/'
        expected = 'http://www.testsite.com/'
        actual = common.remove_version_from_href(fixture)
        self.assertEqual(expected, actual)

    def test_remove_version_from_href_3(self):
        fixture = 'http://www.testsite.com/v10.10'
        expected = 'http://www.testsite.com'
        actual = common.remove_version_from_href(fixture)
        self.assertEqual(expected, actual)

    def test_remove_version_from_href_4(self):
        fixture = 'http://www.testsite.com/v1.1/images/v10.5'
        expected = 'http://www.testsite.com/images/v10.5'
        actual = common.remove_version_from_href(fixture)
        self.assertEqual(expected, actual)

    def test_remove_version_from_href_bad_request(self):
        fixture = 'http://www.testsite.com/1.1/images'
        self.assertRaises(ValueError,
                          common.remove_version_from_href,
                          fixture)

    def test_remove_version_from_href_bad_request_2(self):
        fixture = 'http://www.testsite.com/v/images'
        self.assertRaises(ValueError,
                          common.remove_version_from_href,
                          fixture)

    def test_remove_version_from_href_bad_request_3(self):
        fixture = 'http://www.testsite.com/v1.1images'
        self.assertRaises(ValueError,
                          common.remove_version_from_href,
                          fixture)

    def test_validate_cephx_id_invalid_with_period(self):
        self.assertRaises(webob.exc.HTTPBadRequest,
                          common.validate_cephx_id,
                          "client.manila")

    def test_validate_cephx_id_invalid_with_non_ascii(self):
        self.assertRaises(webob.exc.HTTPBadRequest,
                          common.validate_cephx_id,
                          u"bj\u00F6rn")

    @ddt.data("alice", "alice_bob", "alice bob")
    def test_validate_cephx_id_valid(self, test_id):
        common.validate_cephx_id(test_id)

    @ddt.data(['ip', '1.1.1.1', False], ['user', 'alice', False],
              ['cert', 'alice', False], ['cephx', 'alice', True],
              ['ip', '172.24.41.0/24', False],)
    @ddt.unpack
    def test_validate_access(self, access_type, access_to, ceph):
        common.validate_access(access_type=access_type, access_to=access_to,
                               enable_ceph=ceph)

    @ddt.data(['ip', 'alice', False], ['ip', '1.1.1.0/10/12', False],
              ['ip', '255.255.255.265', False], ['ip', '1.1.1.0/34', False],
              ['cert', '', False], ['cephx', 'client.alice', True],
              ['group', 'alice', True], ['cephx', 'alice', False],
              ['cephx', '', True], ['user', 'bob', False])
    @ddt.unpack
    def test_validate_access_exception(self, access_type, access_to, ceph):
        self.assertRaises(webob.exc.HTTPBadRequest, common.validate_access,
                          access_type=access_type, access_to=access_to,
                          enable_ceph=ceph)


@ddt.ddt
class ViewBuilderTest(test.TestCase):

    def setUp(self):
        super(ViewBuilderTest, self).setUp()
        self.expected_resource_dict = {
            'id': 'fake_resource_id',
            'foo': 'quz',
            'fred': 'bob',
            'alice': 'waldo',
            'spoon': 'spam',
            'xyzzy': 'qwerty',
        }
        self.fake_resource = db_fakes.FakeModel(self.expected_resource_dict)
        self.view_builder = fakes.FakeResourceViewBuilder()

    @ddt.data('1.0', '1.40')
    def test_versioned_method_no_updates(self, version):
        req = fakes.HTTPRequest.blank('/my_resource', version=version)

        actual_resource = self.view_builder.view(req, self.fake_resource)

        self.assertEqual(set({'id', 'foo', 'fred', 'alice'}),
                         set(actual_resource.keys()))

    @ddt.data(True, False)
    def test_versioned_method_v1_6(self, is_admin):
        req = fakes.HTTPRequest.blank('/my_resource', version='1.6',
                                      use_admin_context=is_admin)
        expected_keys = set({'id', 'foo', 'fred', 'alice'})
        if is_admin:
            expected_keys.add('spoon')

        actual_resource = self.view_builder.view(req, self.fake_resource)

        self.assertEqual(expected_keys, set(actual_resource.keys()))

    @ddt.unpack
    @ddt.data({'is_admin': True, 'version': '3.14'},
              {'is_admin': False, 'version': '3.14'},
              {'is_admin': False, 'version': '6.2'},
              {'is_admin': True, 'version': '6.2'})
    def test_versioned_method_all_match(self, is_admin, version):
        req = fakes.HTTPRequest.blank(
            '/my_resource', version=version, use_admin_context=is_admin)

        expected_keys = set({'id', 'fred', 'xyzzy', 'alice'})
        if is_admin:
            expected_keys.add('spoon')

        actual_resource = self.view_builder.view(req, self.fake_resource)

        self.assertEqual(expected_keys, set(actual_resource.keys()))
