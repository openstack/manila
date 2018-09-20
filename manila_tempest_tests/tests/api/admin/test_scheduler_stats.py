# Copyright (c) 2015 Clinton Knight.  All rights reserved.
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
from tempest import config
from tempest.lib.common.utils import data_utils
from testtools import testcase as tc

from manila_tempest_tests.tests.api import base

CONF = config.CONF


@ddt.ddt
class SchedulerStatsAdminTest(base.BaseSharesAdminTest):

    @classmethod
    def _create_share_type(cls, negative=False):
        name = data_utils.rand_name("unique_st_name")
        extra_specs = None

        if negative:
            extra_specs = {
                'share_backend_name': data_utils.rand_name("fake_name"),
            }

        extra_specs = cls.add_extra_specs_to_dict(extra_specs=extra_specs)
        return cls.create_share_type(
            name, extra_specs=extra_specs,
            client=cls.admin_client)["share_type"]

    @classmethod
    def resource_setup(cls):
        super(SchedulerStatsAdminTest, cls).resource_setup()
        cls.admin_client = cls.shares_v2_client

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_pool_list(self):

        # List pools
        pool_response = self.shares_client.list_pools()
        pool_list = pool_response.get('pools')
        self.assertIsNotNone(pool_list, 'No pools returned from pools API')
        self.assertNotEmpty(pool_list)
        pool = pool_list[0]
        required_keys = {'name', 'host', 'backend', 'pool'}
        actual_keys = set(pool.keys())
        self.assertTrue(actual_keys.issuperset(required_keys))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_pool_list_with_filters(self):

        # List pools
        pool_response = self.shares_client.list_pools()
        pool_list = pool_response.get('pools')

        # Ensure we got at least one pool
        self.assertIsNotNone(pool_list, 'No pools returned from pools API')
        self.assertNotEmpty(pool_list)
        pool = pool_list[0]

        # Build search opts from data and get pools again with filter
        search_opts = {
            'host': self._wrap_regex_for_exact_match(pool.get('host')),
            'backend': self._wrap_regex_for_exact_match(pool.get('backend')),
            'pool': self._wrap_regex_for_exact_match(pool.get('pool')),
        }
        pool_response = self.shares_client.list_pools(
            search_opts=search_opts)
        filtered_pool_list = pool_response.get('pools')

        # Ensure we got exactly one pool matching the first one from above
        self.assertEqual(1, len(filtered_pool_list))

        # Match the key values, not the timestamp.
        for k, v in search_opts.items():
            self.assertEqual(v[1:-1], filtered_pool_list[0][k])

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_pool_list_with_filters_negative(self):

        # Build search opts for a non-existent pool
        search_opts = {
            'host': 'foo',
            'backend': 'bar',
            'pool': 'shark',
        }
        pool_response = self.shares_client.list_pools(
            search_opts=search_opts)
        pool_list = pool_response.get('pools')

        # Ensure we got no pools
        self.assertEmpty(pool_list)

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_pool_list_detail(self):

        # List pools
        pool_response = self.shares_client.list_pools(detail=True)
        pool_list = pool_response.get('pools')
        self.assertIsNotNone(pool_list, 'No pools returned from pools API')
        self.assertNotEmpty(pool_list)
        pool = pool_list[0]
        required_keys = {'name', 'host', 'backend', 'pool', 'capabilities'}
        actual_keys = set(pool.keys())
        self.assertTrue(actual_keys.issuperset(required_keys))

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_pool_list_detail_with_filters(self):

        # List pools
        pool_response = self.shares_client.list_pools(detail=True)
        pool_list = pool_response.get('pools')

        # Ensure we got at least one pool
        self.assertIsNotNone(pool_list, 'No pools returned from pools API')
        self.assertNotEmpty(pool_list)
        pool = pool_list[0]

        # Build search opts from data and get pools again with filter
        search_opts = {
            'host': self._wrap_regex_for_exact_match(pool.get('host')),
            'backend': self._wrap_regex_for_exact_match(pool.get('backend')),
            'pool': self._wrap_regex_for_exact_match(pool.get('pool')),
        }
        pool_response = self.shares_client.list_pools(
            detail=True, search_opts=search_opts)
        filtered_pool_list = pool_response.get('pools')

        # Ensure we got exactly one pool matching the first one from above
        self.assertEqual(1, len(filtered_pool_list))

        # Match the key values, not the timestamp.
        for k, v in search_opts.items():
            self.assertEqual(v[1:-1], filtered_pool_list[0][k])

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API)
    def test_pool_list_detail_with_filters_negative(self):

        # Build search opts for a non-existent pool
        search_opts = {
            'host': 'foo',
            'backend': 'bar',
            'pool': 'shark',
        }
        pool_response = self.shares_client.list_pools(
            detail=True, search_opts=search_opts)
        pool_list = pool_response.get('pools')

        # Ensure we got no pools
        self.assertEmpty(pool_list)

    @tc.attr(base.TAG_POSITIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_not_supported("2.23")
    @ddt.data((True, "name"), (True, "id"), (False, "name"), (False, "id"))
    @ddt.unpack
    def test_pool_list_with_share_type_filter_with_detail(
            self, detail, share_type_key):
        st = self._create_share_type()
        search_opts = {"share_type": st[share_type_key]}
        kwargs = {'search_opts': search_opts}

        if detail:
            kwargs.update({'detail': True})

        pools = self.admin_client.list_pools(**kwargs)['pools']

        self.assertIsNotNone(pools, 'No pools returned from pools API')
        self.assertNotEmpty(pools)
        for pool in pools:
            pool_keys = list(pool.keys())
            self.assertIn("name", pool_keys)
            self.assertIn("host", pool_keys)
            self.assertIn("backend", pool_keys)
            self.assertIn("pool", pool_keys)
            self.assertIs(detail, "capabilities" in pool_keys)

    @tc.attr(base.TAG_NEGATIVE, base.TAG_API_WITH_BACKEND)
    @base.skip_if_microversion_not_supported("2.23")
    @ddt.data((True, "name"), (True, "id"), (False, "name"), (False, "id"))
    @ddt.unpack
    def test_pool_list_with_share_type_filter_with_detail_negative(
            self, detail, share_type_key):
        st_negative = self._create_share_type(negative=True)
        search_opts = {"share_type": st_negative[share_type_key]}

        pools = self.admin_client.list_pools(
            detail=detail, search_opts=search_opts)['pools']

        self.assertEmpty(pools)

    def _wrap_regex_for_exact_match(self, regex):
        return '^%s$' % regex
