# Copyright 2011 OpenStack LLC.  # All Rights Reserved.
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
Tests For RetryFilter.
"""

from manila.scheduler.filters import retry
from manila import test
from manila.tests.scheduler import fakes


class HostFiltersTestCase(test.TestCase):
    """Test case for RetryFilter."""

    def setUp(self):
        super(HostFiltersTestCase, self).setUp()
        self.filter = retry.RetryFilter()

    def test_retry_filter_disabled(self):
        # Test case where retry/re-scheduling is disabled.
        host = fakes.FakeHostState('host1', {})
        filter_properties = {}
        self.assertTrue(self.filter.host_passes(host, filter_properties))

    def test_retry_filter_pass(self):
        # Node not previously tried.
        host = fakes.FakeHostState('host1', {})
        retry = dict(num_attempts=2, hosts=['host2'])
        filter_properties = dict(retry=retry)
        self.assertTrue(self.filter.host_passes(host, filter_properties))

    def test_retry_filter_fail(self):
        # Node was already tried.
        host = fakes.FakeHostState('host1', {})
        retry = dict(num_attempts=1, hosts=['host1'])
        filter_properties = dict(retry=retry)
        self.assertFalse(self.filter.host_passes(host, filter_properties))
