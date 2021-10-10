# Copyright 2021 Cloudification GmbH.
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

from manila import context
from manila.scheduler.filters import host
from manila import test
from manila.tests.scheduler import fakes


fake_host1 = fakes.FakeHostState('host1', {})
fake_host2 = fakes.FakeHostState('host2', {})


@ddt.ddt
class OnlyHostFilterTestCase(test.TestCase):
    """Test case for OnlyHostFilter."""

    def setUp(self):
        super(OnlyHostFilterTestCase, self).setUp()
        self.filter = host.OnlyHostFilter()
        self.user_context = context.RequestContext('user', 'project')
        self.admin_context = context.RequestContext('user', 'project',
                                                    is_admin=True)

    def _make_filter_properties(self, hint):
        return {
            'context': self.admin_context,
            'scheduler_hints': hint,
        }

    @ddt.data((fake_host1, {'scheduler_hints': None}),
              (fake_host1, {'scheduler_hints': {}}),
              (fake_host1,
              {'scheduler_hints': {'only_host': fake_host2.host}}))
    @ddt.unpack
    def test_only_host_filter_user_context(self, host, filter_properties):
        context = {'context': self.user_context}
        filter_properties.update(context)
        self.assertTrue(self.filter.host_passes(host, filter_properties))

    @ddt.data((fake_host1, None, True),
              (fake_host1, {}, True),
              (fake_host1, {'only_host': fake_host1.host}, True),
              (fake_host2, {'only_host': fake_host1.host}, False))
    @ddt.unpack
    def test_only_host_filter_admin_context(self, host, hint, host_passes):
        filter_properties = self._make_filter_properties(hint)
        self.assertEqual(host_passes,
                         self.filter.host_passes(host, filter_properties))
