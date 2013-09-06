# Copyright 2011 OpenStack LLC.
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
Tests For Filter Scheduler.
"""

from manila import context
from manila import exception
from manila import test

from manila.openstack.common.scheduler import weights
from manila.scheduler import filter_scheduler
from manila.scheduler import host_manager
from manila.tests.scheduler import fakes
from manila.tests.scheduler import test_scheduler
from manila.tests import utils as test_utils


def fake_get_filtered_hosts(hosts, filter_properties):
    return list(hosts)


class FilterSchedulerTestCase(test_scheduler.SchedulerTestCase):
    """Test case for Filter Scheduler."""

    driver_cls = filter_scheduler.FilterScheduler

    @test.skip_if(not test_utils.is_manila_installed(),
                  'Test requires Manila installed (try setup.py develop')
    def test_create_share_no_hosts(self):
        """
        Ensure empty hosts & child_zones result in NoValidHosts exception.
        """
        def _fake_empty_call_zone_method(*args, **kwargs):
            return []

        sched = fakes.FakeFilterScheduler()

        fake_context = context.RequestContext('user', 'project')
        request_spec = {'share_properties': {'project_id': 1,
                                              'size': 1},
                        'share_type': {'name': 'LVM_NFS'},
                        'share_id': ['fake-id1']}
        self.assertRaises(exception.NoValidHost, sched.schedule_create_share,
                          fake_context, request_spec, {})

    @test.skip_if(not test_utils.is_manila_installed(),
                  'Test requires Manila installed (try setup.py develop')
    def test_create_share_non_admin(self):
        """Test creating share passing a non-admin context.

        DB actions should work."""
        self.was_admin = False

        def fake_get(context, *args, **kwargs):
            # make sure this is called with admin context, even though
            # we're using user context below
            self.was_admin = context.is_admin
            return {}

        sched = fakes.FakeFilterScheduler()
        self.stubs.Set(sched.host_manager,
                       'get_all_host_states_share',
                       fake_get)

        fake_context = context.RequestContext('user', 'project')

        request_spec = {'share_properties': {'project_id': 1,
                                              'size': 1},
                        'share_type': {'name': 'LVM_NFS'},
                        'share_id': ['fake-id1']}
        self.assertRaises(exception.NoValidHost, sched.schedule_create_share,
                          fake_context, request_spec, {})
        self.assertTrue(self.was_admin)

    @test.skip_if(not test_utils.is_manila_installed(),
                  'Test requires Manila installed (try setup.py develop')
    def test_schedule_happy_day_share(self):
        """Make sure there's nothing glaringly wrong with _schedule_share()
        by doing a happy day pass through."""

        self.next_weight = 1.0

        def _fake_weigh_objects(_self, functions, hosts, options):
            self.next_weight += 2.0
            host_state = hosts[0]
            return [weights.WeighedHost(host_state, self.next_weight)]

        sched = fakes.FakeFilterScheduler()
        fake_context = context.RequestContext('user', 'project',
                                              is_admin=True)

        self.stubs.Set(sched.host_manager, 'get_filtered_hosts',
                       fake_get_filtered_hosts)
        self.stubs.Set(weights.HostWeightHandler,
                       'get_weighed_objects', _fake_weigh_objects)
        fakes.mox_host_manager_db_calls_share(self.mox, fake_context)

        request_spec = {'share_type': {'name': 'LVM_NFS'},
                        'sharee_properties': {'project_id': 1,
                                              'size': 1}}
        self.mox.ReplayAll()
        weighed_host = sched._schedule_share(fake_context, request_spec, {})
        self.assertTrue(weighed_host.obj is not None)

    def test_max_attempts(self):
        self.flags(scheduler_max_attempts=4)

        sched = fakes.FakeFilterScheduler()
        self.assertEqual(4, sched._max_attempts())

    def test_invalid_max_attempts(self):
        self.flags(scheduler_max_attempts=0)

        self.assertRaises(exception.InvalidParameterValue,
                          fakes.FakeFilterScheduler)

    def test_add_retry_host(self):
        retry = dict(num_attempts=1, hosts=[])
        filter_properties = dict(retry=retry)
        host = "fakehost"

        sched = fakes.FakeFilterScheduler()
        sched._add_retry_host(filter_properties, host)

        hosts = filter_properties['retry']['hosts']
        self.assertEqual(1, len(hosts))
        self.assertEqual(host, hosts[0])

    def test_post_select_populate(self):
        # Test addition of certain filter props after a node is selected.
        retry = {'hosts': [], 'num_attempts': 1}
        filter_properties = {'retry': retry}
        sched = fakes.FakeFilterScheduler()

        host_state = host_manager.HostState('host')
        host_state.total_capacity_gb = 1024
        sched._post_select_populate_filter_properties(filter_properties,
                                                      host_state)

        self.assertEqual('host',
                         filter_properties['retry']['hosts'][0])

        self.assertEqual(1024, host_state.total_capacity_gb)
