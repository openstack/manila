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

import ddt
import mock
from oslo_utils import strutils

from manila.common import constants
from manila import context
from manila import exception
from manila.scheduler.drivers import base
from manila.scheduler.drivers import filter
from manila.scheduler import host_manager
from manila.tests.scheduler.drivers import test_base
from manila.tests.scheduler import fakes

SNAPSHOT_SUPPORT = constants.ExtraSpecs.SNAPSHOT_SUPPORT
REPLICATION_TYPE_SPEC = constants.ExtraSpecs.REPLICATION_TYPE_SPEC


@ddt.ddt
class FilterSchedulerTestCase(test_base.SchedulerTestCase):
    """Test case for Filter Scheduler."""

    driver_cls = filter.FilterScheduler

    def test___format_filter_properties_active_replica_host_is_provided(self):
        sched = fakes.FakeFilterScheduler()
        fake_context = context.RequestContext('user', 'project')
        request_spec = {
            'share_properties': {'project_id': 1, 'size': 1},
            'share_instance_properties': {},
            'share_type': {'name': 'NFS'},
            'share_id': ['fake-id1'],
            'active_replica_host': 'fake_ar_host',
        }
        hosts = [fakes.FakeHostState(host, {'replication_domain': 'xyzzy'})
                 for host in ('fake_ar_host', 'fake_host_2')]
        self.mock_object(sched.host_manager, 'get_all_host_states_share',
                         mock.Mock(return_value=hosts))
        self.mock_object(sched, 'populate_filter_properties_share')

        retval = sched._format_filter_properties(
            fake_context, {}, request_spec)

        self.assertTrue('replication_domain' in retval[0])

    def test_create_share_no_hosts(self):
        # Ensure empty hosts/child_zones result in NoValidHosts exception.
        sched = fakes.FakeFilterScheduler()
        fake_context = context.RequestContext('user', 'project')
        request_spec = {
            'share_properties': {'project_id': 1, 'size': 1},
            'share_instance_properties': {},
            'share_type': {'name': 'NFS'},
            'share_id': ['fake-id1'],
        }
        self.assertRaises(exception.NoValidHost, sched.schedule_create_share,
                          fake_context, request_spec, {})

    @mock.patch('manila.scheduler.host_manager.HostManager.'
                'get_all_host_states_share')
    def test_create_share_non_admin(self, _mock_get_all_host_states):
        # Test creating a volume locally using create_volume, passing
        # a non-admin context. DB actions should work.
        self.was_admin = False

        def fake_get(context, *args, **kwargs):
            # Make sure this is called with admin context, even though
            # we're using user context below.
            self.was_admin = context.is_admin
            return {}

        sched = fakes.FakeFilterScheduler()
        _mock_get_all_host_states.side_effect = fake_get
        fake_context = context.RequestContext('user', 'project')
        request_spec = {
            'share_properties': {'project_id': 1, 'size': 1},
            'share_instance_properties': {},
            'share_type': {'name': 'NFS'},
            'share_id': ['fake-id1'],
        }
        self.assertRaises(exception.NoValidHost, sched.schedule_create_share,
                          fake_context, request_spec, {})
        self.assertTrue(self.was_admin)

    @ddt.data(
        {'name': 'foo'},
        {'name': 'foo', 'extra_specs': {}},
        *[{'name': 'foo', 'extra_specs': {SNAPSHOT_SUPPORT: v}}
          for v in ('True', '<is> True', 'true', '1')]
    )
    @mock.patch('manila.db.service_get_all_by_topic')
    def test__schedule_share_with_snapshot_support(
            self, share_type, _mock_service_get_all_by_topic):
        sched = fakes.FakeFilterScheduler()
        sched.host_manager = fakes.FakeHostManager()
        fake_context = context.RequestContext('user', 'project',
                                              is_admin=True)
        fakes.mock_host_manager_db_calls(_mock_service_get_all_by_topic)
        request_spec = {
            'share_type': share_type,
            'share_properties': {'project_id': 1, 'size': 1},
            'share_instance_properties': {},
        }

        weighed_host = sched._schedule_share(fake_context, request_spec, {})

        self.assertIsNotNone(weighed_host)
        self.assertIsNotNone(weighed_host.obj)
        self.assertTrue(hasattr(weighed_host.obj, SNAPSHOT_SUPPORT))
        expected_snapshot_support = strutils.bool_from_string(
            share_type.get('extra_specs', {}).get(
                SNAPSHOT_SUPPORT, 'True').split()[-1])
        self.assertEqual(
            expected_snapshot_support,
            getattr(weighed_host.obj, SNAPSHOT_SUPPORT))
        self.assertTrue(_mock_service_get_all_by_topic.called)

    @ddt.data(
        *[{'name': 'foo', 'extra_specs': {SNAPSHOT_SUPPORT: v}}
          for v in ('False', '<is> False', 'false', '0')]
    )
    @mock.patch('manila.db.service_get_all_by_topic')
    def test__schedule_share_without_snapshot_support(
            self, share_type, _mock_service_get_all_by_topic):
        sched = fakes.FakeFilterScheduler()
        sched.host_manager = fakes.FakeHostManager()
        fake_context = context.RequestContext('user', 'project',
                                              is_admin=True)
        fakes.mock_host_manager_db_calls(_mock_service_get_all_by_topic)
        request_spec = {
            'share_type': share_type,
            'share_properties': {'project_id': 1, 'size': 1},
            'share_instance_properties': {'project_id': 1, 'size': 1},
        }

        weighed_host = sched._schedule_share(fake_context, request_spec, {})

        self.assertIsNone(weighed_host)
        self.assertTrue(_mock_service_get_all_by_topic.called)

    @ddt.data(
        *[{'name': 'foo', 'extra_specs': {
            SNAPSHOT_SUPPORT: 'True', REPLICATION_TYPE_SPEC: v
        }} for v in ('writable', 'readable', 'dr')]
    )
    @mock.patch('manila.db.service_get_all_by_topic')
    def test__schedule_share_with_valid_replication_spec(
            self, share_type, _mock_service_get_all_by_topic):
        sched = fakes.FakeFilterScheduler()
        sched.host_manager = fakes.FakeHostManager()
        fake_context = context.RequestContext('user', 'project',
                                              is_admin=True)
        fakes.mock_host_manager_db_calls(_mock_service_get_all_by_topic)
        request_spec = {
            'share_type': share_type,
            'share_properties': {'project_id': 1, 'size': 1},
            'share_instance_properties': {'project_id': 1, 'size': 1},
        }
        weighed_host = sched._schedule_share(fake_context, request_spec, {})

        self.assertIsNotNone(weighed_host)
        self.assertIsNotNone(weighed_host.obj)
        self.assertTrue(hasattr(weighed_host.obj, REPLICATION_TYPE_SPEC))
        expected_replication_type_support = (
            share_type.get('extra_specs', {}).get(REPLICATION_TYPE_SPEC))
        self.assertEqual(
            expected_replication_type_support,
            getattr(weighed_host.obj, REPLICATION_TYPE_SPEC))
        self.assertTrue(_mock_service_get_all_by_topic.called)

    @ddt.data(
        *[{'name': 'foo', 'extra_specs': {
            SNAPSHOT_SUPPORT: 'True', REPLICATION_TYPE_SPEC: v
        }} for v in ('None', 'readwrite', 'activesync')]
    )
    @mock.patch('manila.db.service_get_all_by_topic')
    def test__schedule_share_with_invalid_replication_type_spec(
            self, share_type, _mock_service_get_all_by_topic):
        sched = fakes.FakeFilterScheduler()
        sched.host_manager = fakes.FakeHostManager()
        fake_context = context.RequestContext('user', 'project',
                                              is_admin=True)
        fakes.mock_host_manager_db_calls(_mock_service_get_all_by_topic)
        request_spec = {
            'share_type': share_type,
            'share_properties': {'project_id': 1, 'size': 1},
            'share_instance_properties': {'project_id': 1, 'size': 1},
        }
        weighed_host = sched._schedule_share(fake_context, request_spec, {})

        self.assertIsNone(weighed_host)
        self.assertTrue(_mock_service_get_all_by_topic.called)

    @mock.patch('manila.db.service_get_all_by_topic')
    def test_schedule_share_with_cg_pool_support(
            self, _mock_service_get_all_by_topic):
        sched = fakes.FakeFilterScheduler()
        sched.host_manager = fakes.FakeHostManager()
        fake_context = context.RequestContext('user', 'project',
                                              is_admin=True)
        fakes.mock_host_manager_db_calls(_mock_service_get_all_by_topic)
        request_spec = {
            'share_type': {
                'name': 'NFS',
                'extra_specs': {'consistency_group_support': 'pool'}
            },
            'share_properties': {'project_id': 1, 'size': 1},
            'share_instance_properties': {'project_id': 1, 'size': 1},
            'consistency_group': {
                'id': 'fake-cg-id',
                'host': 'host5#_pool0',
            }
        }

        weighed_host = sched._schedule_share(fake_context, request_spec, {})

        self.assertIsNotNone(weighed_host)
        self.assertIsNotNone(weighed_host.obj)
        self.assertEqual('host5#_pool0', weighed_host.obj.host)
        self.assertTrue(_mock_service_get_all_by_topic.called)

    def _setup_dedupe_fakes(self, extra_specs):
        sched = fakes.FakeFilterScheduler()
        sched.host_manager = fakes.FakeHostManager()
        fake_context = context.RequestContext('user', 'project', is_admin=True)

        share_type = {'name': 'foo', 'extra_specs': extra_specs}
        request_spec = {
            'share_type': share_type,
            'share_properties': {'project_id': 1, 'size': 1},
            'share_instance_properties': {'project_id': 1, 'size': 1},
        }

        return sched, fake_context, request_spec

    @mock.patch('manila.db.service_get_all_by_topic')
    def test__schedule_share_with_default_dedupe_value(
            self, _mock_service_get_all_by_topic):
        sched, fake_context, request_spec = self._setup_dedupe_fakes(
            {'capabilities:dedupe': '<is> False'})
        fakes.mock_host_manager_db_calls(_mock_service_get_all_by_topic)

        weighed_host = sched._schedule_share(fake_context, request_spec, {})

        self.assertIsNotNone(weighed_host)
        self.assertIsNotNone(weighed_host.obj)
        self.assertTrue(hasattr(weighed_host.obj, 'dedupe'))
        self.assertFalse(weighed_host.obj.dedupe)
        self.assertTrue(_mock_service_get_all_by_topic.called)

    @ddt.data('True', '<is> True')
    @mock.patch('manila.db.service_get_all_by_topic')
    def test__schedule_share_with_default_dedupe_value_fail(
            self, capability, _mock_service_get_all_by_topic):
        sched, fake_context, request_spec = self._setup_dedupe_fakes(
            {'capabilities:dedupe': capability})
        fakes.mock_host_manager_db_calls(_mock_service_get_all_by_topic)

        weighed_host = sched._schedule_share(fake_context, request_spec, {})

        self.assertIsNone(weighed_host)
        self.assertTrue(_mock_service_get_all_by_topic.called)

    def test_schedule_share_type_is_none(self):
        sched = fakes.FakeFilterScheduler()
        request_spec = {
            'share_type': None,
            'share_properties': {'project_id': 1, 'size': 1},
        }
        self.assertRaises(exception.InvalidParameterValue,
                          sched._schedule_share,
                          self.context, request_spec)

    @mock.patch('manila.db.service_get_all_by_topic')
    def test_schedule_share_with_instance_properties(
            self, _mock_service_get_all_by_topic):
        sched = fakes.FakeFilterScheduler()
        sched.host_manager = fakes.FakeHostManager()
        fake_context = context.RequestContext('user', 'project',
                                              is_admin=True)
        fakes.mock_host_manager_db_calls(_mock_service_get_all_by_topic)
        share_type = {'name': 'foo'}
        request_spec = {
            'share_type': share_type,
            'share_properties': {'project_id': 1, 'size': 1},
            'share_instance_properties': {'availability_zone_id': "fake_az"},
        }

        weighed_host = sched._schedule_share(fake_context, request_spec, {})

        self.assertIsNone(weighed_host)
        self.assertTrue(_mock_service_get_all_by_topic.called)

    def test_max_attempts(self):
        self.flags(scheduler_max_attempts=4)
        sched = fakes.FakeFilterScheduler()
        self.assertEqual(4, sched._max_attempts())

    def test_invalid_max_attempts(self):
        self.flags(scheduler_max_attempts=0)
        self.assertRaises(exception.InvalidParameterValue,
                          fakes.FakeFilterScheduler)

    def test_retry_disabled(self):
        # Retry info should not get populated when re-scheduling is off.
        self.flags(scheduler_max_attempts=1)
        sched = fakes.FakeFilterScheduler()
        request_spec = {
            'share_type': {'name': 'iSCSI'},
            'share_properties': {'project_id': 1, 'size': 1},
            'share_instance_properties': {},
        }
        filter_properties = {}
        sched._schedule_share(self.context, request_spec,
                              filter_properties=filter_properties)
        # Should not have retry info in the populated filter properties.
        self.assertNotIn("retry", filter_properties)

    def test_retry_attempt_one(self):
        # Test retry logic on initial scheduling attempt.
        self.flags(scheduler_max_attempts=2)
        sched = fakes.FakeFilterScheduler()
        request_spec = {
            'share_type': {'name': 'iSCSI'},
            'share_properties': {'project_id': 1, 'size': 1},
            'share_instance_properties': {},
        }
        filter_properties = {}
        sched._schedule_share(self.context, request_spec,
                              filter_properties=filter_properties)
        num_attempts = filter_properties['retry']['num_attempts']
        self.assertEqual(1, num_attempts)

    def test_retry_attempt_two(self):
        # Test retry logic when re-scheduling.
        self.flags(scheduler_max_attempts=2)
        sched = fakes.FakeFilterScheduler()
        request_spec = {
            'share_type': {'name': 'iSCSI'},
            'share_properties': {'project_id': 1, 'size': 1},
            'share_instance_properties': {},
        }
        retry = dict(num_attempts=1)
        filter_properties = dict(retry=retry)
        sched._schedule_share(self.context, request_spec,
                              filter_properties=filter_properties)
        num_attempts = filter_properties['retry']['num_attempts']
        self.assertEqual(2, num_attempts)

    def test_retry_exceeded_max_attempts(self):
        # Test for necessary explosion when max retries is exceeded.
        self.flags(scheduler_max_attempts=2)
        sched = fakes.FakeFilterScheduler()
        request_spec = {
            'share_type': {'name': 'iSCSI'},
            'share_properties': {'project_id': 1, 'size': 1},
        }
        retry = dict(num_attempts=2)
        filter_properties = dict(retry=retry)
        self.assertRaises(exception.NoValidHost, sched._schedule_share,
                          self.context, request_spec,
                          filter_properties=filter_properties)

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

    def test_schedule_create_consistency_group(self):
        # Ensure empty hosts/child_zones result in NoValidHosts exception.
        sched = fakes.FakeFilterScheduler()
        fake_context = context.RequestContext('user', 'project')
        fake_host = 'fake_host'
        request_spec = {'share_types': [{'id': 'NFS'}]}
        self.mock_object(sched, "_get_best_host_for_consistency_group",
                         mock.Mock(return_value=fake_host))
        fake_updated_group = mock.Mock()
        self.mock_object(base, "cg_update_db", mock.Mock(
            return_value=fake_updated_group))
        self.mock_object(sched.share_rpcapi, "create_consistency_group")

        sched.schedule_create_consistency_group(fake_context, 'fake_id',
                                                request_spec, {})

        sched._get_best_host_for_consistency_group.assert_called_once_with(
            fake_context, request_spec)
        base.cg_update_db.assert_called_once_with(
            fake_context, 'fake_id', fake_host)
        sched.share_rpcapi.create_consistency_group.assert_called_once_with(
            fake_context, fake_updated_group, fake_host)

    def test_create_cg_no_hosts(self):
        # Ensure empty hosts/child_zones result in NoValidHosts exception.
        sched = fakes.FakeFilterScheduler()
        fake_context = context.RequestContext('user', 'project')
        request_spec = {'share_types': [{'id': 'NFS'}]}

        self.assertRaises(exception.NoValidHost,
                          sched.schedule_create_consistency_group,
                          fake_context, 'fake_id', request_spec, {})

    @mock.patch('manila.db.service_get_all_by_topic')
    def test_get_weighted_candidates_for_consistency_group(
            self, _mock_service_get_all_by_topic):
        sched = fakes.FakeFilterScheduler()
        sched.host_manager = fakes.FakeHostManager()
        fake_context = context.RequestContext('user', 'project')
        fakes.mock_host_manager_db_calls(_mock_service_get_all_by_topic)
        request_spec = {'share_types': [{'name': 'NFS',
                                         'extra_specs': {
                                             SNAPSHOT_SUPPORT: True,
                                         }}]}

        hosts = sched._get_weighted_candidates_cg(fake_context,
                                                  request_spec)

        self.assertTrue(hosts)

    @mock.patch('manila.db.service_get_all_by_topic')
    def test_get_weighted_candidates_for_consistency_group_no_hosts(
            self, _mock_service_get_all_by_topic):
        sched = fakes.FakeFilterScheduler()
        sched.host_manager = fakes.FakeHostManager()
        fake_context = context.RequestContext('user', 'project')
        fakes.mock_host_manager_db_calls(_mock_service_get_all_by_topic)
        request_spec = {'share_types': [{'name': 'NFS',
                                         'extra_specs': {
                                             SNAPSHOT_SUPPORT: False
                                         }}]}

        hosts = sched._get_weighted_candidates_cg(fake_context,
                                                  request_spec)

        self.assertEqual([], hosts)

    @mock.patch('manila.db.service_get_all_by_topic')
    def test_get_weighted_candidates_for_consistency_group_many_hosts(
            self, _mock_service_get_all_by_topic):
        sched = fakes.FakeFilterScheduler()
        sched.host_manager = fakes.FakeHostManager()
        fake_context = context.RequestContext('user', 'project')
        fakes.mock_host_manager_db_calls(_mock_service_get_all_by_topic)
        request_spec = {'share_types': [{'name': 'NFS',
                                         'extra_specs': {
                                             SNAPSHOT_SUPPORT: True
                                         }}]}

        hosts = sched._get_weighted_candidates_cg(fake_context,
                                                  request_spec)

        self.assertEqual(2, len(hosts))

    def _host_passes_filters_setup(self, mock_obj):
        sched = fakes.FakeFilterScheduler()
        sched.host_manager = fakes.FakeHostManager()
        fake_context = context.RequestContext('user', 'project',
                                              is_admin=True)

        fakes.mock_host_manager_db_calls(mock_obj)

        return (sched, fake_context)

    @mock.patch('manila.db.service_get_all_by_topic')
    def test_host_passes_filters_happy_day(self, _mock_service_get_topic):
        sched, ctx = self._host_passes_filters_setup(
            _mock_service_get_topic)
        request_spec = {'share_id': 1,
                        'share_type': {'name': 'fake_type'},
                        'share_instance_properties': {},
                        'share_properties': {'project_id': 1,
                                             'size': 1}}

        ret_host = sched.host_passes_filters(ctx, 'host1#_pool0',
                                             request_spec, {})

        self.assertEqual('host1#_pool0', ret_host.host)
        self.assertTrue(_mock_service_get_topic.called)

    @mock.patch('manila.db.service_get_all_by_topic')
    def test_host_passes_filters_no_capacity(self, _mock_service_get_topic):
        sched, ctx = self._host_passes_filters_setup(
            _mock_service_get_topic)
        request_spec = {'share_id': 1,
                        'share_type': {'name': 'fake_type'},
                        'share_instance_properties': {},
                        'share_properties': {'project_id': 1,
                                             'size': 1024}}

        self.assertRaises(exception.NoValidHost,
                          sched.host_passes_filters,
                          ctx, 'host3#_pool0', request_spec, {})
        self.assertTrue(_mock_service_get_topic.called)

    def test_schedule_create_replica_no_host(self):
        sched = fakes.FakeFilterScheduler()
        request_spec = fakes.fake_replica_request_spec()

        self.mock_object(self.driver_cls, '_schedule_share',
                         mock.Mock(return_value=None))

        self.assertRaises(exception.NoValidHost,
                          sched.schedule_create_replica,
                          self.context, request_spec, {})

    def test_schedule_create_replica(self):
        sched = fakes.FakeFilterScheduler()
        request_spec = fakes.fake_replica_request_spec()
        host = 'fake_host'
        replica_id = request_spec['share_instance_properties']['id']
        mock_update_db_call = self.mock_object(
            base, 'share_replica_update_db',
            mock.Mock(return_value='replica'))
        mock_share_rpcapi_call = self.mock_object(
            sched.share_rpcapi, 'create_share_replica')
        self.mock_object(
            self.driver_cls, '_schedule_share',
            mock.Mock(return_value=fakes.get_fake_host(host_name=host)))

        retval = sched.schedule_create_replica(
            self.context, fakes.fake_replica_request_spec(), {})

        self.assertIsNone(retval)
        mock_update_db_call.assert_called_once_with(
            self.context, replica_id, host)
        mock_share_rpcapi_call.assert_called_once_with(
            self.context, 'replica', host, request_spec=request_spec,
            filter_properties={})
