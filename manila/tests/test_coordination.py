# Copyright 2015 Intel
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
import mock
from oslo_service import loopingcall
from tooz import coordination as tooz_coordination
from tooz import locking as tooz_locking

from manila import coordination
from manila import test


class Locked(Exception):
    pass


class MockToozLock(tooz_locking.Lock):
    active_locks = set()

    def acquire(self, blocking=True):
        if self.name not in self.active_locks:
            self.active_locks.add(self.name)
            return True
        elif not blocking:
            return False
        else:
            raise Locked

    def release(self):
        self.active_locks.remove(self.name)


@mock.patch('time.sleep', lambda _: None)
@mock.patch('eventlet.sleep', lambda _: None)
@mock.patch('random.uniform', lambda _a, _b: 0)
@ddt.ddt
class CoordinatorTestCase(test.TestCase):

    def setUp(self):
        super(CoordinatorTestCase, self).setUp()
        self.get_coordinator = self.mock_object(tooz_coordination,
                                                'get_coordinator')
        self.heartbeat = self.mock_object(coordination.Coordinator,
                                          'heartbeat')

    @ddt.data(True, False)
    def test_coordinator_start_with_heartbeat(self, requires_beating):
        mock_start_heartbeat = mock.Mock(
            loopingcall, 'FixedIntervalLoopingCall').return_value
        self.mock_object(loopingcall, 'FixedIntervalLoopingCall',
                         mock.Mock(return_value=mock_start_heartbeat))
        crd = self.get_coordinator.return_value
        crd.requires_beating = requires_beating

        agent = coordination.Coordinator()
        agent.start()

        self.assertTrue(self.get_coordinator.called)
        self.assertTrue(crd.start.called)
        self.assertEqual(requires_beating, mock_start_heartbeat.start.called)

    def test_coordinator_stop(self):
        crd = self.get_coordinator.return_value

        agent = coordination.Coordinator()
        agent.start()

        self.assertIsNotNone(agent.coordinator)
        agent.stop()

        self.assertTrue(crd.stop.called)
        self.assertIsNone(agent.coordinator)

    def test_coordinator_lock(self):
        crd = self.get_coordinator.return_value
        crd.get_lock.side_effect = lambda n: MockToozLock(n)

        agent1 = coordination.Coordinator()
        agent1.start()
        agent2 = coordination.Coordinator()
        agent2.start()

        lock_string = 'lock'
        expected_lock = lock_string.encode('ascii')

        self.assertNotIn(expected_lock, MockToozLock.active_locks)
        with agent1.get_lock(lock_string):
            self.assertIn(expected_lock, MockToozLock.active_locks)
            self.assertRaises(Locked, agent1.get_lock(lock_string).acquire)
            self.assertRaises(Locked, agent2.get_lock(lock_string).acquire)
        self.assertNotIn(expected_lock, MockToozLock.active_locks)

    def test_coordinator_offline(self):
        crd = self.get_coordinator.return_value
        crd.start.side_effect = tooz_coordination.ToozConnectionError('err')

        agent = coordination.Coordinator()
        self.assertRaises(tooz_coordination.ToozError, agent.start)
        self.assertFalse(agent.started)
        self.assertFalse(self.heartbeat.called)

    def test_coordinator_reconnect(self):
        start_online = iter([True] + [False] * 5 + [True])
        heartbeat_online = iter((False, True, True))

        def raiser(cond):
            if not cond:
                raise tooz_coordination.ToozConnectionError('err')

        crd = self.get_coordinator.return_value
        crd.start.side_effect = lambda *_: raiser(next(start_online))
        crd.heartbeat.side_effect = lambda *_: raiser(next(heartbeat_online))

        agent = coordination.Coordinator()
        agent.start()

        self.assertRaises(tooz_coordination.ToozConnectionError,
                          agent._heartbeat)
        self.assertEqual(1, self.get_coordinator.call_count)
        agent._reconnect()
        self.assertEqual(7, self.get_coordinator.call_count)
        agent._heartbeat()


@mock.patch.object(coordination.LOCK_COORDINATOR, 'get_lock')
class CoordinationTestCase(test.TestCase):
    def test_lock(self, get_lock):
        with coordination.Lock('lock'):
            self.assertTrue(get_lock.called)

    def test_synchronized(self, get_lock):
        @coordination.synchronized('lock-{f_name}-{foo.val}-{bar[val]}')
        def func(foo, bar):
            pass

        foo = mock.Mock()
        foo.val = 7
        bar = mock.MagicMock()
        bar.__getitem__.return_value = 8
        func(foo, bar)
        get_lock.assert_called_with('lock-func-7-8')
