# Copyright (c) 2021 SAP.
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
from unittest import mock

from manila import exception
from manila.scheduler.filters import affinity
from manila import test
from manila.tests.scheduler import fakes


fake_hosts = [
    fakes.FakeHostState('host1', {}),
    fakes.FakeHostState('host2', {}),
    fakes.FakeHostState('host3', {}),
    ]

fake_shares_1 = {
    'abb6e0ac-7c3e-4ce0-8a69-5a166d246882': {
        'instances': [
            {'host': fake_hosts[0].host}
            ]
        },
    '4de0cc74-450c-4468-8159-52128cf03407': {
        'instances': [
            {'host': fake_hosts[0].host}
            ]
        },
    }

fake_shares_2 = {
    'c920fb61-e250-4c3c-a25d-1fdd9ca7cbc3': {
        'instances': [
            {'host': fake_hosts[1].host}
            ]
        },
    }

fake_shares_3 = {
    '3923bebf-9825-4a66-971e-6092a9fe2dbb': {
        'instances': [
            {'host': fake_hosts[2].host}
            ]
        },
    }


@ddt.ddt
class AffinityFilterTestCase(test.TestCase):
    """Test case for AffinityFilter."""

    def setUp(self):
        super(AffinityFilterTestCase, self).setUp()
        self.filter = affinity.AffinityFilter()
        self.anti_filter = affinity.AntiAffinityFilter()

    def _make_filter_hints(self, *hints):
        return {
            'context': None,
            'scheduler_hints': {'same_host': ','.join(list(hints))},
        }

    def _make_anti_filter_hints(self, *hints):
        return {
            'context': None,
            'scheduler_hints': {'different_host': ','.join(list(hints))},
        }

    def _fake_get(self, context, uuid):
        if uuid in fake_shares_1.keys():
            return fake_shares_1[uuid]
        if uuid in fake_shares_2.keys():
            return fake_shares_2[uuid]
        if uuid in fake_shares_3.keys():
            return fake_shares_3[uuid]
        raise exception.ShareNotFound(uuid)

    @ddt.data('b5c207da-ac0b-43b0-8691-c6c9e860199d')
    @mock.patch('manila.share.api.API.get')
    def test_affinity_share_not_found(self, unknown_id, mock_share_get):
        mock_share_get.side_effect = self._fake_get
        self.assertRaises(exception.ShareNotFound,
                          self.filter._validate,
                          self._make_filter_hints(unknown_id))

    @ddt.data(
        {'context': None},
        {'context': None, 'scheduler_hints': None},
        {'context': None, 'scheduler_hints': {}},
    )
    def test_affinity_scheduler_hint_not_set(self, hints):
        self.assertRaises(affinity.SchedulerHintsNotSet,
                          self.filter._validate, hints)

    @ mock.patch('manila.share.api.API.get')
    def test_affinity_filter(self, mock_share_get):
        mock_share_get.side_effect = self._fake_get

        share_ids = fake_shares_1.keys()
        hints = self._make_filter_hints(*share_ids)
        valid_hosts = self.filter.filter_all(fake_hosts, hints)
        valid_hosts = [h.host for h in valid_hosts]

        self.assertIn('host1', valid_hosts)
        self.assertNotIn('host2', valid_hosts)
        self.assertNotIn('host3', valid_hosts)

    @ mock.patch('manila.share.api.API.get')
    def test_anti_affinity_filter(self, mock_share_get):
        mock_share_get.side_effect = self._fake_get

        share_ids = fake_shares_2.keys()
        hints = self._make_anti_filter_hints(*share_ids)
        valid_hosts = self.anti_filter.filter_all(fake_hosts, hints)
        valid_hosts = [h.host for h in valid_hosts]

        self.assertIn('host1', valid_hosts)
        self.assertIn('host3', valid_hosts)
        self.assertNotIn('host2', valid_hosts)
