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

from manila.exception import NotFound
from manila.scheduler.filters import affinity
from manila import test
from manila.tests.scheduler import fakes


fake_hosts = [
    fakes.FakeHostState('host1', {}),
    fakes.FakeHostState('host2', {}),
    fakes.FakeHostState('host3', {}),
    ]

fake_shares = {
    'abb6e0ac-7c3e-4ce0-8a69-5a166d246882': {
        'instances': [
            {'host': fake_hosts[0].host}
            ]
        },
    '4de0cc74-450c-4468-8159-52128cf03407': {
        'instances': [
            {'host': fake_hosts[1].host}
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
            'scheduler_hints': {'affinity_filter': list(hints)},
        }

    def _make_anti_filter_hints(self, *hints):
        return {
            'context': None,
            'scheduler_hints': {'anti_affinity_filter': list(hints)},
        }

    def _fake_get(self, context, uuid):
        if uuid in fake_shares.keys():
            return fake_shares[uuid]
        raise NotFound

    @ddt.data(
        {'affinity_filter': 'uuid1'},
        {'affinity_filter': ('uuid1', 'uuid2')},
        {'affinity_filter': ['uuid1', 'uuid2']},
    )
    def test_affinity_invalid_uuid(self, hints):
        filter_properties = {'context': None, 'scheduler_hints': hints}
        self.assertRaises(affinity.InvalidUUIDError,
                          self.filter._validate, filter_properties)

    @ddt.data('b5c207da-ac0b-43b0-8691-c6c9e860199d')
    @mock.patch('manila.share.api.API.get')
    def test_affinity_share_not_found(self, unknown_id, mock_share_get):
        mock_share_get.side_effect = self._fake_get
        self.assertRaises(affinity.ShareNotFoundError,
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

        share_ids = fake_shares.keys()
        hints = self._make_filter_hints(*share_ids)
        valid_hosts = self.filter.filter_all(fake_hosts, hints)
        valid_hosts = [h.host for h in valid_hosts]

        self.assertIn('host1', valid_hosts)
        self.assertIn('host2', valid_hosts)
        self.assertNotIn('host3', valid_hosts)

    @ mock.patch('manila.share.api.API.get')
    def test_anti_affinity_filter(self, mock_share_get):
        mock_share_get.side_effect = self._fake_get

        share_ids = fake_shares.keys()
        hints = self._make_anti_filter_hints(*share_ids)
        valid_hosts = self.anti_filter.filter_all(fake_hosts, hints)
        valid_hosts = [h.host for h in valid_hosts]

        self.assertNotIn('host1', valid_hosts)
        self.assertNotIn('host2', valid_hosts)
        self.assertIn('host3', valid_hosts)
