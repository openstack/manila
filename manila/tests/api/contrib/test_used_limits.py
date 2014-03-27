# Copyright 2014 Mirantis Inc.
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

import mock

from manila.api.contrib import used_limits
from manila.api.openstack import wsgi
from manila import quota
from manila import test
from manila.tests.api import fakes


class FakeRequest(object):
    def __init__(self, context):
        self.environ = {'manila.context': context}


class UsedLimitsTestCase(test.TestCase):

    def setUp(self):
        """Run before each test."""
        super(UsedLimitsTestCase, self).setUp()
        self.controller = used_limits.UsedLimitsController()

    def test_used_limits(self):
        fake_req = FakeRequest(fakes.FakeRequestContext('fake', 'fake'))
        obj = {"limits": {"rate": [], "absolute": {}}}
        res = wsgi.ResponseObject(obj)
        quota_map = {
            'totalSharesUsed': 'shares',
            'totalSnapshotsUsed': 'snapshots',
            'totalShareNetworksUsed': 'share_networks',
            'totalGigabytesUsed': 'gigabytes',
        }
        limits = {}
        for display_name, q in quota_map.iteritems():
            limits[q] = {'limit': 2, 'in_use': 1, }

        def stub_get_project_quotas(*args, **kwargs):
            return limits

        with mock.patch.object(quota.QUOTAS, 'get_project_quotas',
                               mock.Mock(side_effect=stub_get_project_quotas)):

            self.controller.index(fake_req, res)
            abs_limits = res.obj['limits']['absolute']
            for used_limit, value in abs_limits.iteritems():
                self.assertEqual(value,
                                 limits[quota_map[used_limit]]['in_use'])
