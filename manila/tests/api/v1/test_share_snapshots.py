# Copyright 2012 NetApp
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

import datetime

import webob

from manila.api.v1 import share_snapshots
from manila import exception
from manila.share import api as share_api
from manila import test
from manila.tests.api.contrib import stubs
from manila.tests.api import fakes


class ShareSnapshotApiTest(test.TestCase):
    """Share Snapshot Api Test."""

    def setUp(self):
        super(ShareSnapshotApiTest, self).setUp()
        self.controller = share_snapshots.ShareSnapshotsController()

        self.stubs.Set(share_api.API, 'get', stubs.stub_share_get)
        self.stubs.Set(share_api.API, 'get_all_snapshots',
                       stubs.stub_snapshot_get_all_by_project)
        self.stubs.Set(share_api.API, 'get_snapshot',
                       stubs.stub_snapshot_get)

        self.maxDiff = None

    def test_snapshot_create(self):
        self.stubs.Set(share_api.API, 'create_snapshot',
                       stubs.stub_snapshot_create)
        body = {
            'snapshot': {
                'share_id': 100,
                'force': False,
                'name': 'fake_share_name',
                'description': 'fake_share_description',
            }
        }
        req = fakes.HTTPRequest.blank('/snapshots')
        res_dict = self.controller.create(req, body)
        expected = {
            'snapshot': {
                'id': 200,
                'name': 'fake_share_name',
                'links': [
                    {
                        'href': 'http://localhost/v1/fake/snapshots/200',
                        'rel': 'self'
                    },
                    {
                        'href': 'http://localhost/fake/snapshots/200',
                        'rel': 'bookmark'
                    }
                ],
            }
        }
        self.assertEqual(res_dict, expected)

    def test_snapshot_create_no_body(self):
        body = {}
        req = fakes.HTTPRequest.blank('/snapshots')
        self.assertRaises(webob.exc.HTTPUnprocessableEntity,
                          self.controller.create,
                          req,
                          body)

    def test_snapshot_delete(self):
        self.stubs.Set(share_api.API, 'delete_snapshot',
                       stubs.stub_snapshot_delete)
        req = fakes.HTTPRequest.blank('/snapshots/200')
        resp = self.controller.delete(req, 200)
        self.assertEqual(resp.status_int, 202)

    def test_snapshot_delete_nofound(self):
        self.stubs.Set(share_api.API, 'get_snapshot',
                       stubs.stub_snapshot_get_notfound)
        req = fakes.HTTPRequest.blank('/snapshots/200')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.delete,
                          req,
                          200)

    def test_snapshot_show(self):
        req = fakes.HTTPRequest.blank('/snapshots/200')
        res_dict = self.controller.show(req, 200)
        expected = {
            'snapshot': {
                'id': 200,
                'share_id': 'fakeshareid',
                'share_size': 1,
                'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
                'status': 'fakesnapstatus',
                'name': 'displaysnapname',
                'size': 1,
                'description': 'displaysnapdesc',
                'share_proto': 'fakesnapproto',
                'export_location': 'fakesnaplocation',
                'links': [
                    {
                        'href': 'http://localhost/v1/fake/snapshots/200',
                        'rel': 'self',
                    },
                    {
                        'href': 'http://localhost/fake/snapshots/200',
                        'rel': 'bookmark',
                    },
                ],
            }
        }
        self.assertEqual(res_dict, expected)

    def test_snapshot_show_nofound(self):
        self.stubs.Set(share_api.API, 'get_snapshot',
                       stubs.stub_snapshot_get_notfound)
        req = fakes.HTTPRequest.blank('/snapshots/200')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.show,
                          req, '200')

    def test_snapshot_list_summary(self):
        self.stubs.Set(share_api.API, 'get_all_snapshots',
                       stubs.stub_snapshot_get_all_by_project)
        req = fakes.HTTPRequest.blank('/snapshots')
        res_dict = self.controller.index(req)
        expected = {
            'snapshots': [
                {
                    'name': 'displaysnapname',
                    'id': 2,
                    'links': [
                        {
                            'href': 'http://localhost/v1/fake/'
                                    'snapshots/2',
                            'rel': 'self'
                        },
                        {
                            'href': 'http://localhost/fake/snapshots/2',
                            'rel': 'bookmark'
                        }
                    ],
                }
            ]
        }
        self.assertEqual(res_dict, expected)

    def test_snapshot_list_detail(self):
        env = {'QUERY_STRING': 'name=Share+Test+Name'}
        req = fakes.HTTPRequest.blank('/shares/detail', environ=env)
        res_dict = self.controller.detail(req)
        expected = {
            'snapshots': [
                {
                    'id': 2,
                    'share_id': 'fakeshareid',
                    'share_size': 1,
                    'size': 1,
                    'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
                    'status': 'fakesnapstatus',
                    'name': 'displaysnapname',
                    'description': 'displaysnapdesc',
                    'share_proto': 'fakesnapproto',
                    'export_location': 'fakesnaplocation',
                    'links': [
                        {
                            'href': 'http://localhost/v1/fake/snapshots/'
                                    '2',
                            'rel': 'self',
                        },
                        {
                            'href': 'http://localhost/fake/snapshots/2',
                            'rel': 'bookmark',
                        },
                    ],
                },
            ]
        }
        self.assertEqual(res_dict, expected)
