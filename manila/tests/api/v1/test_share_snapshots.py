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

import ddt
import mock
import webob

from manila.api.v1 import share_snapshots
from manila.share import api as share_api
from manila import test
from manila.tests.api.contrib import stubs
from manila.tests.api import fakes


@ddt.ddt
class ShareSnapshotApiTest(test.TestCase):
    """Share Snapshot Api Test."""

    def setUp(self):
        super(ShareSnapshotApiTest, self).setUp()
        self.controller = share_snapshots.ShareSnapshotsController()

        self.mock_object(share_api.API, 'get', stubs.stub_share_get)
        self.mock_object(share_api.API, 'get_all_snapshots',
                         stubs.stub_snapshot_get_all_by_project)
        self.mock_object(share_api.API, 'get_snapshot',
                         stubs.stub_snapshot_get)
        self.mock_object(share_api.API, 'snapshot_update',
                         stubs.stub_snapshot_update)
        self.snp_example = {
            'share_id': 100,
            'size': 12,
            'force': False,
            'display_name': 'updated_share_name',
            'display_description': 'updated_share_description',
        }
        self.maxDiff = None

    @ddt.data('true', 'True', '<is> True', '1')
    def test_snapshot_create(self, snapshot_support):
        self.mock_object(share_api.API, 'create_snapshot',
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
                'share_id': 100,
                'share_size': 1,
                'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
                'status': 'fakesnapstatus',
                'name': 'fake_share_name',
                'size': 1,
                'description': 'fake_share_description',
                'share_proto': 'fakesnapproto',
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
        self.assertEqual(expected, res_dict)

    @ddt.data(0, False)
    def test_snapshot_create_no_support(self, snapshot_support):
        self.mock_object(share_api.API, 'create_snapshot')
        self.mock_object(
            share_api.API,
            'get',
            mock.Mock(return_value={'snapshot_support': snapshot_support}))
        body = {
            'snapshot': {
                'share_id': 100,
                'force': False,
                'name': 'fake_share_name',
                'description': 'fake_share_description',
            }
        }
        req = fakes.HTTPRequest.blank('/snapshots')

        self.assertRaises(
            webob.exc.HTTPUnprocessableEntity,
            self.controller.create, req, body)

        self.assertFalse(share_api.API.create_snapshot.called)

    def test_snapshot_create_no_body(self):
        body = {}
        req = fakes.HTTPRequest.blank('/snapshots')
        self.assertRaises(webob.exc.HTTPUnprocessableEntity,
                          self.controller.create,
                          req,
                          body)

    def test_snapshot_delete(self):
        self.mock_object(share_api.API, 'delete_snapshot',
                         stubs.stub_snapshot_delete)
        req = fakes.HTTPRequest.blank('/snapshots/200')
        resp = self.controller.delete(req, 200)
        self.assertEqual(202, resp.status_int)

    def test_snapshot_delete_nofound(self):
        self.mock_object(share_api.API, 'get_snapshot',
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
        self.assertEqual(expected, res_dict)

    def test_snapshot_show_nofound(self):
        self.mock_object(share_api.API, 'get_snapshot',
                         stubs.stub_snapshot_get_notfound)
        req = fakes.HTTPRequest.blank('/snapshots/200')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.show,
                          req, '200')

    def test_snapshot_list_summary(self):
        self.mock_object(share_api.API, 'get_all_snapshots',
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
        self.assertEqual(expected, res_dict)

    def _snapshot_list_summary_with_search_opts(self, use_admin_context):
        search_opts = {
            'name': 'fake_name',
            'status': 'fake_status',
            'share_id': 'fake_share_id',
            'sort_key': 'fake_sort_key',
            'sort_dir': 'fake_sort_dir',
            'offset': '1',
            'limit': '1',
        }
        # fake_key should be filtered for non-admin
        url = '/snapshots?fake_key=fake_value'
        for k, v in search_opts.items():
            url = url + '&' + k + '=' + v
        req = fakes.HTTPRequest.blank(url, use_admin_context=use_admin_context)

        snapshots = [
            {'id': 'id1', 'display_name': 'n1'},
            {'id': 'id2', 'display_name': 'n2'},
            {'id': 'id3', 'display_name': 'n3'},
        ]
        self.mock_object(share_api.API, 'get_all_snapshots',
                         mock.Mock(return_value=snapshots))

        result = self.controller.index(req)

        search_opts_expected = {
            'display_name': search_opts['name'],
            'status': search_opts['status'],
            'share_id': search_opts['share_id'],
        }
        if use_admin_context:
            search_opts_expected.update({'fake_key': 'fake_value'})
        share_api.API.get_all_snapshots.assert_called_once_with(
            req.environ['manila.context'],
            sort_key=search_opts['sort_key'],
            sort_dir=search_opts['sort_dir'],
            search_opts=search_opts_expected,
        )
        self.assertEqual(1, len(result['snapshots']))
        self.assertEqual(snapshots[1]['id'], result['snapshots'][0]['id'])
        self.assertEqual(
            snapshots[1]['display_name'], result['snapshots'][0]['name'])

    def test_snapshot_list_summary_with_search_opts_by_non_admin(self):
        self._snapshot_list_summary_with_search_opts(use_admin_context=False)

    def test_snapshot_list_summary_with_search_opts_by_admin(self):
        self._snapshot_list_summary_with_search_opts(use_admin_context=True)

    def _snapshot_list_detail_with_search_opts(self, use_admin_context):
        search_opts = {
            'name': 'fake_name',
            'status': 'fake_status',
            'share_id': 'fake_share_id',
            'sort_key': 'fake_sort_key',
            'sort_dir': 'fake_sort_dir',
            'limit': '1',
            'offset': '1',
        }
        # fake_key should be filtered for non-admin
        url = '/shares/detail?fake_key=fake_value'
        for k, v in search_opts.items():
            url = url + '&' + k + '=' + v
        req = fakes.HTTPRequest.blank(url, use_admin_context=use_admin_context)

        snapshots = [
            {'id': 'id1', 'display_name': 'n1'},
            {
                'id': 'id2',
                'display_name': 'n2',
                'status': 'fake_status',
                'share_id': 'fake_share_id',
            },
            {'id': 'id3', 'display_name': 'n3'},
        ]

        self.mock_object(share_api.API, 'get_all_snapshots',
                         mock.Mock(return_value=snapshots))

        result = self.controller.detail(req)

        search_opts_expected = {
            'display_name': search_opts['name'],
            'status': search_opts['status'],
            'share_id': search_opts['share_id'],
        }
        if use_admin_context:
            search_opts_expected.update({'fake_key': 'fake_value'})
        share_api.API.get_all_snapshots.assert_called_once_with(
            req.environ['manila.context'],
            sort_key=search_opts['sort_key'],
            sort_dir=search_opts['sort_dir'],
            search_opts=search_opts_expected,
        )
        self.assertEqual(1, len(result['snapshots']))
        self.assertEqual(snapshots[1]['id'], result['snapshots'][0]['id'])
        self.assertEqual(
            snapshots[1]['display_name'], result['snapshots'][0]['name'])
        self.assertEqual(
            snapshots[1]['status'], result['snapshots'][0]['status'])
        self.assertEqual(
            snapshots[1]['share_id'], result['snapshots'][0]['share_id'])

    def test_share_list_detail_with_search_opts_by_non_admin(self):
        self._snapshot_list_detail_with_search_opts(use_admin_context=False)

    def test_share_list_detail_with_search_opts_by_admin(self):
        self._snapshot_list_detail_with_search_opts(use_admin_context=True)

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

    def test_snapshot_updates_description(self):
        snp = self.snp_example
        body = {"snapshot": snp}

        req = fakes.HTTPRequest.blank('/snapshot/1')
        res_dict = self.controller.update(req, 1, body)
        self.assertEqual(res_dict['snapshot']["name"], snp["display_name"])

    def test_snapshot_updates_display_descr(self):
        snp = self.snp_example
        body = {"snapshot": snp}

        req = fakes.HTTPRequest.blank('/snapshot/1')
        res_dict = self.controller.update(req, 1, body)

        self.assertEqual(res_dict['snapshot']["description"],
                         snp["display_description"])

    def test_share_not_updates_size(self):
        snp = self.snp_example
        body = {"snapshot": snp}

        req = fakes.HTTPRequest.blank('/snapshot/1')
        res_dict = self.controller.update(req, 1, body)

        self.assertNotEqual(res_dict['snapshot']["size"], snp["size"])
