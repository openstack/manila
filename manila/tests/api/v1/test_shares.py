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

import copy
import datetime

import mock
import webob

from manila.api import common
from manila.api.v1 import shares
from manila import context
from manila import exception
from manila.share import api as share_api
from manila import test
from manila.tests.api.contrib import stubs
from manila.tests.api import fakes


class ShareApiTest(test.TestCase):
    """Share Api Test."""
    def setUp(self):
        super(ShareApiTest, self).setUp()
        self.controller = shares.ShareController()
        self.stubs.Set(share_api.API, 'get_all',
                       stubs.stub_get_all_shares)
        self.stubs.Set(share_api.API, 'get',
                       stubs.stub_share_get)
        self.stubs.Set(share_api.API, 'update', stubs.stub_share_update)
        self.stubs.Set(share_api.API, 'delete', stubs.stub_share_delete)
        self.stubs.Set(share_api.API, 'get_snapshot', stubs.stub_snapshot_get)
        self.maxDiff = None
        self.shr_example = {
            "size": 100,
            "name": "Share Test Name",
            "display_name": "Updated Desc",
            "display_description": "Updated Display Desc",
        }

    def _get_expected_share_detailed_response(self, values=None):
        share = {
            'id': '1',
            'name': 'displayname',
            'availability_zone': 'fakeaz',
            'description': 'displaydesc',
            'export_location': 'fake_location',
            'project_id': 'fakeproject',
            'host': 'fakehost',
            'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
            'share_proto': 'FAKEPROTO',
            'metadata': {},
            'size': 1,
            'snapshot_id': '2',
            'share_network_id': None,
            'status': 'fakestatus',
            'volume_type': '1',
            'links': [
                {
                    'href': 'http://localhost/v1/fake/shares/1',
                    'rel': 'self'
                },
                {
                    'href': 'http://localhost/fake/shares/1',
                    'rel': 'bookmark'
                }
            ],
        }
        if values:
            share.update(values)
        if share.get('share_proto'):
            share['share_proto'] = share['share_proto'].upper()
        return {'share': share}

    def test_share_create(self):
        shr = {
            "size": 100,
            "name": "Share Test Name",
            "description": "Share Test Desc",
            "share_proto": "fakeproto",
            "availability_zone": "zone1:host1"
        }
        create_mock = mock.Mock(return_value=stubs.stub_share('1',
                                display_name=shr['name'],
                                display_description=shr['description'],
                                size=100,
                                share_proto=shr['share_proto'].upper(),
                                availability_zone=shr['availability_zone']))
        self.stubs.Set(share_api.API, 'create', create_mock)

        body = {"share": copy.deepcopy(shr)}
        req = fakes.HTTPRequest.blank('/shares')
        res_dict = self.controller.create(req, body)

        expected = self._get_expected_share_detailed_response(shr)
        self.assertEqual(expected, res_dict)

    def test_share_create_with_share_net(self):
        shr = {
            "size": 100,
            "name": "Share Test Name",
            "description": "Share Test Desc",
            "share_proto": "fakeproto",
            "availability_zone": "zone1:host1",
            "share_network_id": "fakenetid"
        }
        create_mock = mock.Mock(return_value=stubs.stub_share('1',
                                display_name=shr['name'],
                                display_description=shr['description'],
                                size=shr['size'],
                                share_proto=shr['share_proto'].upper(),
                                availability_zone=shr['availability_zone'],
                                share_network_id=shr['share_network_id']))
        self.stubs.Set(share_api.API, 'create', create_mock)
        self.stubs.Set(share_api.API, 'get_share_network', mock.Mock(
            return_value={'id': 'fakenetid'}))

        body = {"share": copy.deepcopy(shr)}
        req = fakes.HTTPRequest.blank('/shares')
        res_dict = self.controller.create(req, body)

        expected = self._get_expected_share_detailed_response(shr)
        self.assertEqual(expected, res_dict)
        self.assertEqual(create_mock.call_args[1]['share_network_id'],
                         "fakenetid")

    def test_share_create_from_snapshot_without_share_net_no_parent(self):
        shr = {
            "size": 100,
            "name": "Share Test Name",
            "description": "Share Test Desc",
            "share_proto": "fakeproto",
            "availability_zone": "zone1:host1",
            "snapshot_id": 333,
            "share_network_id": None,
        }
        create_mock = mock.Mock(return_value=stubs.stub_share('1',
                                display_name=shr['name'],
                                display_description=shr['description'],
                                size=shr['size'],
                                share_proto=shr['share_proto'].upper(),
                                availability_zone=shr['availability_zone'],
                                snapshot_id=shr['snapshot_id'],
                                share_network_id=shr['share_network_id']))
        self.stubs.Set(share_api.API, 'create', create_mock)
        body = {"share": copy.deepcopy(shr)}
        req = fakes.HTTPRequest.blank('/shares')
        res_dict = self.controller.create(req, body)
        expected = self._get_expected_share_detailed_response(shr)
        self.assertEqual(expected, res_dict)

    def test_share_create_from_snapshot_without_share_net_parent_exists(self):
        shr = {
            "size": 100,
            "name": "Share Test Name",
            "description": "Share Test Desc",
            "share_proto": "fakeproto",
            "availability_zone": "zone1:host1",
            "snapshot_id": 333,
            "share_network_id": None,
        }
        parent_share_net = 444
        create_mock = mock.Mock(return_value=stubs.stub_share('1',
                                display_name=shr['name'],
                                display_description=shr['description'],
                                size=shr['size'],
                                share_proto=shr['share_proto'].upper(),
                                availability_zone=shr['availability_zone'],
                                snapshot_id=shr['snapshot_id'],
                                share_network_id=shr['share_network_id']))
        self.stubs.Set(share_api.API, 'create', create_mock)
        self.stubs.Set(share_api.API, 'get_snapshot', stubs.stub_snapshot_get)
        self.stubs.Set(share_api.API, 'get', mock.Mock(
            return_value={'share_network_id': parent_share_net}))
        self.stubs.Set(share_api.API, 'get_share_network', mock.Mock(
            return_value={'id': parent_share_net}))

        body = {"share": copy.deepcopy(shr)}
        req = fakes.HTTPRequest.blank('/shares')
        res_dict = self.controller.create(req, body)
        expected = self._get_expected_share_detailed_response(shr)
        self.assertEqual(expected, res_dict)
        self.assertEqual(create_mock.call_args[1]['share_network_id'],
                         parent_share_net)

    def test_share_create_from_snapshot_with_share_net_equals_parent(self):
        parent_share_net = 444
        shr = {
            "size": 100,
            "name": "Share Test Name",
            "description": "Share Test Desc",
            "share_proto": "fakeproto",
            "availability_zone": "zone1:host1",
            "snapshot_id": 333,
            "share_network_id": parent_share_net
        }
        create_mock = mock.Mock(return_value=stubs.stub_share('1',
                                display_name=shr['name'],
                                display_description=shr['description'],
                                size=shr['size'],
                                share_proto=shr['share_proto'].upper(),
                                availability_zone=shr['availability_zone'],
                                snapshot_id=shr['snapshot_id'],
                                share_network_id=shr['share_network_id']))
        self.stubs.Set(share_api.API, 'create', create_mock)
        self.stubs.Set(share_api.API, 'get_snapshot', stubs.stub_snapshot_get)
        self.stubs.Set(share_api.API, 'get', mock.Mock(
            return_value={'share_network_id': parent_share_net}))
        self.stubs.Set(share_api.API, 'get_share_network', mock.Mock(
            return_value={'id': parent_share_net}))

        body = {"share": copy.deepcopy(shr)}
        req = fakes.HTTPRequest.blank('/shares')
        res_dict = self.controller.create(req, body)
        expected = self._get_expected_share_detailed_response(shr)
        self.assertEqual(res_dict, expected)
        self.assertEqual(create_mock.call_args[1]['share_network_id'],
                         parent_share_net)

    def test_share_create_from_snapshot_invalid_share_net(self):
        self.stubs.Set(share_api.API, 'create', mock.Mock())
        shr = {
            "size": 100,
            "name": "Share Test Name",
            "description": "Share Test Desc",
            "share_proto": "fakeproto",
            "availability_zone": "zone1:host1",
            "snapshot_id": 333,
            "share_network_id": 1234
        }
        body = {"share": shr}
        req = fakes.HTTPRequest.blank('/shares')
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.create,
                          req,
                          body)

    def test_share_creation_fails_with_bad_size(self):
        shr = {"size": '',
               "name": "Share Test Name",
               "description": "Share Test Desc",
               "share_proto": "fakeproto",
               "availability_zone": "zone1:host1"}
        body = {"share": shr}
        req = fakes.HTTPRequest.blank('/shares')
        self.assertRaises(exception.InvalidInput,
                          self.controller.create,
                          req,
                          body)

    def test_share_create_no_body(self):
        body = {}
        req = fakes.HTTPRequest.blank('/shares')
        self.assertRaises(webob.exc.HTTPUnprocessableEntity,
                          self.controller.create,
                          req,
                          body)

    def test_share_show(self):
        req = fakes.HTTPRequest.blank('/shares/1')
        res_dict = self.controller.show(req, '1')
        expected = self._get_expected_share_detailed_response()
        self.assertEqual(expected, res_dict)

    def test_share_show_no_share(self):
        self.stubs.Set(share_api.API, 'get',
                       stubs.stub_share_get_notfound)
        req = fakes.HTTPRequest.blank('/shares/1')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.show,
                          req, '1')

    def test_share_delete(self):
        req = fakes.HTTPRequest.blank('/shares/1')
        resp = self.controller.delete(req, 1)
        self.assertEqual(resp.status_int, 202)

    def test_share_updates_description(self):
        shr = self.shr_example
        body = {"share": shr}

        req = fakes.HTTPRequest.blank('/share/1')
        res_dict = self.controller.update(req, 1, body)
        self.assertEqual(res_dict['share']["name"], shr["display_name"])

    def test_share_updates_display_descr(self):
        shr = self.shr_example
        body = {"share": shr}

        req = fakes.HTTPRequest.blank('/share/1')
        res_dict = self.controller.update(req, 1, body)

        self.assertEqual(res_dict['share']["description"],
                         shr["display_description"])

    def test_share_not_updates_size(self):
        shr = self.shr_example
        body = {"share": shr}

        req = fakes.HTTPRequest.blank('/share/1')
        res_dict = self.controller.update(req, 1, body)

        self.assertNotEqual(res_dict['share']["size"], shr["size"])

    def test_share_delete_no_share(self):
        self.stubs.Set(share_api.API, 'get',
                       stubs.stub_share_get_notfound)
        req = fakes.HTTPRequest.blank('/shares/1')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.delete,
                          req,
                          1)

    def test_share_list_summary_with_search_opts_by_non_admin(self):
        # fake_key should be filtered for non-admin
        fake_key = 'fake_value'
        name = 'fake_name'
        status = 'available'
        share_server_id = 'fake_share_server_id'
        req = fakes.HTTPRequest.blank(
            '/shares?fake_key=%s&name=%s&share_server_id=%s&'
            'status=%s' % (fake_key, name, share_server_id, status),
            use_admin_context=False,
        )
        self.stubs.Set(share_api.API, 'get_all', mock.Mock(return_value=[]))
        self.controller.index(req)
        share_api.API.get_all.assert_called_once_with(
            req.environ['manila.context'],
            search_opts={
                'display_name': name,
                'share_server_id': share_server_id,
                'status': status,
            },
        )

    def test_share_list_summary_with_search_opts_by_admin(self):
        # none of search_opts should be filtered for admin
        fake_key = 'fake_value'
        name = 'fake_name'
        status = 'available'
        share_server_id = 'fake_share_server_id'
        req = fakes.HTTPRequest.blank(
            '/shares?fake_key=%s&name=%s&share_server_id=%s&'
            'status=%s' % (fake_key, name, share_server_id, status),
            use_admin_context=True,
        )
        self.stubs.Set(share_api.API, 'get_all', mock.Mock(return_value=[]))
        self.controller.index(req)
        share_api.API.get_all.assert_called_once_with(
            req.environ['manila.context'],
            search_opts={
                'display_name': name,
                'fake_key': fake_key,
                'share_server_id': share_server_id,
                'status': status,
            },
        )

    def test_share_list_summary(self):
        self.stubs.Set(share_api.API, 'get_all',
                       stubs.stub_share_get_all_by_project)
        req = fakes.HTTPRequest.blank('/shares')
        res_dict = self.controller.index(req)
        expected = {
            'shares': [
                {
                    'name': 'displayname',
                    'id': '1',
                    'links': [
                        {
                            'href': 'http://localhost/v1/fake/shares/1',
                            'rel': 'self'
                        },
                        {
                            'href': 'http://localhost/fake/shares/1',
                            'rel': 'bookmark'
                        }
                    ],
                }
            ]
        }
        self.assertEqual(res_dict, expected)

    def test_share_list_detail_with_search_opts_by_non_admin(self):
        # fake_key should be filtered for non-admin
        fake_key = 'fake_value'
        name = 'fake_name'
        status = 'available'
        share_server_id = 'fake_share_server_id'
        req = fakes.HTTPRequest.blank(
            '/shares?fake_key=%s&name=%s&share_server_id=%s&'
            'status=%s' % (fake_key, name, share_server_id, status),
            use_admin_context=False,
        )
        self.stubs.Set(share_api.API, 'get_all', mock.Mock(return_value=[]))
        self.controller.detail(req)
        share_api.API.get_all.assert_called_once_with(
            req.environ['manila.context'],
            search_opts={
                'display_name': name,
                'share_server_id': share_server_id,
                'status': status,
            },
        )

    def test_share_list_detail_with_search_opts_by_admin(self):
        # none of search_opts should be filtered for admin
        fake_key = 'fake_value'
        name = 'fake_name'
        status = 'available'
        share_server_id = 'fake_share_server_id'
        req = fakes.HTTPRequest.blank(
            '/shares?fake_key=%s&name=%s&share_server_id=%s&'
            'status=%s' % (fake_key, name, share_server_id, status),
            use_admin_context=True,
        )
        self.stubs.Set(share_api.API, 'get_all', mock.Mock(return_value=[]))
        self.controller.detail(req)
        share_api.API.get_all.assert_called_once_with(
            req.environ['manila.context'],
            search_opts={
                'display_name': name,
                'fake_key': fake_key,
                'share_server_id': share_server_id,
                'status': status,
            },
        )

    def test_share_list_detail(self):
        self.stubs.Set(share_api.API, 'get_all',
                       stubs.stub_share_get_all_by_project)
        env = {'QUERY_STRING': 'name=Share+Test+Name'}
        req = fakes.HTTPRequest.blank('/shares/detail', environ=env)
        res_dict = self.controller.detail(req)
        expected = {
            'shares': [
                {
                    'status': 'fakestatus',
                    'description': 'displaydesc',
                    'export_location': 'fake_location',
                    'availability_zone': 'fakeaz',
                    'name': 'displayname',
                    'share_proto': 'FAKEPROTO',
                    'metadata': {},
                    'project_id': 'fakeproject',
                    'host': 'fakehost',
                    'id': '1',
                    'snapshot_id': '2',
                    'share_network_id': None,
                    'created_at': datetime.datetime(1, 1, 1, 1, 1, 1),
                    'size': 1,
                    'volume_type': '1',
                    'links': [
                        {
                            'href': 'http://localhost/v1/fake/shares/1',
                            'rel': 'self'
                        },
                        {
                            'href': 'http://localhost/fake/shares/1',
                            'rel': 'bookmark'
                        }
                    ],
                }
            ]
        }
        self.assertEqual(expected, res_dict)

    def test_remove_invalid_options(self):
        ctx = context.RequestContext('fakeuser', 'fakeproject', is_admin=False)
        search_opts = {'a': 'a', 'b': 'b', 'c': 'c', 'd': 'd'}
        expected_opts = {'a': 'a', 'c': 'c'}
        allowed_opts = ['a', 'c']
        common.remove_invalid_options(ctx, search_opts, allowed_opts)
        self.assertEqual(search_opts, expected_opts)

    def test_remove_invalid_options_admin(self):
        ctx = context.RequestContext('fakeuser', 'fakeproject', is_admin=True)
        search_opts = {'a': 'a', 'b': 'b', 'c': 'c', 'd': 'd'}
        expected_opts = {'a': 'a', 'b': 'b', 'c': 'c', 'd': 'd'}
        allowed_opts = ['a', 'c']
        common.remove_invalid_options(ctx, search_opts, allowed_opts)
        self.assertEqual(search_opts, expected_opts)
