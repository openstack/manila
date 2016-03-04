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

import ddt
import mock
from oslo_serialization import jsonutils
import six
import webob

from manila.api.v1 import share_snapshots
from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila.share import api as share_api
from manila import test
from manila.tests.api.contrib import stubs
from manila.tests.api import fakes
from manila.tests import db_utils
from manila.tests import fake_share


@ddt.ddt
class ShareSnapshotAPITest(test.TestCase):
    """Share Snapshot API Test."""

    def setUp(self):
        super(self.__class__, self).setUp()
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

    def test_snapshot_show_status_none(self):
        return_snapshot = {
            'share_id': 100,
            'name': 'fake_share_name',
            'description': 'fake_share_description',
            'status': None,
        }
        self.mock_object(share_api.API, 'get_snapshot',
                         mock.Mock(return_value=return_snapshot))
        req = fakes.HTTPRequest.blank('/snapshots/200')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.show,
                          req, '200')

    @ddt.data('true', 'True', '<is> True', '1')
    def test_snapshot_create(self, snapshot_support):
        self.mock_object(share_api.API, 'create_snapshot',
                         stubs.stub_snapshot_create)
        body = {
            'snapshot': {
                'share_id': 'fakeshareid',
                'force': False,
                'name': 'displaysnapname',
                'description': 'displaysnapdesc',
            }
        }
        req = fakes.HTTPRequest.blank('/snapshots')

        res_dict = self.controller.create(req, body)

        expected = fake_share.expected_snapshot(id=200)

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
        expected = fake_share.expected_snapshot(id=200)
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
        search_opts = fake_share.search_opts()
        # fake_key should be filtered for non-admin
        url = '/snapshots?fake_key=fake_value'
        for k, v in search_opts.items():
            url = url + '&' + k + '=' + v
        req = fakes.HTTPRequest.blank(url, use_admin_context=use_admin_context)

        snapshots = [
            {'id': 'id1', 'display_name': 'n1',
             'status': 'fake_status', 'share_id': 'fake_share_id'},
            {'id': 'id2', 'display_name': 'n2',
             'status': 'fake_status', 'share_id': 'fake_share_id'},
            {'id': 'id3', 'display_name': 'n3',
             'status': 'fake_status', 'share_id': 'fake_share_id'},
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
        search_opts = fake_share.search_opts()
        # fake_key should be filtered for non-admin
        url = '/shares/detail?fake_key=fake_value'
        for k, v in search_opts.items():
            url = url + '&' + k + '=' + v
        req = fakes.HTTPRequest.blank(url, use_admin_context=use_admin_context)

        snapshots = [
            {
                'id': 'id1',
                'display_name': 'n1',
                'status': 'fake_status_other',
                'aggregate_status': 'fake_status',
                'share_id': 'fake_share_id',
            },
            {
                'id': 'id2',
                'display_name': 'n2',
                'status': 'fake_status',
                'aggregate_status': 'fake_status',
                'share_id': 'fake_share_id',
            },
            {
                'id': 'id3',
                'display_name': 'n3',
                'status': 'fake_status_other',
                'aggregate_status': 'fake_status',
                'share_id': 'fake_share_id',
            },
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

    def test_snapshot_list_detail_with_search_opts_by_non_admin(self):
        self._snapshot_list_detail_with_search_opts(use_admin_context=False)

    def test_snapshot_list_detail_with_search_opts_by_admin(self):
        self._snapshot_list_detail_with_search_opts(use_admin_context=True)

    def test_snapshot_list_detail(self):
        env = {'QUERY_STRING': 'name=Share+Test+Name'}
        req = fakes.HTTPRequest.blank('/shares/detail', environ=env)
        res_dict = self.controller.detail(req)
        expected_s = fake_share.expected_snapshot(id=2)
        expected = {'snapshots': [expected_s['snapshot']]}
        self.assertEqual(expected, res_dict)

    def test_snapshot_list_status_none(self):
        snapshots = [
            {
                'id': 2,
                'share_id': 'fakeshareid',
                'size': 1,
                'status': 'fakesnapstatus',
                'name': 'displaysnapname',
                'description': 'displaysnapdesc',
            },
            {
                'id': 3,
                'share_id': 'fakeshareid',
                'size': 1,
                'status': None,
                'name': 'displaysnapname',
                'description': 'displaysnapdesc',
            }
        ]
        self.mock_object(share_api.API, 'get_all_snapshots',
                         mock.Mock(return_value=snapshots))
        req = fakes.HTTPRequest.blank('/snapshots')
        result = self.controller.index(req)
        self.assertEqual(1, len(result['snapshots']))
        self.assertEqual(snapshots[0]['id'], result['snapshots'][0]['id'])

    def test_snapshot_updates_description(self):
        snp = self.snp_example
        body = {"snapshot": snp}

        req = fakes.HTTPRequest.blank('/snapshot/1')
        res_dict = self.controller.update(req, 1, body)
        self.assertEqual(snp["display_name"], res_dict['snapshot']["name"])

    def test_snapshot_updates_display_descr(self):
        snp = self.snp_example
        body = {"snapshot": snp}

        req = fakes.HTTPRequest.blank('/snapshot/1')
        res_dict = self.controller.update(req, 1, body)

        self.assertEqual(snp["display_description"],
                         res_dict['snapshot']["description"])

    def test_share_not_updates_size(self):
        snp = self.snp_example
        body = {"snapshot": snp}

        req = fakes.HTTPRequest.blank('/snapshot/1')
        res_dict = self.controller.update(req, 1, body)

        self.assertNotEqual(snp["size"], res_dict['snapshot']["size"])


@ddt.ddt
class ShareSnapshotAdminActionsAPITest(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.controller = share_snapshots.ShareSnapshotsController()
        self.flags(rpc_backend='manila.openstack.common.rpc.impl_fake')
        self.admin_context = context.RequestContext('admin', 'fake', True)
        self.member_context = context.RequestContext('fake', 'fake')

    def _get_context(self, role):
        return getattr(self, '%s_context' % role)

    def _setup_snapshot_data(self, snapshot=None):
        if snapshot is None:
            share = db_utils.create_share()
            snapshot = db_utils.create_snapshot(
                status=constants.STATUS_AVAILABLE, share_id=share['id'])
        req = fakes.HTTPRequest.blank('/v1/fake/snapshots/%s/action' %
                                      snapshot['id'])
        return snapshot, req

    def _reset_status(self, ctxt, model, req, db_access_method,
                      valid_code, valid_status=None, body=None):
        action_name = 'os-reset_status'
        if body is None:
            body = {action_name: {'status': constants.STATUS_ERROR}}
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.body = six.b(jsonutils.dumps(body))
        req.environ['manila.context'] = ctxt

        resp = req.get_response(fakes.app())

        # validate response code and model status
        self.assertEqual(valid_code, resp.status_int)

        if valid_code == 404:
            self.assertRaises(exception.NotFound,
                              db_access_method,
                              ctxt,
                              model['id'])
        else:
            actual_model = db_access_method(ctxt, model['id'])
            self.assertEqual(valid_status, actual_model['status'])

    @ddt.data(*fakes.fixture_reset_status_with_different_roles_v1)
    @ddt.unpack
    def test_snapshot_reset_status_with_different_roles(self, role, valid_code,
                                                        valid_status):
        ctxt = self._get_context(role)
        snapshot, req = self._setup_snapshot_data()

        self._reset_status(ctxt, snapshot, req, db.share_snapshot_get,
                           valid_code, valid_status)

    @ddt.data(
        {'os-reset_status': {'x-status': 'bad'}},
        {'os-reset_status': {'status': 'invalid'}},
    )
    def test_snapshot_invalid_reset_status_body(self, body):
        snapshot, req = self._setup_snapshot_data()

        self._reset_status(self.admin_context, snapshot, req,
                           db.share_snapshot_get, 400,
                           constants.STATUS_AVAILABLE, body)

    def _force_delete(self, ctxt, model, req, db_access_method, valid_code):
        action_name = 'os-force_delete'
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.body = six.b(jsonutils.dumps({action_name: {}}))
        req.environ['manila.context'] = ctxt

        resp = req.get_response(fakes.app())

        # Validate response
        self.assertEqual(valid_code, resp.status_int)

    @ddt.data(
        {'role': 'admin', 'resp_code': 202},
        {'role': 'member', 'resp_code': 403},
    )
    @ddt.unpack
    def test_snapshot_force_delete_with_different_roles(self, role, resp_code):
        ctxt = self._get_context(role)
        snapshot, req = self._setup_snapshot_data()

        self._force_delete(ctxt, snapshot, req, db.share_snapshot_get,
                           resp_code)

    def test_snapshot_force_delete_missing(self):
        ctxt = self._get_context('admin')
        snapshot, req = self._setup_snapshot_data(snapshot={'id': 'fake'})

        self._force_delete(ctxt, snapshot, req, db.share_snapshot_get, 404)
