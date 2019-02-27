# Copyright 2015 EMC Corporation
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

from manila.api.openstack import api_version_request as api_version
from manila.api.v2 import share_snapshots
from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila import policy
from manila.share import api as share_api
from manila import test
from manila.tests.api.contrib import stubs
from manila.tests.api import fakes
from manila.tests import db_utils
from manila.tests import fake_share
from manila import utils

MIN_MANAGE_SNAPSHOT_API_VERSION = '2.12'


def get_fake_manage_body(share_id=None, provider_location=None,
                         driver_options=None, **kwargs):
    fake_snapshot = {
        'share_id': share_id,
        'provider_location': provider_location,
        'driver_options': driver_options,
        'user_id': 'fake_user_id',
        'project_id': 'fake_project_id',
    }
    fake_snapshot.update(kwargs)
    return {'snapshot': fake_snapshot}


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
            'display_name': 'updated_snapshot_name',
            'display_description': 'updated_snapshot_description',
        }

    @ddt.data('1.0', '2.16', '2.17')
    def test_snapshot_create(self, version):
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
        req = fakes.HTTPRequest.blank('/snapshots', version=version)

        res_dict = self.controller.create(req, body)

        expected = fake_share.expected_snapshot(version=version, id=200)

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

    @ddt.data('2.0', '2.16', '2.17')
    def test_snapshot_show(self, version):
        req = fakes.HTTPRequest.blank('/snapshots/200', version=version)
        expected = fake_share.expected_snapshot(version=version, id=200)

        res_dict = self.controller.show(req, 200)

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

    def _snapshot_list_summary_with_search_opts(self, version,
                                                use_admin_context):
        search_opts = fake_share.search_opts()
        if (api_version.APIVersionRequest(version) >=
                api_version.APIVersionRequest('2.36')):
            search_opts.pop('name')
            search_opts['display_name~'] = 'fake_name'
        # fake_key should be filtered for non-admin
        url = '/snapshots?fake_key=fake_value'
        for k, v in search_opts.items():
            url = url + '&' + k + '=' + v
        req = fakes.HTTPRequest.blank(
            url, use_admin_context=use_admin_context, version=version)

        snapshots = [
            {'id': 'id1', 'display_name': 'n1', 'status': 'fake_status', },
            {'id': 'id2', 'display_name': 'n2', 'status': 'fake_status', },
            {'id': 'id3', 'display_name': 'n3', 'status': 'fake_status', },
        ]
        self.mock_object(share_api.API, 'get_all_snapshots',
                         mock.Mock(return_value=snapshots))

        result = self.controller.index(req)

        search_opts_expected = {
            'status': search_opts['status'],
            'share_id': search_opts['share_id'],
        }
        if (api_version.APIVersionRequest(version) >=
                api_version.APIVersionRequest('2.36')):
            search_opts_expected['display_name~'] = 'fake_name'
        else:
            search_opts_expected['display_name'] = search_opts['name']
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

    @ddt.data({'version': '2.35', 'use_admin_context': True},
              {'version': '2.36', 'use_admin_context': True},
              {'version': '2.35', 'use_admin_context': False},
              {'version': '2.36', 'use_admin_context': False})
    @ddt.unpack
    def test_snapshot_list_summary_with_search_opts(self, version,
                                                    use_admin_context):
        self._snapshot_list_summary_with_search_opts(
            version=version, use_admin_context=use_admin_context)

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
                'status': 'fake_status',
                'aggregate_status': 'fake_status',
            },
            {
                'id': 'id2',
                'display_name': 'n2',
                'status': 'someotherstatus',
                'aggregate_status': 'fake_status',
                'share_id': 'fake_share_id',
            },
            {
                'id': 'id3',
                'display_name': 'n3',
                'status': 'fake_status',
                'aggregate_status': 'fake_status',
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
            snapshots[1]['aggregate_status'], result['snapshots'][0]['status'])
        self.assertEqual(
            snapshots[1]['share_id'], result['snapshots'][0]['share_id'])

    def test_snapshot_list_detail_with_search_opts_by_non_admin(self):
        self._snapshot_list_detail_with_search_opts(use_admin_context=False)

    def test_snapshot_list_detail_with_search_opts_by_admin(self):
        self._snapshot_list_detail_with_search_opts(use_admin_context=True)

    @ddt.data('2.0', '2.16', '2.17')
    def test_snapshot_list_detail(self, version):
        env = {'QUERY_STRING': 'name=Share+Test+Name'}
        req = fakes.HTTPRequest.blank('/snapshots/detail', environ=env,
                                      version=version)
        expected_s = fake_share.expected_snapshot(version=version, id=2)
        expected = {'snapshots': [expected_s['snapshot']]}

        res_dict = self.controller.detail(req)

        self.assertEqual(expected, res_dict)

    @ddt.data('2.0', '2.16', '2.17')
    def test_snapshot_updates_display_name_and_description(self, version):
        snp = self.snp_example
        body = {"snapshot": snp}
        req = fakes.HTTPRequest.blank('/snapshot/1', version=version)

        res_dict = self.controller.update(req, 1, body)

        self.assertEqual(snp["display_name"], res_dict['snapshot']["name"])

        if (api_version.APIVersionRequest(version) <=
                api_version.APIVersionRequest('2.16')):
            self.assertNotIn('user_id', res_dict['snapshot'])
            self.assertNotIn('project_id', res_dict['snapshot'])
        else:
            self.assertIn('user_id', res_dict['snapshot'])
            self.assertIn('project_id', res_dict['snapshot'])

    def test_share_update_invalid_key(self):
        snp = self.snp_example
        body = {"snapshot": snp}

        req = fakes.HTTPRequest.blank('/snapshot/1')
        res_dict = self.controller.update(req, 1, body)

        self.assertNotEqual(snp["size"], res_dict['snapshot']["size"])

    def test_access_list(self):
        share = db_utils.create_share(mount_snapshot_support=True)
        snapshot = db_utils.create_snapshot(
            status=constants.STATUS_AVAILABLE, share_id=share['id'])

        expected = []

        self.mock_object(share_api.API, 'get',
                         mock.Mock(return_value=share))
        self.mock_object(share_api.API, 'get_snapshot',
                         mock.Mock(return_value=snapshot))
        self.mock_object(share_api.API, 'snapshot_access_get_all',
                         mock.Mock(return_value=expected))

        id = 'fake_snap_id'
        req = fakes.HTTPRequest.blank('/snapshots/%s/action' % id,
                                      version='2.32')

        actual = self.controller.access_list(req, id)

        self.assertEqual(expected, actual['snapshot_access_list'])

    @ddt.data(('1.1.1.1', '2.32'),
              ('1.1.1.1', '2.38'),
              ('1001::1001', '2.38'))
    @ddt.unpack
    def test_allow_access(self, ip_address, version):
        share = db_utils.create_share(mount_snapshot_support=True)
        snapshot = db_utils.create_snapshot(
            status=constants.STATUS_AVAILABLE, share_id=share['id'])

        access = {
            'id': 'fake_id',
            'access_type': 'ip',
            'access_to': ip_address,
            'state': 'new',
        }

        get = self.mock_object(share_api.API, 'get',
                               mock.Mock(return_value=share))
        get_snapshot = self.mock_object(share_api.API, 'get_snapshot',
                                        mock.Mock(return_value=snapshot))
        allow_access = self.mock_object(share_api.API, 'snapshot_allow_access',
                                        mock.Mock(return_value=access))
        body = {'allow_access': access}
        req = fakes.HTTPRequest.blank('/snapshots/%s/action' % snapshot['id'],
                                      version=version)

        actual = self.controller.allow_access(req, snapshot['id'], body)

        self.assertEqual(access, actual['snapshot_access'])
        get.assert_called_once_with(utils.IsAMatcher(context.RequestContext),
                                    share['id'])
        get_snapshot.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'])
        allow_access.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot,
            access['access_type'], access['access_to'])

    def test_allow_access_data_not_found_exception(self):
        share = db_utils.create_share(mount_snapshot_support=True)
        snapshot = db_utils.create_snapshot(
            status=constants.STATUS_AVAILABLE, share_id=share['id'])
        req = fakes.HTTPRequest.blank('/snapshots/%s/action' % snapshot['id'],
                                      version='2.32')
        body = {}

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.allow_access, req,
                          snapshot['id'], body)

    def test_allow_access_exists_exception(self):
        share = db_utils.create_share(mount_snapshot_support=True)
        snapshot = db_utils.create_snapshot(
            status=constants.STATUS_AVAILABLE, share_id=share['id'])
        req = fakes.HTTPRequest.blank('/snapshots/%s/action' % snapshot['id'],
                                      version='2.32')
        access = {
            'id': 'fake_id',
            'access_type': 'ip',
            'access_to': '1.1.1.1',
            'state': 'new',
        }
        msg = "Share snapshot access exists."

        get = self.mock_object(share_api.API, 'get', mock.Mock(
            return_value=share))
        get_snapshot = self.mock_object(share_api.API, 'get_snapshot',
                                        mock.Mock(return_value=snapshot))
        allow_access = self.mock_object(
            share_api.API, 'snapshot_allow_access', mock.Mock(
                side_effect=exception.ShareSnapshotAccessExists(msg)))

        body = {'allow_access': access}

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.allow_access, req,
                          snapshot['id'], body)

        get.assert_called_once_with(utils.IsAMatcher(context.RequestContext),
                                    share['id'])
        get_snapshot.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'])
        allow_access.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot,
            access['access_type'], access['access_to'])

    def test_allow_access_share_without_mount_snap_support(self):
        share = db_utils.create_share(mount_snapshot_support=False)
        snapshot = db_utils.create_snapshot(
            status=constants.STATUS_AVAILABLE, share_id=share['id'])

        access = {
            'id': 'fake_id',
            'access_type': 'ip',
            'access_to': '1.1.1.1',
            'state': 'new',
        }

        get_snapshot = self.mock_object(share_api.API, 'get_snapshot',
                                        mock.Mock(return_value=snapshot))
        get = self.mock_object(share_api.API, 'get',
                               mock.Mock(return_value=share))

        body = {'allow_access': access}
        req = fakes.HTTPRequest.blank('/snapshots/%s/action' % snapshot['id'],
                                      version='2.32')

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.allow_access, req,
                          snapshot['id'], body)

        get.assert_called_once_with(utils.IsAMatcher(context.RequestContext),
                                    share['id'])
        get_snapshot.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'])

    def test_allow_access_empty_parameters(self):
        share = db_utils.create_share(mount_snapshot_support=True)
        snapshot = db_utils.create_snapshot(
            status=constants.STATUS_AVAILABLE, share_id=share['id'])

        access = {'id': 'fake_id',
                  'access_type': '',
                  'access_to': ''}

        body = {'allow_access': access}
        req = fakes.HTTPRequest.blank('/snapshots/%s/action' % snapshot['id'],
                                      version='2.32')

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.allow_access, req,
                          snapshot['id'], body)

    def test_deny_access(self):
        share = db_utils.create_share(mount_snapshot_support=True)
        snapshot = db_utils.create_snapshot(
            status=constants.STATUS_AVAILABLE, share_id=share['id'])
        access = db_utils.create_snapshot_access(
            share_snapshot_id=snapshot['id'])

        get = self.mock_object(share_api.API, 'get',
                               mock.Mock(return_value=share))
        get_snapshot = self.mock_object(share_api.API, 'get_snapshot',
                                        mock.Mock(return_value=snapshot))
        access_get = self.mock_object(share_api.API, 'snapshot_access_get',
                                      mock.Mock(return_value=access))
        deny_access = self.mock_object(share_api.API, 'snapshot_deny_access')

        body = {'deny_access': {'access_id': access.id}}
        req = fakes.HTTPRequest.blank('/snapshots/%s/action' % snapshot['id'],
                                      version='2.32')

        resp = self.controller.deny_access(req, snapshot['id'], body)

        self.assertEqual(202, resp.status_int)
        get.assert_called_once_with(utils.IsAMatcher(context.RequestContext),
                                    share['id'])
        get_snapshot.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'])
        access_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            body['deny_access']['access_id'])
        deny_access.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot, access)

    def test_deny_access_data_not_found_exception(self):
        share = db_utils.create_share(mount_snapshot_support=True)
        snapshot = db_utils.create_snapshot(
            status=constants.STATUS_AVAILABLE, share_id=share['id'])
        req = fakes.HTTPRequest.blank('/snapshots/%s/action' % snapshot['id'],
                                      version='2.32')
        body = {}

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.deny_access, req,
                          snapshot['id'], body)

    def test_deny_access_access_rule_not_found(self):
        share = db_utils.create_share(mount_snapshot_support=True)
        snapshot = db_utils.create_snapshot(
            status=constants.STATUS_AVAILABLE, share_id=share['id'])
        access = db_utils.create_snapshot_access(
            share_snapshot_id=snapshot['id'])
        wrong_access = {
            'access_type': 'fake_type',
            'access_to': 'fake_IP',
            'share_snapshot_id': 'fake_id'
        }

        get = self.mock_object(share_api.API, 'get',
                               mock.Mock(return_value=share))
        get_snapshot = self.mock_object(share_api.API, 'get_snapshot',
                                        mock.Mock(return_value=snapshot))
        access_get = self.mock_object(share_api.API, 'snapshot_access_get',
                                      mock.Mock(return_value=wrong_access))

        body = {'deny_access': {'access_id': access.id}}
        req = fakes.HTTPRequest.blank('/snapshots/%s/action' % snapshot['id'],
                                      version='2.32')

        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.deny_access, req, snapshot['id'],
                          body)
        get.assert_called_once_with(utils.IsAMatcher(context.RequestContext),
                                    share['id'])
        get_snapshot.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext), snapshot['id'])
        access_get.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext),
            body['deny_access']['access_id'])


@ddt.ddt
class ShareSnapshotAdminActionsAPITest(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.controller = share_snapshots.ShareSnapshotsController()
        self.flags(rpc_backend='manila.openstack.common.rpc.impl_fake')
        self.admin_context = context.RequestContext('admin', 'fake', True)
        self.member_context = context.RequestContext('fake', 'fake')

        self.resource_name = self.controller.resource_name
        self.manage_request = fakes.HTTPRequest.blank(
            '/snapshots/manage', use_admin_context=True,
            version=MIN_MANAGE_SNAPSHOT_API_VERSION)
        self.snapshot_id = 'fake'
        self.unmanage_request = fakes.HTTPRequest.blank(
            '/snapshots/%s/unmanage' % self.snapshot_id,
            use_admin_context=True,
            version=MIN_MANAGE_SNAPSHOT_API_VERSION)

    def _get_context(self, role):
        return getattr(self, '%s_context' % role)

    def _setup_snapshot_data(self, snapshot=None, version='2.7'):
        if snapshot is None:
            share = db_utils.create_share()
            snapshot = db_utils.create_snapshot(
                status=constants.STATUS_AVAILABLE, share_id=share['id'])
        path = '/v2/fake/snapshots/%s/action' % snapshot['id']
        req = fakes.HTTPRequest.blank(path, script_name=path, version=version)
        return snapshot, req

    def _reset_status(self, ctxt, model, req, db_access_method,
                      valid_code, valid_status=None, body=None, version='2.7'):
        if float(version) > 2.6:
            action_name = 'reset_status'
        else:
            action_name = 'os-reset_status'
        if body is None:
            body = {action_name: {'status': constants.STATUS_ERROR}}
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.headers['X-Openstack-Manila-Api-Version'] = version
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

    @ddt.data(*fakes.fixture_reset_status_with_different_roles)
    @ddt.unpack
    def test_snapshot_reset_status_with_different_roles(self, role, valid_code,
                                                        valid_status, version):
        ctxt = self._get_context(role)
        snapshot, req = self._setup_snapshot_data(version=version)

        self._reset_status(ctxt, snapshot, req, db.share_snapshot_get,
                           valid_code, valid_status, version=version)

    @ddt.data(
        ({'os-reset_status': {'x-status': 'bad'}}, '2.6'),
        ({'reset_status': {'x-status': 'bad'}}, '2.7'),
        ({'os-reset_status': {'status': 'invalid'}}, '2.6'),
        ({'reset_status': {'status': 'invalid'}}, '2.7'),
    )
    @ddt.unpack
    def test_snapshot_invalid_reset_status_body(self, body, version):
        snapshot, req = self._setup_snapshot_data(version=version)

        self._reset_status(self.admin_context, snapshot, req,
                           db.share_snapshot_get, 400,
                           constants.STATUS_AVAILABLE, body, version=version)

    def _force_delete(self, ctxt, model, req, db_access_method, valid_code,
                      version='2.7'):
        if float(version) > 2.6:
            action_name = 'force_delete'
        else:
            action_name = 'os-force_delete'
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.headers['X-Openstack-Manila-Api-Version'] = version
        req.body = six.b(jsonutils.dumps({action_name: {}}))
        req.environ['manila.context'] = ctxt

        resp = req.get_response(fakes.app())

        # Validate response
        self.assertEqual(valid_code, resp.status_int)

    @ddt.data(*fakes.fixture_force_delete_with_different_roles)
    @ddt.unpack
    def test_snapshot_force_delete_with_different_roles(self, role, resp_code,
                                                        version):
        ctxt = self._get_context(role)
        snapshot, req = self._setup_snapshot_data(version=version)

        self._force_delete(ctxt, snapshot, req, db.share_snapshot_get,
                           resp_code, version=version)

    def test_snapshot_force_delete_missing(self):
        ctxt = self._get_context('admin')
        snapshot, req = self._setup_snapshot_data(snapshot={'id': 'fake'})

        self._force_delete(ctxt, snapshot, req, db.share_snapshot_get, 404)

    @ddt.data(
        {},
        {'snapshots': {}},
        {'snapshot': get_fake_manage_body(share_id='xxxxxxxx')},
        {'snapshot': get_fake_manage_body(provider_location='xxxxxxxx')}
    )
    def test_snapshot_manage_invalid_body(self, body):
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        self.assertRaises(webob.exc.HTTPUnprocessableEntity,
                          self.controller.manage,
                          self.manage_request,
                          body)
        self.mock_policy_check.assert_called_once_with(
            self.manage_request.environ['manila.context'],
            self.resource_name, 'manage_snapshot')

    @ddt.data(
        {'version': '2.12',
         'data': get_fake_manage_body(name='foo', display_description='bar')},
        {'version': '2.12',
         'data': get_fake_manage_body(display_name='foo', description='bar')},
        {'version': '2.17',
         'data': get_fake_manage_body(display_name='foo', description='bar')},
        {'version': '2.17',
         'data': get_fake_manage_body(name='foo', display_description='bar')},
    )
    @ddt.unpack
    def test_snapshot_manage(self, version, data):
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        data['snapshot']['share_id'] = 'fake'
        data['snapshot']['provider_location'] = 'fake_volume_snapshot_id'
        data['snapshot']['driver_options'] = {}
        return_snapshot = fake_share.fake_snapshot(
            create_instance=True, id='fake_snap',
            provider_location='fake_volume_snapshot_id')
        self.mock_object(
            share_api.API, 'manage_snapshot', mock.Mock(
                return_value=return_snapshot))
        share_snapshot = {
            'share_id': 'fake',
            'provider_location': 'fake_volume_snapshot_id',
            'display_name': 'foo',
            'display_description': 'bar',
        }

        req = fakes.HTTPRequest.blank(
            '/snapshots/manage', use_admin_context=True, version=version)

        actual_result = self.controller.manage(req, data)

        actual_snapshot = actual_result['snapshot']
        share_api.API.manage_snapshot.assert_called_once_with(
            mock.ANY, share_snapshot, data['snapshot']['driver_options'])
        self.assertEqual(return_snapshot['id'],
                         actual_result['snapshot']['id'])
        self.assertEqual('fake_volume_snapshot_id',
                         actual_result['snapshot']['provider_location'])

        if (api_version.APIVersionRequest(version) >=
                api_version.APIVersionRequest('2.17')):
            self.assertEqual(return_snapshot['user_id'],
                             actual_snapshot['user_id'])
            self.assertEqual(return_snapshot['project_id'],
                             actual_snapshot['project_id'])
        else:
            self.assertNotIn('user_id', actual_snapshot)
            self.assertNotIn('project_id', actual_snapshot)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name,
            'manage_snapshot')

    @ddt.data(exception.ShareNotFound(share_id='fake'),
              exception.ShareSnapshotNotFound(snapshot_id='fake'),
              exception.ManageInvalidShareSnapshot(reason='error'),
              exception.InvalidShare(reason='error'))
    def test_manage_exception(self, exception_type):
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        body = get_fake_manage_body(
            share_id='fake', provider_location='fake_volume_snapshot_id',
            driver_options={})
        self.mock_object(
            share_api.API, 'manage_snapshot', mock.Mock(
                side_effect=exception_type))

        http_ex = webob.exc.HTTPNotFound

        if (isinstance(exception_type, exception.ManageInvalidShareSnapshot)
                or isinstance(exception_type, exception.InvalidShare)):
            http_ex = webob.exc.HTTPConflict

        self.assertRaises(http_ex,
                          self.controller.manage,
                          self.manage_request, body)
        self.mock_policy_check.assert_called_once_with(
            self.manage_request.environ['manila.context'],
            self.resource_name, 'manage_snapshot')

    @ddt.data('1.0', '2.6', '2.11')
    def test_manage_version_not_found(self, version):
        body = get_fake_manage_body(
            share_id='fake', provider_location='fake_volume_snapshot_id',
            driver_options={})
        fake_req = fakes.HTTPRequest.blank(
            '/snapshots/manage', use_admin_context=True,
            version=version)

        self.assertRaises(exception.VersionNotFoundForAPIMethod,
                          self.controller.manage,
                          fake_req, body)

    def test_snapshot_unmanage_share_server(self):
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        share = {'status': constants.STATUS_AVAILABLE, 'id': 'bar_id',
                 'share_server_id': 'fake_server_id'}
        self.mock_object(share_api.API, 'get', mock.Mock(return_value=share))
        snapshot = {'status': constants.STATUS_AVAILABLE, 'id': 'foo_id',
                    'share_id': 'bar_id'}
        self.mock_object(share_api.API, 'get_snapshot',
                         mock.Mock(return_value=snapshot))

        self.assertRaises(webob.exc.HTTPForbidden,
                          self.controller.unmanage,
                          self.unmanage_request,
                          snapshot['id'])
        self.controller.share_api.get_snapshot.assert_called_once_with(
            self.unmanage_request.environ['manila.context'], snapshot['id'])
        self.controller.share_api.get.assert_called_once_with(
            self.unmanage_request.environ['manila.context'], share['id'])
        self.mock_policy_check.assert_called_once_with(
            self.unmanage_request.environ['manila.context'],
            self.resource_name, 'unmanage_snapshot')

    def test_snapshot_unmanage_replicated_snapshot(self):
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        share = {'status': constants.STATUS_AVAILABLE, 'id': 'bar_id',
                 'has_replicas': True}
        self.mock_object(share_api.API, 'get', mock.Mock(return_value=share))
        snapshot = {'status': constants.STATUS_AVAILABLE, 'id': 'foo_id',
                    'share_id': 'bar_id'}
        self.mock_object(share_api.API, 'get_snapshot',
                         mock.Mock(return_value=snapshot))

        self.assertRaises(webob.exc.HTTPConflict,
                          self.controller.unmanage,
                          self.unmanage_request,
                          snapshot['id'])
        self.controller.share_api.get_snapshot.assert_called_once_with(
            self.unmanage_request.environ['manila.context'], snapshot['id'])
        self.controller.share_api.get.assert_called_once_with(
            self.unmanage_request.environ['manila.context'], share['id'])
        self.mock_policy_check.assert_called_once_with(
            self.unmanage_request.environ['manila.context'],
            self.resource_name, 'unmanage_snapshot')

    @ddt.data(*constants.TRANSITIONAL_STATUSES)
    def test_snapshot_unmanage_with_transitional_state(self, status):
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        share = {'status': constants.STATUS_AVAILABLE, 'id': 'bar_id'}
        self.mock_object(share_api.API, 'get', mock.Mock(return_value=share))
        snapshot = {'status': status, 'id': 'foo_id', 'share_id': 'bar_id'}
        self.mock_object(
            self.controller.share_api, 'get_snapshot',
            mock.Mock(return_value=snapshot))
        self.assertRaises(
            webob.exc.HTTPForbidden,
            self.controller.unmanage, self.unmanage_request, snapshot['id'])

        self.controller.share_api.get_snapshot.assert_called_once_with(
            self.unmanage_request.environ['manila.context'], snapshot['id'])
        self.controller.share_api.get.assert_called_once_with(
            self.unmanage_request.environ['manila.context'], share['id'])
        self.mock_policy_check.assert_called_once_with(
            self.unmanage_request.environ['manila.context'],
            self.resource_name, 'unmanage_snapshot')

    def test_snapshot_unmanage(self):
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        share = {'status': constants.STATUS_AVAILABLE, 'id': 'bar_id',
                 'host': 'fake_host'}
        self.mock_object(share_api.API, 'get', mock.Mock(return_value=share))
        snapshot = {'status': constants.STATUS_AVAILABLE, 'id': 'foo_id',
                    'share_id': 'bar_id'}
        self.mock_object(share_api.API, 'get_snapshot',
                         mock.Mock(return_value=snapshot))
        self.mock_object(share_api.API, 'unmanage_snapshot', mock.Mock())

        actual_result = self.controller.unmanage(self.unmanage_request,
                                                 snapshot['id'])

        self.assertEqual(202, actual_result.status_int)
        self.controller.share_api.get_snapshot.assert_called_once_with(
            self.unmanage_request.environ['manila.context'], snapshot['id'])
        share_api.API.unmanage_snapshot.assert_called_once_with(
            mock.ANY, snapshot, 'fake_host')
        self.mock_policy_check.assert_called_once_with(
            self.unmanage_request.environ['manila.context'],
            self.resource_name, 'unmanage_snapshot')

    def test_unmanage_share_not_found(self):
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        self.mock_object(
            share_api.API, 'get', mock.Mock(
                side_effect=exception.ShareNotFound(share_id='fake')))
        snapshot = {'status': constants.STATUS_AVAILABLE, 'id': 'foo_id',
                    'share_id': 'bar_id'}
        self.mock_object(share_api.API, 'get_snapshot',
                         mock.Mock(return_value=snapshot))
        self.mock_object(share_api.API, 'unmanage_snapshot', mock.Mock())

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.unmanage,
                          self.unmanage_request, 'foo_id')
        self.mock_policy_check.assert_called_once_with(
            self.unmanage_request.environ['manila.context'],
            self.resource_name, 'unmanage_snapshot')

    def test_unmanage_snapshot_not_found(self):
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        share = {'status': constants.STATUS_AVAILABLE, 'id': 'bar_id'}
        self.mock_object(share_api.API, 'get', mock.Mock(return_value=share))
        self.mock_object(
            share_api.API, 'get_snapshot', mock.Mock(
                side_effect=exception.ShareSnapshotNotFound(
                    snapshot_id='foo_id')))
        self.mock_object(share_api.API, 'unmanage_snapshot', mock.Mock())

        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.unmanage,
                          self.unmanage_request, 'foo_id')
        self.mock_policy_check.assert_called_once_with(
            self.unmanage_request.environ['manila.context'],
            self.resource_name, 'unmanage_snapshot')

    @ddt.data('1.0', '2.6', '2.11')
    def test_unmanage_version_not_found(self, version):
        snapshot_id = 'fake'
        fake_req = fakes.HTTPRequest.blank(
            '/snapshots/%s/unmanage' % snapshot_id,
            use_admin_context=True,
            version=version)

        self.assertRaises(exception.VersionNotFoundForAPIMethod,
                          self.controller.unmanage,
                          fake_req, 'fake')
