# Copyright 2013 Mirantis Inc.
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
from oslo_config import cfg
from oslo_serialization import jsonutils
import six
import webob

from manila.api.openstack import wsgi
from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila.share import api as share_api
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils

CONF = cfg.CONF


def app():
    # no auth, just let environ['manila.context'] pass through
    api = fakes.router.APIRouter()
    mapper = fakes.urlmap.URLMap()
    mapper['/v1'] = api
    return mapper


fixture_reset_status_with_different_roles = (
    {'role': 'admin', 'valid_code': 202,
     'valid_status': constants.STATUS_ERROR},
    {'role': 'member', 'valid_code': 403,
     'valid_status': constants.STATUS_AVAILABLE}
)

fixture_force_delete_with_different_roles = (
    {'role': 'admin', 'resp_code': 202},
    {'role': 'member', 'resp_code': 403},
)

fixture_invalid_reset_status_body = (
    {'os-reset_status': {'x-status': 'bad'}},
    {'os-reset_status': {'status': 'invalid'}}
)


@ddt.ddt
class AdminActionsTest(test.TestCase):

    def setUp(self):
        super(AdminActionsTest, self).setUp()
        self.flags(rpc_backend='manila.openstack.common.rpc.impl_fake')
        self.share_api = share_api.API()
        self.admin_context = context.RequestContext('admin', 'fake', True)
        self.member_context = context.RequestContext('fake', 'fake')

    def _get_context(self, role):
        return getattr(self, '%s_context' % role)

    def _setup_share_data(self, share=None):
        if share is None:
            share = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                          size='1',
                                          override_defaults=True)
        req = webob.Request.blank('/v1/fake/shares/%s/action' % share['id'])
        return share, req

    def _setup_snapshot_data(self, snapshot=None):
        if snapshot is None:
            share = db_utils.create_share()
            snapshot = db_utils.create_snapshot(
                status=constants.STATUS_AVAILABLE, share_id=share['id'])
        req = webob.Request.blank('/v1/fake/snapshots/%s/action' %
                                  snapshot['id'])
        return snapshot, req

    def _setup_share_instance_data(self, instance=None):
        if instance is None:
            instance = db_utils.create_share(status=constants.STATUS_AVAILABLE,
                                             size='1').instance
        req = webob.Request.blank(
            '/v1/fake/share_instances/%s/action' % instance['id'])
        return instance, req

    def _setup_cg_data(self, cg=None):
        if cg is None:
            cg = db_utils.create_consistency_group(
                status=constants.STATUS_AVAILABLE)
        req = webob.Request.blank('/v1/fake/consistency-groups/%s/action' %
                                  cg['id'])
        req.headers[wsgi.API_VERSION_REQUEST_HEADER] = '1.5'
        req.headers[wsgi.EXPERIMENTAL_API_REQUEST_HEADER] = 'True'

        return cg, req

    def _setup_cgsnapshot_data(self, cgsnapshot=None):
        if cgsnapshot is None:
            cgsnapshot = db_utils.create_cgsnapshot(
                'fake_id', status=constants.STATUS_AVAILABLE)
        req = webob.Request.blank('/v1/fake/cgsnapshots/%s/action' %
                                  cgsnapshot['id'])
        req.headers[wsgi.API_VERSION_REQUEST_HEADER] = '1.5'
        req.headers[wsgi.EXPERIMENTAL_API_REQUEST_HEADER] = 'True'
        return cgsnapshot, req

    def _reset_status(self, ctxt, model, req, db_access_method,
                      valid_code, valid_status=None, body=None):
        if body is None:
            body = {'os-reset_status': {'status': constants.STATUS_ERROR}}
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.body = six.b(jsonutils.dumps(body))
        req.environ['manila.context'] = ctxt

        resp = req.get_response(app())

        # validate response code and model status
        self.assertEqual(resp.status_int, valid_code)

        if valid_code == 404:
            self.assertRaises(exception.NotFound,
                              db_access_method,
                              ctxt,
                              model['id'])
        else:
            actual_model = db_access_method(ctxt, model['id'])
            self.assertEqual(actual_model['status'], valid_status)

    @ddt.data(*fixture_reset_status_with_different_roles)
    @ddt.unpack
    def test_share_reset_status_with_different_roles(self, role, valid_code,
                                                     valid_status):
        share, req = self._setup_share_data()
        ctxt = self._get_context(role)

        self._reset_status(ctxt, share, req, db.share_get, valid_code,
                           valid_status)

    @ddt.data(*fixture_reset_status_with_different_roles)
    @ddt.unpack
    def test_snapshot_reset_status_with_different_roles(self, role, valid_code,
                                                        valid_status):
        ctxt = self._get_context(role)
        snapshot, req = self._setup_snapshot_data()

        self._reset_status(ctxt, snapshot, req, db.share_snapshot_get,
                           valid_code, valid_status)

    @ddt.data(*fixture_reset_status_with_different_roles)
    @ddt.unpack
    def test_share_instances_reset_status_with_different_roles(self, role,
                                                               valid_code,
                                                               valid_status):
        ctxt = self._get_context(role)
        instance, req = self._setup_share_instance_data()

        self._reset_status(ctxt, instance, req, db.share_instance_get,
                           valid_code, valid_status)

    @ddt.data(*fixture_reset_status_with_different_roles)
    @ddt.unpack
    def test_consistency_groups_reset_status_with_different_roles(
            self, role, valid_code, valid_status):
        ctxt = self._get_context(role)
        cg, req = self._setup_cg_data()

        self._reset_status(ctxt, cg, req, db.consistency_group_get,
                           valid_code, valid_status)

    @ddt.data(*fixture_reset_status_with_different_roles)
    @ddt.unpack
    def test_cgsnapshot_reset_status_with_different_roles(
            self, role, valid_code, valid_status):
        ctxt = self._get_context(role)
        cgsnap, req = self._setup_cgsnapshot_data()

        self._reset_status(ctxt, cgsnap, req, db.cgsnapshot_get,
                           valid_code, valid_status)

    @ddt.data(*fixture_invalid_reset_status_body)
    def test_share_invalid_reset_status_body(self, body):
        share, req = self._setup_share_data()
        ctxt = self.admin_context

        self._reset_status(ctxt, share, req, db.share_get, 400,
                           constants.STATUS_AVAILABLE, body)

    @ddt.data(*fixture_invalid_reset_status_body)
    def test_snapshot_invalid_reset_status_body(self, body):
        snapshot, req = self._setup_snapshot_data()

        self._reset_status(self.admin_context, snapshot, req,
                           db.share_snapshot_get, 400,
                           constants.STATUS_AVAILABLE, body)

    @ddt.data(*fixture_invalid_reset_status_body)
    def test_share_instance_invalid_reset_status_body(self, body):
        instance, req = self._setup_share_instance_data()

        self._reset_status(self.admin_context, instance, req,
                           db.share_instance_get, 400,
                           constants.STATUS_AVAILABLE, body)

    def test_share_reset_status_for_missing(self):
        fake_share = {'id': 'missing-share-id'}
        req = webob.Request.blank('/v1/fake/shares/%s/action' %
                                  fake_share['id'])

        self._reset_status(self.admin_context, fake_share, req,
                           db.share_snapshot_get, 404)

    def _force_delete(self, ctxt, model, req, db_access_method, valid_code,
                      check_model_in_db=False):
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.body = six.b(jsonutils.dumps({'os-force_delete': {}}))
        req.environ['manila.context'] = ctxt

        resp = req.get_response(app())

        # validate response
        self.assertEqual(resp.status_int, valid_code)

        if valid_code == 202 and check_model_in_db:
            self.assertRaises(exception.NotFound,
                              db_access_method,
                              ctxt,
                              model['id'])

    @ddt.data(*fixture_force_delete_with_different_roles)
    @ddt.unpack
    def test_share_force_delete_with_different_roles(self, role, resp_code):
        share, req = self._setup_share_data()
        ctxt = self._get_context(role)

        self._force_delete(ctxt, share, req, db.share_get, resp_code,
                           check_model_in_db=True)

    def test_share_force_delete_missing(self):
        share, req = self._setup_share_data(share={'id': 'fake'})
        ctxt = self._get_context('admin')

        self._force_delete(ctxt, share, req, db.share_get, 404)

    @ddt.data(*fixture_force_delete_with_different_roles)
    @ddt.unpack
    def test_snapshot_force_delete_with_different_roles(self, role, resp_code):
        snapshot, req = self._setup_snapshot_data()
        ctxt = self._get_context(role)

        self._force_delete(ctxt, snapshot, req, db.share_snapshot_get,
                           resp_code)

    def test_snapshot_force_delete_missing(self):
        snapshot, req = self._setup_snapshot_data(snapshot={'id': 'fake'})
        ctxt = self._get_context('admin')

        self._force_delete(ctxt, snapshot, req, db.share_snapshot_get, 404)

    @ddt.data(*fixture_force_delete_with_different_roles)
    @ddt.unpack
    def test_instance_force_delete_with_different_roles(self, role, resp_code):
        instance, req = self._setup_share_instance_data()
        ctxt = self._get_context(role)

        self._force_delete(ctxt, instance, req, db.share_instance_get,
                           resp_code)

    def test_instance_force_delete_missing(self):
        instance, req = self._setup_share_instance_data(
            instance={'id': 'fake'})
        ctxt = self._get_context('admin')

        self._force_delete(ctxt, instance, req, db.share_instance_get, 404)

    @ddt.data(*fixture_force_delete_with_different_roles)
    @ddt.unpack
    def test_consistency_group_force_delete_with_different_roles(self, role,
                                                                 resp_code):
        cg, req = self._setup_cg_data()
        ctxt = self._get_context(role)

        self._force_delete(ctxt, cg, req, db.consistency_group_get,
                           resp_code)

    @ddt.data(*fixture_force_delete_with_different_roles)
    @ddt.unpack
    def test_cgsnapshot_force_delete_with_different_roles(self, role,
                                                          resp_code):
        cgsnap, req = self._setup_cgsnapshot_data()
        ctxt = self._get_context(role)

        self._force_delete(ctxt, cgsnap, req, db.cgsnapshot_get,
                           resp_code)
