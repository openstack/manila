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

import shutil
import tempfile
import webob

from oslo.config import cfg

from manila import context
from manila import db
from manila import exception
from manila.openstack.common import jsonutils
from manila.share import api as share_api
from manila import test
from manila.tests.api import fakes

CONF = cfg.CONF


def app():
    # no auth, just let environ['manila.context'] pass through
    api = fakes.router.APIRouter()
    mapper = fakes.urlmap.URLMap()
    mapper['/v2'] = api
    return mapper


class AdminActionsTest(test.TestCase):

    def setUp(self):
        super(AdminActionsTest, self).setUp()
        self.tempdir = tempfile.mkdtemp()
        self.flags(rpc_backend='manila.openstack.common.rpc.impl_fake')
        self.flags(lock_path=self.tempdir)
        self.share_api = share_api.API()

    def tearDown(self):
        shutil.rmtree(self.tempdir)
        super(AdminActionsTest, self).tearDown()

    def test_reset_status_as_admin(self):
        # admin context
        ctx = context.RequestContext('admin', 'fake', True)
        # current status is available
        share = db.share_create(ctx, {'status': 'available'})
        req = webob.Request.blank('/v2/fake/shares/%s/action' % share['id'])
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        # request status of 'error'
        req.body = jsonutils.dumps({'os-reset_status': {'status': 'error'}})
        # attach admin context to request
        req.environ['manila.context'] = ctx
        resp = req.get_response(app())
        # request is accepted
        self.assertEqual(resp.status_int, 202)
        share = db.share_get(ctx, share['id'])
        # status changed to 'error'
        self.assertEqual(share['status'], 'error')

    def test_reset_status_as_non_admin(self):
        # current status is 'error'
        share = db.share_create(context.get_admin_context(),
                                  {'status': 'error'})
        req = webob.Request.blank('/v2/fake/shares/%s/action' % share['id'])
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        # request changing status to available
        req.body = jsonutils.dumps({'os-reset_status': {'status':
                                                        'available'}})
        # non-admin context
        req.environ['manila.context'] = context.RequestContext('fake', 'fake')
        resp = req.get_response(app())
        # request is not authorized
        self.assertEqual(resp.status_int, 403)
        share = db.share_get(context.get_admin_context(), share['id'])
        # status is still 'error'
        self.assertEqual(share['status'], 'error')

    def test_malformed_reset_status_body(self):
        # admin context
        ctx = context.RequestContext('admin', 'fake', True)
        # current status is available
        share = db.share_create(ctx, {'status': 'available'})
        req = webob.Request.blank('/v2/fake/shares/%s/action' % share['id'])
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        # malformed request body
        req.body = jsonutils.dumps({'os-reset_status': {'x-status': 'bad'}})
        # attach admin context to request
        req.environ['manila.context'] = ctx
        resp = req.get_response(app())
        # bad request
        self.assertEqual(resp.status_int, 400)
        share = db.share_get(ctx, share['id'])
        # status is still 'available'
        self.assertEqual(share['status'], 'available')

    def test_invalid_status_for_share(self):
        # admin context
        ctx = context.RequestContext('admin', 'fake', True)
        # current status is available
        share = db.share_create(ctx, {'status': 'available'})
        req = webob.Request.blank('/v2/fake/shares/%s/action' % share['id'])
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        # 'invalid' is not a valid status
        req.body = jsonutils.dumps({'os-reset_status': {'status': 'invalid'}})
        # attach admin context to request
        req.environ['manila.context'] = ctx
        resp = req.get_response(app())
        # bad request
        self.assertEqual(resp.status_int, 400)
        share = db.share_get(ctx, share['id'])
        # status is still 'available'
        self.assertEqual(share['status'], 'available')

    def test_reset_status_for_missing_share(self):
        # admin context
        ctx = context.RequestContext('admin', 'fake', True)
        # missing-share-id
        req = webob.Request.blank('/v2/fake/shares/%s/action' %
                                  'missing-share-id')
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        # malformed request body
        req.body = jsonutils.dumps({'os-reset_status': {'status':
                                                        'available'}})
        # attach admin context to request
        req.environ['manila.context'] = ctx
        resp = req.get_response(app())
        # not found
        self.assertEqual(resp.status_int, 404)
        self.assertRaises(exception.NotFound, db.share_get, ctx,
                          'missing-share-id')
