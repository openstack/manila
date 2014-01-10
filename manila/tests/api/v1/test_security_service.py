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

import mock
import webob

from manila.api.v1 import security_service
from manila.common import constants
from manila import db
from manila import exception
from manila import test
from manila.tests.api import fakes


class ShareApiTest(test.TestCase):
    """Share Api Test."""
    def setUp(self):
        super(ShareApiTest, self).setUp()
        self.controller = security_service.SecurityServiceController()
        self.maxDiff = None
        self.security_service = {
            "created_at": "fake-time",
            "updated_at": "fake-time-2",
            "id": 1,
            "name": "fake-name",
            "description": "Fake Security Service Desc",
            "type": constants.SECURITY_SERVICES_ALLOWED_TYPES[0],
            "dns_ip": "1.1.1.1",
            "server": "fake-server",
            "domain": "fake-domain",
            "sid": "fake-sid",
            "status": "new"
        }
        security_service.policy.check_policy = mock.Mock()

    def test_security_service_show(self):
        db.security_service_get = mock.Mock(return_value=self.security_service)
        req = fakes.HTTPRequest.blank('/security-services/1')
        res_dict = self.controller.show(req, '1')
        expected = self.security_service.copy()
        expected.update()
        self.assertEqual(res_dict, {'security_service': self.security_service})

    def test_security_service_show_not_found(self):
        db.security_service_get = mock.Mock(side_effect=exception.NotFound)
        req = fakes.HTTPRequest.blank('/shares/1')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.show,
                          req, '1')

    def test_security_service_create(self):
        sec_service = self.security_service.copy()
        db.security_service_create = mock.Mock(
            return_value=sec_service)
        req = fakes.HTTPRequest.blank('/security-services')
        res_dict = self.controller.create(
            req, {"security_service": sec_service})
        expected = self.security_service.copy()
        self.assertEqual(res_dict, {'security_service': expected})

    def test_security_service_create_invalid_types(self):
        sec_service = self.security_service.copy()
        sec_service['type'] = 'invalid'
        req = fakes.HTTPRequest.blank('/security-services')
        self.assertRaises(exception.InvalidInput, self.controller.create, req,
                          {"security_service": sec_service})

    def test_create_security_service_no_body(self):
        body = {}
        req = fakes.HTTPRequest.blank('/security-services')
        self.assertRaises(webob.exc.HTTPUnprocessableEntity,
                          self.controller.create,
                          req,
                          body)

    def test_security_service_delete(self):
        db.security_service_delete = mock.Mock()
        db.security_service_get = mock.Mock()
        req = fakes.HTTPRequest.blank('/shares/1')
        resp = self.controller.delete(req, 1)
        db.security_service_delete.assert_called_once_with(
            req.environ['manila.context'], 1)
        self.assertEqual(resp.status_int, 202)

    def test_security_service_delete_not_found(self):
        db.security_service_get = mock.Mock(side_effect=exception.NotFound)
        req = fakes.HTTPRequest.blank('/security_services/1')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.delete,
                          req,
                          1)

    def test_security_service_update_name(self):
        new = self.security_service.copy()
        updated = self.security_service.copy()
        updated['name'] = 'new'
        db.security_service_get = mock.Mock(return_value=new)
        db.security_service_update = mock.Mock(return_value=updated)
        body = {"security_service": {"name": "new"}}
        req = fakes.HTTPRequest.blank('/security_service/1')
        res_dict = self.controller.update(req, 1, body)['security_service']
        self.assertEqual(res_dict['name'], updated['name'])

    def test_security_service_update_description(self):
        new = self.security_service.copy()
        updated = self.security_service.copy()
        updated['description'] = 'new'
        db.security_service_get = mock.Mock(return_value=new)
        db.security_service_update = mock.Mock(return_value=updated)
        body = {"security_service": {"description": "new"}}
        req = fakes.HTTPRequest.blank('/security_service/1')
        res_dict = self.controller.update(req, 1, body)['security_service']
        self.assertEqual(res_dict['description'], updated['description'])

    def test_security_service_list(self):
        db.security_service_get_all_by_project = mock.Mock(
            return_value=[self.security_service.copy()])
        req = fakes.HTTPRequest.blank('/security_services')
        res_dict = self.controller.index(req)
        expected = {'security_services': [
            {'id': self.security_service['id'],
             'name': self.security_service['name'],
             'status': self.security_service['status']
             }
        ]}
        self.assertEqual(res_dict, expected)
