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
from six.moves.urllib import parse
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
        self.ss_active_directory = {
            "created_at": "fake-time",
            "updated_at": "fake-time-2",
            "id": 1,
            "name": "fake-name",
            "description": "Fake Security Service Desc",
            "type": constants.SECURITY_SERVICES_ALLOWED_TYPES[0],
            "dns_ip": "1.1.1.1",
            "server": "fake-server",
            "domain": "fake-domain",
            "user": "fake-user",
            "password": "fake-password",
            "status": constants.STATUS_NEW,
            "project_id": "fake",
        }
        self.ss_ldap = {
            "created_at": "fake-time",
            "updated_at": "fake-time-2",
            "id": 2,
            "name": "ss-ldap",
            "description": "Fake Security Service Desc",
            "type": constants.SECURITY_SERVICES_ALLOWED_TYPES[1],
            "dns_ip": "2.2.2.2",
            "server": "test-server",
            "domain": "test-domain",
            "user": "test-user",
            "password": "test-password",
            "status": "active",
            "project_id": "fake",
        }
        self.valid_search_opts = {
            'user': 'fake-user',
            'server': 'fake-server',
            'dns_ip': '1.1.1.1',
            'domain': 'fake-domain',
            'type': constants.SECURITY_SERVICES_ALLOWED_TYPES[0],
        }
        self.check_policy_patcher = mock.patch(
            'manila.api.v1.security_service.policy.check_policy')
        self.check_policy_patcher.start()
        self.addCleanup(self._stop_started_patcher, self.check_policy_patcher)
        self.security_service_list_expected_resp = {
            'security_services': [{
                'id': self.ss_active_directory['id'],
                'name': self.ss_active_directory['name'],
                'type': self.ss_active_directory['type'],
                'status': self.ss_active_directory['status']
            }, ]
        }

    def _stop_started_patcher(self, patcher):
        if hasattr(patcher, 'is_local'):
            patcher.stop()

    def test_security_service_show(self):
        db.security_service_get = mock.Mock(
            return_value=self.ss_active_directory)
        req = fakes.HTTPRequest.blank('/security-services/1')
        res_dict = self.controller.show(req, '1')
        expected = self.ss_active_directory.copy()
        expected.update()
        self.assertEqual({'security_service': self.ss_active_directory},
                         res_dict)

    def test_security_service_show_not_found(self):
        db.security_service_get = mock.Mock(side_effect=exception.NotFound)
        req = fakes.HTTPRequest.blank('/shares/1')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.show,
                          req, '1')

    def test_security_service_create(self):
        sec_service = self.ss_active_directory.copy()
        create_stub = mock.Mock(
            return_value=sec_service)
        self.mock_object(db, 'security_service_create', create_stub)

        req = fakes.HTTPRequest.blank('/security-services')
        res_dict = self.controller.create(
            req, {"security_service": sec_service})
        expected = self.ss_active_directory.copy()
        self.assertEqual({'security_service': expected}, res_dict)

    def test_security_service_create_invalid_types(self):
        sec_service = self.ss_active_directory.copy()
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
        db.share_network_get_all_by_security_service = mock.Mock(
            return_value=[])
        req = fakes.HTTPRequest.blank('/security_services/1')
        resp = self.controller.delete(req, 1)
        db.security_service_delete.assert_called_once_with(
            req.environ['manila.context'], 1)
        self.assertEqual(202, resp.status_int)

    def test_security_service_delete_not_found(self):
        db.security_service_get = mock.Mock(side_effect=exception.NotFound)
        req = fakes.HTTPRequest.blank('/security_services/1')
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.delete,
                          req,
                          1)

    def test_security_service_delete_has_share_networks(self):
        db.security_service_get = mock.Mock()
        db.share_network_get_all_by_security_service = mock.Mock(
            return_value=[{'share_network': 'fake_share_network'}])
        req = fakes.HTTPRequest.blank('/security_services/1')
        self.assertRaises(webob.exc.HTTPForbidden, self.controller.delete,
                          req, 1)

    def test_security_service_update_name(self):
        new = self.ss_active_directory.copy()
        updated = self.ss_active_directory.copy()
        updated['name'] = 'new'
        self.mock_object(security_service.policy, 'check_policy')
        db.security_service_get = mock.Mock(return_value=new)
        db.security_service_update = mock.Mock(return_value=updated)
        db.share_network_get_all_by_security_service = mock.Mock(
            return_value=[{
                'id': 'fake_id',
                'share_servers': 'fake_share_server'
            }])
        body = {"security_service": {"name": "new"}}
        req = fakes.HTTPRequest.blank('/security_service/1')
        res_dict = self.controller.update(req, 1, body)['security_service']
        self.assertEqual(updated['name'], res_dict['name'])
        db.share_network_get_all_by_security_service.assert_called_once_with(
            req.environ['manila.context'], 1)
        self.assertEqual(2, security_service.policy.check_policy.call_count)
        security_service.policy.check_policy.assert_has_calls([
            mock.call(req.environ['manila.context'],
                      security_service.RESOURCE_NAME, 'update', new)
        ])

    def test_security_service_update_description(self):
        new = self.ss_active_directory.copy()
        updated = self.ss_active_directory.copy()
        updated['description'] = 'new'
        self.mock_object(security_service.policy, 'check_policy')
        db.security_service_get = mock.Mock(return_value=new)
        db.security_service_update = mock.Mock(return_value=updated)
        db.share_network_get_all_by_security_service = mock.Mock(
            return_value=[{
                'id': 'fake_id',
                'share_servers': 'fake_share_server'
            }])
        body = {"security_service": {"description": "new"}}
        req = fakes.HTTPRequest.blank('/security_service/1')
        res_dict = self.controller.update(req, 1, body)['security_service']
        self.assertEqual(updated['description'], res_dict['description'])
        db.share_network_get_all_by_security_service.assert_called_once_with(
            req.environ['manila.context'], 1)
        self.assertEqual(2, security_service.policy.check_policy.call_count)
        security_service.policy.check_policy.assert_has_calls([
            mock.call(req.environ['manila.context'],
                      security_service.RESOURCE_NAME, 'update', new)
        ])

    @mock.patch.object(db, 'security_service_get', mock.Mock())
    @mock.patch.object(db, 'share_network_get_all_by_security_service',
                       mock.Mock())
    def test_security_service_update_invalid_keys_sh_server_exists(self):
        self.mock_object(security_service.policy, 'check_policy')
        db.share_network_get_all_by_security_service.return_value = [
            {'id': 'fake_id', 'share_servers': 'fake_share_servers'},
        ]
        db.security_service_get.return_value = self.ss_active_directory.copy()
        body = {'security_service': {'user_id': 'new_user'}}
        req = fakes.HTTPRequest.blank('/security_services/1')
        self.assertRaises(webob.exc.HTTPForbidden, self.controller.update,
                          req, 1, body)
        db.security_service_get.assert_called_once_with(
            req.environ['manila.context'], 1)
        db.share_network_get_all_by_security_service.assert_called_once_with(
            req.environ['manila.context'], 1)
        self.assertEqual(1, security_service.policy.check_policy.call_count)
        security_service.policy.check_policy.assert_has_calls([
            mock.call(req.environ['manila.context'],
                      security_service.RESOURCE_NAME, 'update',
                      db.security_service_get.return_value)
        ])

    @mock.patch.object(db, 'security_service_get', mock.Mock())
    @mock.patch.object(db, 'security_service_update', mock.Mock())
    @mock.patch.object(db, 'share_network_get_all_by_security_service',
                       mock.Mock())
    def test_security_service_update_valid_keys_sh_server_exists(self):
        self.mock_object(security_service.policy, 'check_policy')
        db.share_network_get_all_by_security_service.return_value = [
            {'id': 'fake_id', 'share_servers': 'fake_share_servers'},
        ]
        old = self.ss_active_directory.copy()
        updated = self.ss_active_directory.copy()
        updated['name'] = 'new name'
        updated['description'] = 'new description'
        db.security_service_get.return_value = old
        db.security_service_update.return_value = updated
        body = {
            'security_service': {
                'description': 'new description',
                'name': 'new name',
            },
        }
        req = fakes.HTTPRequest.blank('/security_services/1')
        res_dict = self.controller.update(req, 1, body)['security_service']
        self.assertEqual(updated['description'], res_dict['description'])
        self.assertEqual(updated['name'], res_dict['name'])
        db.security_service_get.assert_called_once_with(
            req.environ['manila.context'], 1)
        db.share_network_get_all_by_security_service.assert_called_once_with(
            req.environ['manila.context'], 1)
        db.security_service_update.assert_called_once_with(
            req.environ['manila.context'], 1, body['security_service'])
        self.assertEqual(2, security_service.policy.check_policy.call_count)
        security_service.policy.check_policy.assert_has_calls([
            mock.call(req.environ['manila.context'],
                      security_service.RESOURCE_NAME, 'update', old)
        ])

    def test_security_service_list(self):
        db.security_service_get_all_by_project = mock.Mock(
            return_value=[self.ss_active_directory.copy()])
        req = fakes.HTTPRequest.blank('/security_services')
        res_dict = self.controller.index(req)
        self.assertEqual(self.security_service_list_expected_resp, res_dict)

    @mock.patch.object(db, 'share_network_get', mock.Mock())
    def test_security_service_list_filter_by_sn(self):
        sn = {
            'id': 'fake_sn_id',
            'security_services': [self.ss_active_directory, ],
        }
        db.share_network_get.return_value = sn
        req = fakes.HTTPRequest.blank(
            '/security-services?share_network_id=fake_sn_id')
        res_dict = self.controller.index(req)
        self.assertEqual(self.security_service_list_expected_resp, res_dict)
        db.share_network_get.assert_called_once_with(
            req.environ['manila.context'],
            sn['id'])

    @mock.patch.object(db, 'security_service_get_all', mock.Mock())
    def test_security_services_list_all_tenants_admin_context(self):
        self.check_policy_patcher.stop()
        db.security_service_get_all.return_value = [
            self.ss_active_directory,
            self.ss_ldap,
        ]
        req = fakes.HTTPRequest.blank(
            '/security-services?all_tenants=1&name=fake-name',
            use_admin_context=True)
        res_dict = self.controller.index(req)
        self.assertEqual(self.security_service_list_expected_resp, res_dict)
        db.security_service_get_all.assert_called_once_with(
            req.environ['manila.context'])

    @mock.patch.object(db, 'security_service_get_all_by_project', mock.Mock())
    def test_security_services_list_all_tenants_non_admin_context(self):
        db.security_service_get_all_by_project.return_value = []
        req = fakes.HTTPRequest.blank(
            '/security-services?all_tenants=1')
        fake_context = req.environ['manila.context']
        self.controller.index(req)
        db.security_service_get_all_by_project.assert_called_once_with(
            fake_context, fake_context.project_id
        )

    @mock.patch.object(db, 'security_service_get_all_by_project', mock.Mock())
    def test_security_services_list_admin_context_invalid_opts(self):
        db.security_service_get_all_by_project.return_value = [
            self.ss_active_directory,
            self.ss_ldap,
        ]
        req = fakes.HTTPRequest.blank(
            '/security-services?fake_opt=fake_value',
            use_admin_context=True)
        res_dict = self.controller.index(req)
        self.assertEqual({'security_services': []}, res_dict)
        db.security_service_get_all_by_project.assert_called_once_with(
            req.environ['manila.context'],
            req.environ['manila.context'].project_id)

    @mock.patch.object(db, 'security_service_get_all_by_project', mock.Mock())
    def test_security_service_list_all_filter_opts_separately(self):
        db.security_service_get_all_by_project.return_value = [
            self.ss_active_directory,
            self.ss_ldap,
        ]
        for opt, val in self.valid_search_opts.items():
            for use_admin_context in [True, False]:
                req = fakes.HTTPRequest.blank(
                    '/security-services?' + opt + '=' + val,
                    use_admin_context=use_admin_context)
                res_dict = self.controller.index(req)
                self.assertEqual(self.security_service_list_expected_resp,
                                 res_dict)
                db.security_service_get_all_by_project.assert_called_with(
                    req.environ['manila.context'],
                    req.environ['manila.context'].project_id)

    @mock.patch.object(db, 'security_service_get_all_by_project', mock.Mock())
    def test_security_service_list_all_filter_opts(self):
        db.security_service_get_all_by_project.return_value = [
            self.ss_active_directory,
            self.ss_ldap,
        ]
        query_string = '/security-services?' + parse.urlencode(sorted(
            [(k, v) for (k, v) in list(self.valid_search_opts.items())]))
        for use_admin_context in [True, False]:
            req = fakes.HTTPRequest.blank(query_string,
                                          use_admin_context=use_admin_context)
            res_dict = self.controller.index(req)
            self.assertEqual(self.security_service_list_expected_resp,
                             res_dict)
            db.security_service_get_all_by_project.assert_called_with(
                req.environ['manila.context'],
                req.environ['manila.context'].project_id)
