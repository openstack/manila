# Copyright 2013 OpenStack Foundation
# All Rights Reserved
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

from manila.common import constants
from manila import context
from manila.db import api as db_api
from manila import exception
from manila import test


security_service_dict = {'id': 'fake id',
                         'project_id': 'fake project',
                         'type': 'ldap',
                         'dns_ip': 'fake dns',
                         'server': 'fake ldap server',
                         'domain': 'fake ldap domain',
                         'sid': 'fake sid',
                         'name': 'whatever',
                         'description': 'nevermind',
                         'status': constants.STATUS_NEW}


class SecurityServiceDBTest(test.TestCase):

    def __init__(self, *args, **kwargs):
        super(SecurityServiceDBTest, self).__init__(*args, **kwargs)

        self.fake_context = context.RequestContext(user_id='fake user',
                                           project_id='fake project',
                                           is_admin=False)

    def _check_expected_fields(self, result, expected):
        for key in expected:
            self.assertEqual(result[key], expected[key])

    def test_create(self):
        result = db_api.security_service_create(self.fake_context,
                                                security_service_dict)

        self._check_expected_fields(result, security_service_dict)

    def test_get(self):
        db_api.security_service_create(self.fake_context,
                                       security_service_dict)

        result = db_api.security_service_get(self.fake_context,
                                             security_service_dict['id'])

        self._check_expected_fields(result, security_service_dict)

    def test_get_not_found(self):
        self.assertRaises(exception.SecurityServiceNotFound,
                          db_api.security_service_get,
                          self.fake_context,
                          'wrong id')

    def test_delete(self):
        db_api.security_service_create(self.fake_context,
                                       security_service_dict)

        db_api.security_service_delete(self.fake_context,
                                       security_service_dict['id'])

        self.assertRaises(exception.SecurityServiceNotFound,
                          db_api.security_service_get,
                          self.fake_context,
                          security_service_dict['id'])

    def test_update(self):
        update_dict = {'dns_ip': 'new dns',
                       'server': 'new ldap server',
                       'domain': 'new ldap domain',
                       'sid': 'new sid',
                       'name': 'new whatever',
                       'description': 'new nevermind',
                       'status': constants.STATUS_ERROR}

        db_api.security_service_create(self.fake_context,
                                       security_service_dict)

        result = db_api.security_service_update(self.fake_context,
                                                security_service_dict['id'],
                                                update_dict)

        self._check_expected_fields(result, update_dict)

    def test_update_no_updates(self):
        db_api.security_service_create(self.fake_context,
                                       security_service_dict)

        result = db_api.security_service_update(self.fake_context,
                                                security_service_dict['id'],
                                                {})

        self._check_expected_fields(result, security_service_dict)

    def test_update_not_found(self):
        self.assertRaises(exception.SecurityServiceNotFound,
                          db_api.security_service_update,
                          self.fake_context,
                          'wrong id',
                          {})

    def test_get_all_no_records(self):
        result = db_api.security_service_get_all(self.fake_context)

        self.assertEqual(len(result), 0)

    def test_get_all_one_record(self):
        db_api.security_service_create(self.fake_context,
                                       security_service_dict)

        result = db_api.security_service_get_all(self.fake_context)

        self.assertEqual(len(result), 1)
        self._check_expected_fields(result[0], security_service_dict)

    def test_get_all_two_records(self):
        dict1 = security_service_dict
        dict2 = security_service_dict.copy()
        dict2['id'] = 'fake id 2'
        db_api.security_service_create(self.fake_context,
                                       dict1)
        db_api.security_service_create(self.fake_context,
                                       dict2)

        result = db_api.security_service_get_all(self.fake_context)

        self.assertEqual(len(result), 2)

    def test_get_all_by_project(self):
        dict1 = security_service_dict
        dict2 = security_service_dict.copy()
        dict2['id'] = 'fake id 2'
        dict2['project_id'] = 'fake project 2'
        db_api.security_service_create(self.fake_context,
                                       dict1)
        db_api.security_service_create(self.fake_context,
                                       dict2)

        result1 = db_api.security_service_get_all_by_project(
                    self.fake_context,
                    dict1['project_id'])

        self.assertEqual(len(result1), 1)
        self._check_expected_fields(result1[0], dict1)

        result2 = db_api.security_service_get_all_by_project(
                    self.fake_context,
                    dict2['project_id'])

        self.assertEqual(len(result2), 1)
        self._check_expected_fields(result2[0], dict2)
