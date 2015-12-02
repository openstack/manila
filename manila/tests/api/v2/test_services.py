# Copyright 2012 IBM Corp.
# Copyright 2014 Mirantis Inc.
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
from oslo_utils import timeutils

from manila.api.v2 import services
from manila import context
from manila import db
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes


fake_services_list = [
    {
        'binary': 'manila-scheduler',
        'host': 'host1',
        'availability_zone': {'name': 'manila1'},
        'id': 1,
        'disabled': True,
        'updated_at': datetime.datetime(2012, 10, 29, 13, 42, 2),
        'created_at': datetime.datetime(2012, 9, 18, 2, 46, 27),
    },
    {
        'binary': 'manila-share',
        'host': 'host1',
        'availability_zone': {'name': 'manila1'},
        'id': 2,
        'disabled': True,
        'updated_at': datetime.datetime(2012, 10, 29, 13, 42, 5),
        'created_at': datetime.datetime(2012, 9, 18, 2, 46, 27)},
    {
        'binary': 'manila-scheduler',
        'host': 'host2',
        'availability_zone': {'name': 'manila2'},
        'id': 3,
        'disabled': False,
        'updated_at': datetime.datetime(2012, 9, 19, 6, 55, 34),
        'created_at': datetime.datetime(2012, 9, 18, 2, 46, 28)},
    {
        'binary': 'manila-share',
        'host': 'host2',
        'availability_zone': {'name': 'manila2'},
        'id': 4,
        'disabled': True,
        'updated_at': datetime.datetime(2012, 9, 18, 8, 3, 38),
        'created_at': datetime.datetime(2012, 9, 18, 2, 46, 28),
    },
]


fake_response_service_list = {'services': [
    {
        'id': 1,
        'binary': 'manila-scheduler',
        'host': 'host1',
        'zone': 'manila1',
        'status': 'disabled', 'state': 'up',
        'updated_at': datetime.datetime(2012, 10, 29, 13, 42, 2),
    },
    {
        'id': 2,
        'binary': 'manila-share',
        'host': 'host1',
        'zone': 'manila1',
        'status': 'disabled',
        'state': 'up',
        'updated_at': datetime.datetime(2012, 10, 29, 13, 42, 5),
    },
    {
        'id': 3,
        'binary': 'manila-scheduler',
        'host': 'host2',
        'zone': 'manila2',
        'status': 'enabled',
        'state': 'down',
        'updated_at': datetime.datetime(2012, 9, 19, 6, 55, 34),
    },
    {
        'id': 4,
        'binary': 'manila-share',
        'host': 'host2',
        'zone': 'manila2',
        'status': 'disabled',
        'state': 'down',
        'updated_at': datetime.datetime(2012, 9, 18, 8, 3, 38),
    },
]}


def fake_service_get_all(context):
    return fake_services_list


def fake_service_get_by_host_binary(context, host, binary):
    for service in fake_services_list:
        if service['host'] == host and service['binary'] == binary:
            return service
    return None


def fake_service_get_by_id(value):
    for service in fake_services_list:
        if service['id'] == value:
            return service
    return None


def fake_service_update(context, service_id, values):
    service = fake_service_get_by_id(service_id)
    if service is None:
        raise exception.ServiceNotFound(service_id=service_id)
    else:
        {'host': 'host1', 'binary': 'manila-share',
         'disabled': values['disabled']}


def fake_utcnow():
    return datetime.datetime(2012, 10, 29, 13, 42, 11)


@ddt.ddt
class ServicesTest(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()

        self.mock_object(db, "service_get_all", fake_service_get_all)
        self.mock_object(timeutils, "utcnow", fake_utcnow)
        self.mock_object(db, "service_get_by_args",
                         fake_service_get_by_host_binary)
        self.mock_object(db, "service_update", fake_service_update)
        self.context = context.get_admin_context()
        self.controller = services.ServiceController()
        self.controller_legacy = services.ServiceControllerLegacy()
        self.resource_name = self.controller.resource_name
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))

    @ddt.data(
        ('os-services', '1.0', services.ServiceControllerLegacy),
        ('os-services', '2.6', services.ServiceControllerLegacy),
        ('services', '2.7', services.ServiceController),
    )
    @ddt.unpack
    def test_services_list(self, url, version, controller):
        req = fakes.HTTPRequest.blank('/%s' % url, version=version)
        req.environ['manila.context'] = self.context

        res_dict = controller().index(req)

        self.assertEqual(fake_response_service_list, res_dict)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'index')

    def test_services_list_with_host(self):
        req = fakes.HTTPRequest.blank('/services?host=host1', version='2.7')
        req.environ['manila.context'] = self.context

        res_dict = self.controller.index(req)

        response = {'services': [
            fake_response_service_list['services'][0],
            fake_response_service_list['services'][1],
        ]}
        self.assertEqual(response, res_dict)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'index')

    def test_services_list_with_binary(self):
        req = fakes.HTTPRequest.blank(
            '/services?binary=manila-share', version='2.7')
        req.environ['manila.context'] = self.context

        res_dict = self.controller.index(req)

        response = {'services': [
            fake_response_service_list['services'][1],
            fake_response_service_list['services'][3],
        ]}

        self.assertEqual(response, res_dict)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'index')

    def test_services_list_with_zone(self):
        req = fakes.HTTPRequest.blank('/services?zone=manila1', version='2.7')
        req.environ['manila.context'] = self.context

        res_dict = self.controller.index(req)

        response = {'services': [
            fake_response_service_list['services'][0],
            fake_response_service_list['services'][1],
        ]}
        self.assertEqual(response, res_dict)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'index')

    def test_services_list_with_status(self):
        req = fakes.HTTPRequest.blank(
            '/services?status=enabled', version='2.7')
        req.environ['manila.context'] = self.context

        res_dict = self.controller.index(req)

        response = {'services': [
            fake_response_service_list['services'][2],
        ]}
        self.assertEqual(response, res_dict)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'index')

    def test_services_list_with_state(self):
        req = fakes.HTTPRequest.blank('/services?state=up', version='2.7')
        req.environ['manila.context'] = self.context

        res_dict = self.controller.index(req)

        response = {'services': [
            fake_response_service_list['services'][0],
            fake_response_service_list['services'][1],
        ]}
        self.assertEqual(response, res_dict)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'index')

    def test_services_list_with_host_binary(self):
        req = fakes.HTTPRequest.blank(
            "/services?binary=manila-share&state=up", version='2.7')
        req.environ['manila.context'] = self.context

        res_dict = self.controller.index(req)

        response = {'services': [fake_response_service_list['services'][1], ]}
        self.assertEqual(response, res_dict)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'index')

    @ddt.data(
        ('os-services', '1.0', services.ServiceControllerLegacy),
        ('os-services', '2.6', services.ServiceControllerLegacy),
        ('services', '2.7', services.ServiceController),
    )
    @ddt.unpack
    def test_services_enable(self, url, version, controller):
        body = {'host': 'host1', 'binary': 'manila-share'}
        req = fakes.HTTPRequest.blank('/fooproject/%s' % url, version=version)

        res_dict = controller().update(req, "enable", body)

        self.assertFalse(res_dict['disabled'])
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'update')

    @ddt.data(
        ('os-services', '1.0', services.ServiceControllerLegacy),
        ('os-services', '2.6', services.ServiceControllerLegacy),
        ('services', '2.7', services.ServiceController),
    )
    @ddt.unpack
    def test_services_disable(self, url, version, controller):
        req = fakes.HTTPRequest.blank(
            '/fooproject/%s/disable' % url, version=version)
        body = {'host': 'host1', 'binary': 'manila-share'}

        res_dict = controller().update(req, "disable", body)

        self.assertTrue(res_dict['disabled'])
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'update')

    @ddt.data(
        ('os-services', '2.7', services.ServiceControllerLegacy),
        ('services', '2.6', services.ServiceController),
        ('services', '1.0', services.ServiceController),
    )
    @ddt.unpack
    def test_services_update_legacy_url_2_dot_7_api_not_found(self, url,
                                                              version,
                                                              controller):
        req = fakes.HTTPRequest.blank(
            '/fooproject/%s/fake' % url, version=version)
        body = {'host': 'host1', 'binary': 'manila-share'}

        self.assertRaises(
            exception.VersionNotFoundForAPIMethod,
            controller().update,
            req, "disable", body,
        )

    @ddt.data(
        ('os-services', '2.7', services.ServiceControllerLegacy),
        ('services', '2.6', services.ServiceController),
        ('services', '1.0', services.ServiceController),
    )
    @ddt.unpack
    def test_services_list_api_not_found(self, url, version, controller):
        req = fakes.HTTPRequest.blank('/fooproject/%s' % url, version=version)

        self.assertRaises(
            exception.VersionNotFoundForAPIMethod, controller().index, req)
