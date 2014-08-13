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


from datetime import datetime

from manila.api.contrib import services
from manila import context
from manila import db
from manila import exception
from manila.openstack.common import timeutils
from manila import policy
from manila import test
from manila.tests.api import fakes


fake_services_list = [
    {
        'binary': 'manila-scheduler',
        'host': 'host1',
        'availability_zone': 'manila1',
        'id': 1,
        'disabled': True,
        'updated_at': datetime(2012, 10, 29, 13, 42, 2),
        'created_at': datetime(2012, 9, 18, 2, 46, 27),
    },
    {
        'binary': 'manila-share',
        'host': 'host1',
        'availability_zone': 'manila1',
        'id': 2,
        'disabled': True,
        'updated_at': datetime(2012, 10, 29, 13, 42, 5),
        'created_at': datetime(2012, 9, 18, 2, 46, 27)},
    {
        'binary': 'manila-scheduler',
        'host': 'host2',
        'availability_zone': 'manila2',
        'id': 3,
        'disabled': False,
        'updated_at': datetime(2012, 9, 19, 6, 55, 34),
        'created_at': datetime(2012, 9, 18, 2, 46, 28)},
    {
        'binary': 'manila-share',
        'host': 'host2',
        'availability_zone': 'manila2',
        'id': 4,
        'disabled': True,
        'updated_at': datetime(2012, 9, 18, 8, 3, 38),
        'created_at': datetime(2012, 9, 18, 2, 46, 28),
    },
]


fake_response_service_list = {'services': [
    {
        'binary': 'manila-scheduler',
        'host': 'host1',
        'zone': 'manila1',
        'status': 'disabled', 'state': 'up',
        'updated_at': datetime(2012, 10, 29, 13, 42, 2),
    },
    {
        'binary': 'manila-share',
        'host': 'host1',
        'zone': 'manila1',
        'status': 'disabled',
        'state': 'up',
        'updated_at': datetime(2012, 10, 29, 13, 42, 5),
    },
    {
        'binary': 'manila-scheduler',
        'host': 'host2',
        'zone': 'manila2',
        'status': 'enabled',
        'state': 'down',
        'updated_at': datetime(2012, 9, 19, 6, 55, 34),
    },
    {
        'binary': 'manila-share',
        'host': 'host2',
        'zone': 'manila2',
        'status': 'disabled',
        'state': 'down',
        'updated_at': datetime(2012, 9, 18, 8, 3, 38),
    },
]}


class FakeRequest(object):
    environ = {"manila.context": context.get_admin_context()}
    GET = {}


class FakeRequestWithBinary(object):
    environ = {"manila.context": context.get_admin_context()}
    GET = {"binary": "manila-share"}


class FakeRequestWithHost(object):
    environ = {"manila.context": context.get_admin_context()}
    GET = {"host": "host1"}


class FakeRequestWithZone(object):
    environ = {"manila.context": context.get_admin_context()}
    GET = {"zone": "manila1"}


class FakeRequestWithStatus(object):
    environ = {"manila.context": context.get_admin_context()}
    GET = {"status": "enabled"}


class FakeRequestWithState(object):
    environ = {"manila.context": context.get_admin_context()}
    GET = {"state": "up"}


class FakeRequestWithHostBinary(object):
    environ = {"manila.context": context.get_admin_context()}
    GET = {"host": "host1", "binary": "manila-share"}


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


def fake_policy_enforce(context, action, target):
    pass


def fake_utcnow():
    return datetime(2012, 10, 29, 13, 42, 11)


class ServicesTest(test.TestCase):

    def setUp(self):
        super(ServicesTest, self).setUp()

        self.stubs.Set(db, "service_get_all", fake_service_get_all)
        self.stubs.Set(timeutils, "utcnow", fake_utcnow)
        self.stubs.Set(db, "service_get_by_args",
                       fake_service_get_by_host_binary)
        self.stubs.Set(db, "service_update", fake_service_update)
        self.stubs.Set(policy, "enforce", fake_policy_enforce)

        self.context = context.get_admin_context()
        self.controller = services.ServiceController()

    def tearDown(self):
        super(ServicesTest, self).tearDown()

    def test_services_list(self):
        req = FakeRequest()
        res_dict = self.controller.index(req)
        self.assertEqual(res_dict, fake_response_service_list)

    def test_services_list_with_host(self):
        req = FakeRequestWithHost()
        res_dict = self.controller.index(req)

        response = {'services': [
            fake_response_service_list['services'][0],
            fake_response_service_list['services'][1],
        ]}
        self.assertEqual(res_dict, response)

    def test_services_list_with_binary(self):
        req = FakeRequestWithBinary()
        res_dict = self.controller.index(req)
        response = {'services': [
            fake_response_service_list['services'][1],
            fake_response_service_list['services'][3],
        ]}

        self.assertEqual(res_dict, response)

    def test_services_list_with_zone(self):
        req = FakeRequestWithZone()
        res_dict = self.controller.index(req)
        response = {'services': [
            fake_response_service_list['services'][0],
            fake_response_service_list['services'][1],
        ]}
        self.assertEqual(res_dict, response)

    def test_services_list_with_status(self):
        req = FakeRequestWithStatus()
        res_dict = self.controller.index(req)
        response = {'services': [
            fake_response_service_list['services'][2],
        ]}
        self.assertEqual(res_dict, response)

    def test_services_list_with_state(self):
        req = FakeRequestWithState()
        res_dict = self.controller.index(req)
        response = {'services': [
            fake_response_service_list['services'][0],
            fake_response_service_list['services'][1],
        ]}
        self.assertEqual(res_dict, response)

    def test_services_list_with_host_binary(self):
        req = FakeRequestWithHostBinary()
        res_dict = self.controller.index(req)
        response = {'services': [fake_response_service_list['services'][1], ]}
        self.assertEqual(res_dict, response)

    def test_services_enable(self):
        body = {'host': 'host1', 'binary': 'manila-share'}
        req = fakes.HTTPRequest.blank('/v1/fake/os-services/enable')
        res_dict = self.controller.update(req, "enable", body)
        self.assertEqual(res_dict['disabled'], False)

    def test_services_disable(self):
        req = fakes.HTTPRequest.blank('/v1/fake/os-services/disable')
        body = {'host': 'host1', 'binary': 'manila-share'}
        res_dict = self.controller.update(req, "disable", body)
        self.assertEqual(res_dict['disabled'], True)
