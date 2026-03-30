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
import random
from unittest import mock
import webob

import ddt
from oslo_utils import strutils
from oslo_utils import timeutils

from manila.api.openstack import api_version_request as api_version
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
        'disabled_reason': 'test1',
        'state': 'up',
        'updated_at': datetime.datetime(2012, 10, 29, 13, 42, 2),
        'created_at': datetime.datetime(2012, 9, 18, 2, 46, 27),
    },
    {
        'binary': 'manila-share',
        'host': 'host1',
        'availability_zone': {'name': 'manila1'},
        'id': 2,
        'disabled': True,
        'disabled_reason': 'test2',
        'state': 'up',
        'updated_at': datetime.datetime(2012, 10, 29, 13, 42, 5),
        'created_at': datetime.datetime(2012, 9, 18, 2, 46, 27)},
    {
        'binary': 'manila-scheduler',
        'host': 'host2',
        'availability_zone': {'name': 'manila2'},
        'id': 3,
        'disabled': False,
        'disabled_reason': '',
        'state': 'down',
        'updated_at': datetime.datetime(2012, 9, 19, 6, 55, 34),
        'created_at': datetime.datetime(2012, 9, 18, 2, 46, 28)},
    {
        'binary': 'manila-share',
        'host': 'host2',
        'availability_zone': {'name': 'manila2'},
        'id': 4,
        'disabled': True,
        'disabled_reason': 'test4',
        'state': 'down',
        'updated_at': datetime.datetime(2012, 9, 18, 8, 3, 38),
        'created_at': datetime.datetime(2012, 9, 18, 2, 46, 28),
    },
]

ENSURE_SHARES_VERSION = "2.86"
FILTERING_BY_ENSURE_VERSION = "2.93"


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
        super(ServicesTest, self).setUp()

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

    def _generate_fake_response_service_list(self, with_disabled_reason=False,
                                             with_ensuring=False):
        fake_services = []
        for i in range(0, 3):
            service = {
                'id': i,
                'binary': random.choice([
                    'manila-scheduler', 'manila-share']),
                'host': 'host1',
                'availability_zone': {
                    'name': random.choice(['manila1', 'manila2'])
                },
                'disabled': False,
                'state': 'up',
                'updated_at': datetime.datetime(2012, 10, 29, 13, 42, 2),
            }
            if with_disabled_reason:
                service['disabled_reason'] = f'test{i}'
            if with_ensuring:
                service['ensuring'] = random.choice([True, False])
            fake_services.append(service)
        return fake_services

    @ddt.data(
        ('os-services', '2.6', services.ServiceControllerLegacy),
        ('services', '2.7', services.ServiceController),
        ('services', '2.83', services.ServiceController),
        ('services', '2.86', services.ServiceController),
    )
    @ddt.unpack
    def test_services_list(self, url, version, controller):
        req = fakes.HTTPRequest.blank('/%s' % url, version=version)
        req.environ['manila.context'] = self.context
        with_disabled_reason = (
            api_version.APIVersionRequest(version) >=
            api_version.APIVersionRequest('2.83')
        )
        with_ensuring = (
            api_version.APIVersionRequest(version) >=
            api_version.APIVersionRequest('2.86')
        )
        expected_return = {
            'services': self._generate_fake_response_service_list(
                with_disabled_reason=with_disabled_reason,
                with_ensuring=with_ensuring)
        }
        mock_service_get_all = self.mock_object(
            db, 'service_get_all_with_filters',
            mock.Mock(return_value=expected_return['services'])
        )
        expected_services_result = expected_return

        res_dict = controller().index(req)

        for service in expected_services_result['services']:
            service['status'] = (
                'disabled' if service['disabled'] else 'enabled'
            )
            service.pop('disabled')
            service['zone'] = service['availability_zone']['name']
            service.pop('availability_zone')

        self.assertEqual(expected_services_result, res_dict)
        mock_service_get_all.assert_called_once_with(self.context, req.GET)
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'index')

    @ddt.data(
        ({'ensuring': 'True'}, ENSURE_SHARES_VERSION),
        ({'host': 'fakehost@fakebackend', 'ensuring': 'True'},
         FILTERING_BY_ENSURE_VERSION),
        ({'host': 'fakehost@fakebackend', 'topic': 'manila-share'},
         FILTERING_BY_ENSURE_VERSION),
    )
    @ddt.unpack
    def test_services_list_with_search_opts(self, filters, version):
        url = '/services?'
        for k, v in filters.items():
            url += '%s=%s&' % (k, v)

        req = fakes.HTTPRequest.blank(url, version=version)
        req.environ['manila.context'] = self.context
        fake_response = {
            'services': self._generate_fake_response_service_list(
                with_disabled_reason=True, with_ensuring=True)
        }

        mock_service_get_all = self.mock_object(
            db, 'service_get_all_with_filters',
            mock.Mock(return_value=fake_response['services'])
        )
        expected_services_result = fake_response

        supports_filtering_by_ensuring = (
            api_version.APIVersionRequest(version) >=
            api_version.APIVersionRequest(FILTERING_BY_ENSURE_VERSION)
        )
        if not supports_filtering_by_ensuring and 'ensuring' in filters:
            filters.pop('ensuring')
        elif 'ensuring' in filters:
            filters['ensuring'] = strutils.bool_from_string(
                filters['ensuring'], strict=True)

        self.controller.index(req)

        for service in expected_services_result['services']:
            service['status'] = (
                'disabled' if service['disabled'] else 'enabled'
            )
            service['zone'] = service['availability_zone']['name']
            service.pop('availability_zone')

        mock_service_get_all.assert_called_once_with(self.context, filters)

    @ddt.data(
        (services.ServiceControllerLegacy, '2.6'),
        (services.ServiceController, '2.85'))
    @ddt.unpack
    def test_services_list_ensuring_provided_but_not_supported(
            self, controller, version):
        fake_response = {
            'services': self._generate_fake_response_service_list(
                with_disabled_reason=True, with_ensuring=False)
        }
        req = fakes.HTTPRequest.blank(
            'services?ensuring=True', version=version)
        req.environ['manila.context'] = self.context
        mock_service_get_all = self.mock_object(
            db, 'service_get_all_with_filters',
            mock.Mock(return_value=fake_response['services'])
        )
        expected_services_result = fake_response

        res_dict = controller().index(req)

        for service in expected_services_result['services']:
            service['status'] = (
                'disabled' if service['disabled'] else 'enabled'
            )
            service.pop('disabled')
            service['zone'] = service['availability_zone']['name']
            service.pop('availability_zone')
            if (api_version.APIVersionRequest(version) <
                    api_version.APIVersionRequest('2.83')):
                service.pop('disabled_reason')

        self.assertEqual(expected_services_result, res_dict)
        mock_service_get_all.assert_called_once_with(self.context, {})
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'index')

    @ddt.data(('available', FILTERING_BY_ENSURE_VERSION),
              ('migrating', '2.85'))
    @ddt.unpack
    def test_services_list_invalid_status(self, status, version):
        req = fakes.HTTPRequest.blank('services?status=%s' % status,
                                      version=version)
        # We had introduced a regression in API version 2.93, so now we need to
        # ensure that the behavior is unchanged.
        req.environ['manila.context'] = self.context
        mock_log_warning = self.mock_object(services.LOG, 'warning')

        result = self.controller.index(req)
        self.assertEqual(len(result['services']), 0)
        mock_log_warning.assert_called()

    @ddt.data('maybe', 'invalid', '2', 'notabool')
    def test_services_list_invalid_ensuring(self, ensuring):
        req = fakes.HTTPRequest.blank(
            'services?ensuring=%s' % ensuring,
            version=FILTERING_BY_ENSURE_VERSION)
        req.environ['manila.context'] = self.context
        mock_log_warning = self.mock_object(services.LOG, 'warning')

        result = self.controller.index(req)
        self.assertEqual(len(result['services']), 0)
        mock_log_warning.assert_called()

    @ddt.data(
        ('services', '2.7', services.ServiceController),
        ('services', '2.92', services.ServiceController,),
    )
    @ddt.unpack
    def test_services_list_supports_ensure(self, url, version, controller):
        req = fakes.HTTPRequest.blank('/%s' % url, version=version)
        req.environ['manila.context'] = self.context
        mock__index = self.mock_object(controller, '_index')

        controller().index(req)

        mock__index.assert_called_once_with(req)

    @ddt.data(
        ('os-services', '2.6', services.ServiceControllerLegacy),
        ('services', '2.7', services.ServiceController),
    )
    @ddt.unpack
    def test_services_enable(self, url, version, controller):
        body = {'host': 'host1', 'binary': 'manila-share'}
        req = fakes.HTTPRequest.blank('/fooproject/%s' % url, version=version)

        res_dict = controller().update(req, "enable", body)

        self.assertEqual('enabled', res_dict['status'])
        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'update')

    @ddt.data(
        ('os-services', '2.6', services.ServiceControllerLegacy),
        ('services', '2.7', services.ServiceController),
        ('services', '2.83', services.ServiceController),
    )
    @ddt.unpack
    def test_services_disable(self, url, version, controller):
        req = fakes.HTTPRequest.blank(
            '/fooproject/%s/disable' % url, version=version)
        body = {'host': 'host1', 'binary': 'manila-share'}
        if (api_version.APIVersionRequest(version) >
                api_version.APIVersionRequest("2.83")):
            body['disabled_reason'] = 'test1'

        res_dict = controller().update(req, "disable", body)

        self.assertEqual('disabled', res_dict['status'])
        if (api_version.APIVersionRequest(version) >
                api_version.APIVersionRequest("2.83")):
            self.assertEqual(res_dict['disabled_reason'], 'test1')

        self.mock_policy_check.assert_called_once_with(
            req.environ['manila.context'], self.resource_name, 'update')

    @ddt.data(
        ('os-services', '2.7', services.ServiceControllerLegacy),
        ('services', '2.6', services.ServiceController),
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
    )
    @ddt.unpack
    def test_services_list_api_not_found(self, url, version, controller):
        req = fakes.HTTPRequest.blank('/fooproject/%s' % url, version=version)

        self.assertRaises(
            exception.VersionNotFoundForAPIMethod, controller().index, req)

    def test_ensure_shares_no_host_param(self):
        req = fakes.HTTPRequest.blank(
            '/fooproject/services/ensure', version=ENSURE_SHARES_VERSION)
        body = {}

        self.assertRaises(
            exception.ValidationError,
            self.controller.ensure_shares,
            req,
            body=body
        )

    def test_ensure_shares_host_not_found(self):
        req = fakes.HTTPRequest.blank(
            '/fooproject/services/ensure', version=ENSURE_SHARES_VERSION)
        req_context = req.environ['manila.context']
        body = {'ensure_shares': {'host': 'host1'}}

        mock_service_get = self.mock_object(
            db, 'service_get_by_args',
            mock.Mock(side_effect=exception.NotFound())
        )

        self.assertRaises(
            webob.exc.HTTPNotFound,
            self.controller.ensure_shares,
            req,
            body=body
        )
        mock_service_get.assert_called_once_with(
            req_context,
            body['ensure_shares']['host'],
            'manila-share'
        )

    def test_ensure_shares_conflict(self):
        req = fakes.HTTPRequest.blank(
            '/fooproject/services/ensure', version=ENSURE_SHARES_VERSION)
        req_context = req.environ['manila.context']
        body = {'ensure_shares': {'host': 'host1'}}
        fake_service = {'id': 'fake_service_id'}

        mock_service_get = self.mock_object(
            db,
            'service_get_by_args',
            mock.Mock(return_value=fake_service)
        )
        mock_ensure = self.mock_object(
            self.controller.service_api,
            'ensure_shares',
            mock.Mock(side_effect=webob.exc.HTTPConflict)
        )

        self.assertRaises(
            webob.exc.HTTPConflict,
            self.controller.ensure_shares,
            req,
            body=body
        )
        mock_service_get.assert_called_once_with(
            req_context,
            body['ensure_shares']['host'],
            'manila-share'
        )
        mock_ensure.assert_called_once_with(
            req_context, fake_service, body['ensure_shares']['host']
        )

    def test_ensure_shares(self):
        req = fakes.HTTPRequest.blank(
            '/fooproject/services/ensure', version=ENSURE_SHARES_VERSION)
        req_context = req.environ['manila.context']
        body = {'ensure_shares': {'host': 'host1'}}
        fake_service = {'id': 'fake_service_id'}

        mock_service_get = self.mock_object(
            db,
            'service_get_by_args',
            mock.Mock(return_value=fake_service)
        )
        mock_ensure = self.mock_object(
            self.controller.service_api, 'ensure_shares',
        )

        response = self.controller.ensure_shares(req, body=body)

        self.assertEqual(202, response.status_int)
        mock_service_get.assert_called_once_with(
            req_context,
            body['ensure_shares']['host'],
            'manila-share'
        )
        mock_ensure.assert_called_once_with(
            req_context, fake_service, body['ensure_shares']['host']
        )
