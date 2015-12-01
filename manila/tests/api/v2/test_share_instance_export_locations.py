# Copyright (c) 2015 Mirantis Inc.
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
from webob import exc

from manila.api.v2 import share_instance_export_locations as export_locations
from manila import context
from manila import db
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils


@ddt.ddt
class ShareInstanceExportLocationsAPITest(test.TestCase):

    def _get_request(self, version="2.9", use_admin_context=True):
        req = fakes.HTTPRequest.blank(
            '/v2/share_instances/%s/export_locations' % self.share_instance_id,
            version=version, use_admin_context=use_admin_context)
        return req

    def setUp(self):
        super(self.__class__, self).setUp()
        self.controller = (
            export_locations.ShareInstanceExportLocationController())
        self.resource_name = self.controller.resource_name
        self.ctxt = {
            'admin': context.RequestContext('admin', 'fake', True),
            'user': context.RequestContext('fake', 'fake'),
        }
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        self.share = db_utils.create_share()
        self.share_instance_id = self.share.instance.id
        self.req = self._get_request()
        paths = ['fake1/1/', 'fake2/2', 'fake3/3']
        db.share_export_locations_update(
            self.ctxt['admin'], self.share_instance_id, paths, False)

    @ddt.data('admin', 'user')
    def test_list_and_show(self, role):
        req = self._get_request(use_admin_context=(role == 'admin'))
        index_result = self.controller.index(req, self.share_instance_id)

        self.assertIn('export_locations', index_result)
        self.assertEqual(1, len(index_result))
        self.assertEqual(3, len(index_result['export_locations']))

        for index_el in index_result['export_locations']:
            self.assertIn('uuid', index_el)
            show_result = self.controller.show(
                req, self.share_instance_id, index_el['uuid'])
            self.assertIn('export_location', show_result)
            self.assertEqual(1, len(show_result))
            expected_keys = (
                'created_at', 'updated_at', 'uuid', 'path',
                'share_instance_id', 'is_admin_only',
            )
            for el in (index_el, show_result['export_location']):
                self.assertEqual(len(expected_keys), len(el))
                for key in expected_keys:
                    self.assertIn(key, el)

            for key in expected_keys:
                self.assertEqual(
                    index_el[key], show_result['export_location'][key])

    def test_list_export_locations_share_instance_not_found(self):
        self.assertRaises(
            exc.HTTPNotFound,
            self.controller.index,
            self.req, 'inexistent_share_instance_id',
        )

    def test_show_export_location_share_instance_not_found(self):
        index_result = self.controller.index(self.req, self.share_instance_id)
        el_uuid = index_result['export_locations'][0]['uuid']

        self.assertRaises(
            exc.HTTPNotFound,
            self.controller.show,
            self.req, 'inexistent_share_id', el_uuid,
        )

    @ddt.data('1.0', '2.0', '2.8')
    def test_list_with_unsupported_version(self, version):
        self.assertRaises(
            exception.VersionNotFoundForAPIMethod,
            self.controller.index,
            self._get_request(version),
            self.share_instance_id,
        )

    @ddt.data('1.0', '2.0', '2.8')
    def test_show_with_unsupported_version(self, version):
        index_result = self.controller.index(self.req, self.share_instance_id)

        self.assertRaises(
            exception.VersionNotFoundForAPIMethod,
            self.controller.show,
            self._get_request(version),
            self.share_instance_id,
            index_result['export_locations'][0]['uuid']
        )
