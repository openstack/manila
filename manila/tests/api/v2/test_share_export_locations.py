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

from manila.api.v2 import share_export_locations as export_locations
from manila import context
from manila import db
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils


@ddt.ddt
class ShareExportLocationsAPITest(test.TestCase):

    def _get_request(self, version="2.9", use_admin_context=True):
        req = fakes.HTTPRequest.blank(
            '/v2/shares/%s/export_locations' % self.share_instance_id,
            version=version, use_admin_context=use_admin_context)
        return req

    def setUp(self):
        super(self.__class__, self).setUp()
        self.controller = (
            export_locations.ShareExportLocationController())
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

    @ddt.data({'role': 'admin', 'version': '2.9'},
              {'role': 'user', 'version': '2.9'},
              {'role': 'admin', 'version': '2.13'},
              {'role': 'user', 'version': '2.13'})
    @ddt.unpack
    def test_list_and_show(self, role, version):

        summary_keys = ['id', 'path']
        admin_summary_keys = summary_keys + [
            'share_instance_id', 'is_admin_only']
        detail_keys = summary_keys + ['created_at', 'updated_at']
        admin_detail_keys = admin_summary_keys + ['created_at', 'updated_at']

        self._test_list_and_show(role, version, summary_keys, detail_keys,
                                 admin_summary_keys, admin_detail_keys)

    @ddt.data('admin', 'user')
    def test_list_and_show_with_preferred_flag(self, role):

        summary_keys = ['id', 'path', 'preferred']
        admin_summary_keys = summary_keys + [
            'share_instance_id', 'is_admin_only']
        detail_keys = summary_keys + ['created_at', 'updated_at']
        admin_detail_keys = admin_summary_keys + ['created_at', 'updated_at']

        self._test_list_and_show(role, '2.14', summary_keys, detail_keys,
                                 admin_summary_keys, admin_detail_keys)

    def _test_list_and_show(self, role, version, summary_keys, detail_keys,
                            admin_summary_keys, admin_detail_keys):

        req = self._get_request(version=version,
                                use_admin_context=(role == 'admin'))
        index_result = self.controller.index(req, self.share['id'])

        self.assertIn('export_locations', index_result)
        self.assertEqual(1, len(index_result))
        self.assertEqual(3, len(index_result['export_locations']))

        for index_el in index_result['export_locations']:
            self.assertIn('id', index_el)
            show_result = self.controller.show(
                req, self.share['id'], index_el['id'])
            self.assertIn('export_location', show_result)
            self.assertEqual(1, len(show_result))

            show_el = show_result['export_location']

            # Check summary keys in index result & detail keys in show result
            if role == 'admin':
                self.assertEqual(len(admin_summary_keys), len(index_el))
                for key in admin_summary_keys:
                    self.assertIn(key, index_el)
                self.assertEqual(len(admin_detail_keys), len(show_el))
                for key in admin_detail_keys:
                    self.assertIn(key, show_el)
            else:
                self.assertEqual(len(summary_keys), len(index_el))
                for key in summary_keys:
                    self.assertIn(key, index_el)
                self.assertEqual(len(detail_keys), len(show_el))
                for key in detail_keys:
                    self.assertIn(key, show_el)

            # Ensure keys common to index & show results have matching values
            for key in summary_keys:
                self.assertEqual(index_el[key], show_el[key])

    def test_list_export_locations_share_not_found(self):
        self.assertRaises(
            exc.HTTPNotFound,
            self.controller.index,
            self.req, 'inexistent_share_id',
        )

    def test_show_export_location_share_not_found(self):
        index_result = self.controller.index(self.req, self.share['id'])
        el_id = index_result['export_locations'][0]['id']
        self.assertRaises(
            exc.HTTPNotFound,
            self.controller.show,
            self.req, 'inexistent_share_id', el_id,
        )

    def test_show_export_location_not_found(self):
        self.assertRaises(
            exc.HTTPNotFound,
            self.controller.show,
            self.req, self.share['id'], 'inexistent_export_location',
        )

    def test_get_admin_export_location(self):
        el_data = {
            'path': '/admin/export/location',
            'is_admin_only': True,
            'metadata': {'foo': 'bar'},
        }
        db.share_export_locations_update(
            self.ctxt['admin'], self.share_instance_id, el_data, True)
        index_result = self.controller.index(self.req, self.share['id'])
        el_id = index_result['export_locations'][0]['id']

        # Not found for member
        member_req = self._get_request(use_admin_context=False)
        self.assertRaises(
            exc.HTTPForbidden,
            self.controller.show,
            member_req, self.share['id'], el_id,
        )

        # Ok for admin
        el = self.controller.show(self.req, self.share['id'], el_id)
        for k, v in el.items():
            self.assertEqual(v, el[k])

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
        index_result = self.controller.index(self.req, self.share['id'])

        self.assertRaises(
            exception.VersionNotFoundForAPIMethod,
            self.controller.show,
            self._get_request(version),
            self.share['id'],
            index_result['export_locations'][0]['id']
        )
