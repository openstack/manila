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

from unittest import mock

import ddt
from webob import exc

from manila.api.v2 import share_replica_export_locations as export_locations
from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila import policy
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils


GRADUATION_VERSION = '2.56'


@ddt.ddt
class ShareReplicaExportLocationsAPITest(test.TestCase):

    def _get_request(self, version="2.47", use_admin_context=False):
        req = fakes.HTTPRequest.blank(
            '/v2/share-replicas/%s/export-locations' % self.active_replica_id,
            version=version, use_admin_context=use_admin_context,
            experimental=True)
        return req

    def setUp(self):
        super(ShareReplicaExportLocationsAPITest, self).setUp()
        self.controller = (
            export_locations.ShareReplicaExportLocationController())
        self.resource_name = 'share_replica_export_location'
        self.ctxt = context.RequestContext('fake', 'fake')
        self.mock_policy_check = self.mock_object(
            policy, 'check_policy', mock.Mock(return_value=True))
        self.share = db_utils.create_share(
            replication_type=constants.REPLICATION_TYPE_READABLE,
            replica_state=constants.REPLICA_STATE_ACTIVE)
        self.active_replica_id = self.share.instance.id
        self.req = self._get_request()
        exports = [
            {'path': 'myshare.mydomain/active-replica-exp1',
             'is_admin_only': False},
            {'path': 'myshare.mydomain/active-replica-exp2',
             'is_admin_only': False},
        ]
        db.share_export_locations_update(
            self.ctxt, self.active_replica_id, exports)

        # Replicas
        self.share_replica2 = db_utils.create_share_replica(
            share_id=self.share.id,
            replica_state=constants.REPLICA_STATE_IN_SYNC)
        self.share_replica3 = db_utils.create_share_replica(
            share_id=self.share.id,
            replica_state=constants.REPLICA_STATE_OUT_OF_SYNC)
        replica2_exports = [
            {'path': 'myshare.mydomain/insync-replica-exp',
             'is_admin_only': False},
            {'path': 'myshare.mydomain/insync-replica-exp2',
             'is_admin_only': False}
        ]
        replica3_exports = [
            {'path': 'myshare.mydomain/outofsync-replica-exp',
             'is_admin_only': False},
            {'path': 'myshare.mydomain/outofsync-replica-exp2',
             'is_admin_only': False}
        ]
        db.share_export_locations_update(
            self.ctxt, self.share_replica2.id, replica2_exports)
        db.share_export_locations_update(
            self.ctxt, self.share_replica3.id, replica3_exports)

    @ddt.data(('user', '2.47'), ('admin', GRADUATION_VERSION))
    @ddt.unpack
    def test_list_and_show(self, role, microversion):
        summary_keys = [
            'id', 'path', 'replica_state', 'availability_zone', 'preferred'
        ]
        admin_summary_keys = summary_keys + [
            'share_instance_id', 'is_admin_only'
        ]
        detail_keys = summary_keys + ['created_at', 'updated_at']
        admin_detail_keys = admin_summary_keys + ['created_at', 'updated_at']

        self._test_list_and_show(role, summary_keys, detail_keys,
                                 admin_summary_keys, admin_detail_keys,
                                 microversion=microversion)

    def _test_list_and_show(self, role, summary_keys, detail_keys,
                            admin_summary_keys, admin_detail_keys,
                            microversion='2.47'):

        req = self._get_request(version=microversion,
                                use_admin_context=(role == 'admin'))
        for replica_id in (self.active_replica_id, self.share_replica2.id,
                           self.share_replica3.id):
            index_result = self.controller.index(req, replica_id)

            self.assertIn('export_locations', index_result)
            self.assertEqual(1, len(index_result))
            self.assertEqual(2, len(index_result['export_locations']))

            for index_el in index_result['export_locations']:
                self.assertIn('id', index_el)
                show_result = self.controller.show(
                    req, replica_id, index_el['id'])
                self.assertIn('export_location', show_result)
                self.assertEqual(1, len(show_result))

                show_el = show_result['export_location']

                # Check summary keys in index result & detail keys in show
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

                # Ensure keys common to index & show have matching values
                for key in summary_keys:
                    self.assertEqual(index_el[key], show_el[key])

    def test_list_and_show_with_non_replicas(self):
        non_replicated_share = db_utils.create_share()
        instance_id = non_replicated_share.instance.id
        exports = [
            {'path': 'myshare.mydomain/non-replicated-share',
             'is_admin_only': False},
            {'path': 'myshare.mydomain/non-replicated-share-2',
             'is_admin_only': False},
        ]
        db.share_export_locations_update(self.ctxt, instance_id, exports)
        updated_exports = db.share_export_locations_get_by_share_id(
            self.ctxt, non_replicated_share.id)

        self.assertRaises(exc.HTTPNotFound, self.controller.index, self.req,
                          instance_id)

        for export in updated_exports:
            self.assertRaises(exc.HTTPNotFound, self.controller.show, self.req,
                              instance_id, export['id'])

    def test_list_export_locations_share_replica_not_found(self):
        self.assertRaises(
            exc.HTTPNotFound,
            self.controller.index,
            self.req, 'non-existent-share-replica-id')

    def test_show_export_location_share_replica_not_found(self):
        index_result = self.controller.index(self.req, self.active_replica_id)
        el_id = index_result['export_locations'][0]['id']

        self.assertRaises(
            exc.HTTPNotFound,
            self.controller.show,
            self.req, 'non-existent-share-replica-id', el_id)

        self.assertRaises(
            exc.HTTPNotFound,
            self.controller.show,
            self.req, self.active_replica_id,
            'non-existent-export-location-id')

    @ddt.data('1.0', '2.0', '2.46')
    def test_list_with_unsupported_version(self, version):
        self.assertRaises(
            exception.VersionNotFoundForAPIMethod,
            self.controller.index,
            self._get_request(version),
            self.active_replica_id)

    @ddt.data('1.0', '2.0', '2.46')
    def test_show_with_unsupported_version(self, version):
        index_result = self.controller.index(self.req, self.active_replica_id)

        self.assertRaises(
            exception.VersionNotFoundForAPIMethod,
            self.controller.show,
            self._get_request(version),
            self.active_replica_id,
            index_result['export_locations'][0]['id'])
