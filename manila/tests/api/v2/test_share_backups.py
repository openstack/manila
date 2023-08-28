# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import ddt
from oslo_config import cfg
from unittest import mock
from webob import exc

from manila.api.v2 import share_backups
from manila.common import constants
from manila import context
from manila import exception
from manila import policy
from manila import share
from manila import test
from manila.tests.api import fakes
from manila.tests import db_utils
from manila.tests import fake_share

CONF = cfg.CONF


@ddt.ddt
class ShareBackupsApiTest(test.TestCase):
    """Share backups API Test Cases."""
    def setUp(self):
        super(ShareBackupsApiTest, self).setUp()
        self.controller = share_backups.ShareBackupController()
        self.resource_name = self.controller.resource_name
        self.api_version = share_backups.MIN_SUPPORTED_API_VERSION
        self.backups_req = fakes.HTTPRequest.blank(
            '/share-backups', version=self.api_version,
            experimental=True)
        self.member_context = context.RequestContext('fake', 'fake')
        self.backups_req.environ['manila.context'] = self.member_context
        self.backups_req_admin = fakes.HTTPRequest.blank(
            '/share-backups', version=self.api_version,
            experimental=True, use_admin_context=True)
        self.admin_context = self.backups_req_admin.environ['manila.context']
        self.mock_policy_check = self.mock_object(policy, 'check_policy')

    def _get_context(self, role):
        return getattr(self, '%s_context' % role)

    def _create_backup_get_req(self, **kwargs):
        if 'status' not in kwargs:
            kwargs['status'] = constants.STATUS_AVAILABLE
        backup = db_utils.create_share_backup(**kwargs)
        req = fakes.HTTPRequest.blank(
            '/v2/fake/share-backups/%s/action' % backup['id'],
            version=self.api_version)
        req.method = 'POST'
        req.headers['content-type'] = 'application/json'
        req.headers['X-Openstack-Manila-Api-Version'] = self.api_version
        req.headers['X-Openstack-Manila-Api-Experimental'] = True

        return backup, req

    def _get_fake_backup(self, admin=False, summary=False, **values):
        backup = fake_share.fake_backup(**values)
        backup['updated_at'] = '2016-06-12T19:57:56.506805'
        expected_keys = {'id', 'share_id', 'status'}
        expected_backup = {key: backup[key] for key in backup if key
                           in expected_keys}
        expected_backup.update({'name': backup.get('display_name')})

        if not summary:
            expected_backup.update({
                'id': backup.get('id'),
                'share_id': backup.get('share_id'),
                'status': backup.get('status'),
                'description': backup.get('display_description'),
                'size': backup.get('size'),
                'created_at': backup.get('created_at'),
                'updated_at': backup.get('updated_at'),
                'availability_zone': backup.get('availability_zone'),
                'progress': backup.get('progress'),
                'restore_progress': backup.get('restore_progress'),
            })
            if admin:
                expected_backup.update({
                    'host': backup.get('host'),
                    'topic': backup.get('topic'),
                })

        return backup, expected_backup

    def test_list_backups_summary(self):
        fake_backup, expected_backup = self._get_fake_backup(summary=True)
        self.mock_object(share_backups.db, 'share_backups_get_all',
                         mock.Mock(return_value=[fake_backup]))

        res_dict = self.controller.index(self.backups_req)
        self.assertEqual([expected_backup], res_dict['share_backups'])
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'get_all')

    def test_list_backups_summary_with_share_id(self):
        fake_backup, expected_backup = self._get_fake_backup(summary=True)
        self.mock_object(share.API, 'get',
                         mock.Mock(return_value={'id': 'FAKE_SHAREID'}))
        self.mock_object(share_backups.db, 'share_backups_get_all',
                         mock.Mock(return_value=[fake_backup]))
        req = fakes.HTTPRequest.blank(
            '/share-backups?share_id=FAKE_SHARE_ID',
            version=self.api_version, experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.index(req)

        self.assertEqual([expected_backup], res_dict['share_backups'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    @ddt.data(True, False)
    def test_list_backups_detail(self, is_admin):
        fake_backup, expected_backup = self._get_fake_backup(admin=is_admin)
        self.mock_object(share_backups.db, 'share_backups_get_all',
                         mock.Mock(return_value=[fake_backup]))

        req = self.backups_req if not is_admin else self.backups_req_admin
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        self.assertEqual([expected_backup], res_dict['share_backups'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_share_backups_detail_with_limit(self):
        fake_backup_1, expected_backup_1 = self._get_fake_backup()
        fake_backup_2, expected_backup_2 = self._get_fake_backup(
            id="fake_id2")
        self.mock_object(
            share_backups.db, 'share_backups_get_all',
            mock.Mock(return_value=[fake_backup_1]))
        req = fakes.HTTPRequest.blank('/share-backups?limit=1',
                                      version=self.api_version,
                                      experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        self.assertEqual(1, len(res_dict['share_backups']))
        self.assertEqual([expected_backup_1], res_dict['share_backups'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_share_backups_detail_with_limit_and_offset(self):
        fake_backup_1, expected_backup_1 = self._get_fake_backup()
        fake_backup_2, expected_backup_2 = self._get_fake_backup(
            id="fake_id2")
        self.mock_object(
            share_backups.db, 'share_backups_get_all',
            mock.Mock(return_value=[fake_backup_2]))
        req = fakes.HTTPRequest.blank(
            '/share-backups/detail?limit=1&offset=1',
            version=self.api_version, experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        self.assertEqual(1, len(res_dict['share_backups']))
        self.assertEqual([expected_backup_2], res_dict['share_backups'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_share_backups_detail_invalid_share(self):
        self.mock_object(share_backups.db, 'share_backups_get_all',
                         mock.Mock(side_effect=exception.NotFound))
        mock__view_builder_call = self.mock_object(
            share_backups.backup_view.BackupViewBuilder,
            'detail_list')
        req = self.backups_req
        req.GET['share_id'] = 'FAKE_SHARE_ID'

        self.assertRaises(exc.HTTPBadRequest,
                          self.controller.detail, req)
        self.assertFalse(mock__view_builder_call.called)
        self.mock_policy_check.assert_called_once_with(
            self.member_context, self.resource_name, 'get_all')

    def test_list_share_backups_detail(self):
        fake_backup, expected_backup = self._get_fake_backup()

        self.mock_object(share.API, 'get',
                         mock.Mock(return_value={'id': 'FAKE_SHAREID'}))
        self.mock_object(share_backups.db, 'share_backups_get_all',
                         mock.Mock(return_value=[fake_backup]))
        req = fakes.HTTPRequest.blank(
            '/share-backups?share_id=FAKE_SHARE_ID',
            version=self.api_version, experimental=True)
        req.environ['manila.context'] = (
            self.member_context)
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        self.assertEqual([expected_backup], res_dict['share_backups'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_share_backups_with_limit(self):
        fake_backup_1, expected_backup_1 = self._get_fake_backup()
        fake_backup_2, expected_backup_2 = self._get_fake_backup(
            id="fake_id2")

        self.mock_object(share.API, 'get',
                         mock.Mock(return_value={'id': 'FAKE_SHAREID'}))
        self.mock_object(
            share_backups.db, 'share_backups_get_all',
            mock.Mock(return_value=[fake_backup_1]))
        req = fakes.HTTPRequest.blank(
            '/share-backups?share_id=FAKE_SHARE_ID&limit=1',
            version=self.api_version, experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        self.assertEqual(1, len(res_dict['share_backups']))
        self.assertEqual([expected_backup_1], res_dict['share_backups'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_list_share_backups_with_limit_and_offset(self):
        fake_backup_1, expected_backup_1 = self._get_fake_backup()
        fake_backup_2, expected_backup_2 = self._get_fake_backup(
            id="fake_id2")
        self.mock_object(share.API, 'get',
                         mock.Mock(return_value={'id': 'FAKE_SHAREID'}))
        self.mock_object(
            share_backups.db, 'share_backups_get_all',
            mock.Mock(return_value=[fake_backup_2]))
        req = fakes.HTTPRequest.blank(
            '/share-backups?share_id=FAKE_SHARE_ID&limit=1&offset=1',
            version=self.api_version, experimental=True)
        req_context = req.environ['manila.context']

        res_dict = self.controller.detail(req)

        self.assertEqual(1, len(res_dict['share_backups']))
        self.assertEqual([expected_backup_2], res_dict['share_backups'])
        self.mock_policy_check.assert_called_once_with(
            req_context, self.resource_name, 'get_all')

    def test_show(self):
        fake_backup, expected_backup = self._get_fake_backup()
        self.mock_object(
            share_backups.db, 'share_backup_get',
            mock.Mock(return_value=fake_backup))

        req = self.backups_req
        res_dict = self.controller.show(req, fake_backup.get('id'))

        self.assertEqual(expected_backup, res_dict['share_backup'])

    def test_show_no_backup(self):
        mock__view_builder_call = self.mock_object(
            share_backups.backup_view.BackupViewBuilder, 'detail')
        fake_exception = exception.ShareBackupNotFound(
            backup_id='FAKE_backup_ID')
        self.mock_object(share_backups.db, 'share_backup_get', mock.Mock(
            side_effect=fake_exception))

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.show,
                          self.backups_req,
                          'FAKE_backup_ID')
        self.assertFalse(mock__view_builder_call.called)

    def test_create_invalid_body(self):
        body = {}
        mock__view_builder_call = self.mock_object(
            share_backups.backup_view.BackupViewBuilder,
            'detail_list')

        self.assertRaises(exc.HTTPUnprocessableEntity,
                          self.controller.create,
                          self.backups_req, body)
        self.assertEqual(0, mock__view_builder_call.call_count)

    def test_create_no_share_id(self):
        body = {
            'share_backup': {
                'share_id': None,
                'availability_zone': None,
            }
        }
        mock__view_builder_call = self.mock_object(
            share_backups.backup_view.BackupViewBuilder,
            'detail_list')
        self.mock_object(share_backups.db, 'share_get',
                         mock.Mock(side_effect=exception.NotFound))

        self.assertRaises(exc.HTTPBadRequest,
                          self.controller.create,
                          self.backups_req, body)
        self.assertFalse(mock__view_builder_call.called)

    def test_create_invalid_share_id(self):
        body = {
            'share_backup': {
                'share_id': None,
            }
        }
        mock__view_builder_call = self.mock_object(
            share_backups.backup_view.BackupViewBuilder,
            'detail_list')
        self.mock_object(share.API, 'get',
                         mock.Mock(side_effect=exception.NotFound))

        self.assertRaises(exc.HTTPBadRequest,
                          self.controller.create,
                          self.backups_req, body)
        self.assertFalse(mock__view_builder_call.called)

    @ddt.data(exception.InvalidBackup, exception.ShareBusyException)
    def test_create_exception_path(self, exception_type):
        fake_backup, _ = self._get_fake_backup()
        mock__view_builder_call = self.mock_object(
            share_backups.backup_view.BackupViewBuilder,
            'detail_list')
        body = {
            'share_backup': {
                'share_id': 'FAKE_SHAREID',
            }
        }
        exc_args = {'id': 'xyz', 'reason': 'abc'}
        self.mock_object(share.API, 'get',
                         mock.Mock(return_value={'id': 'FAKE_SHAREID'}))
        self.mock_object(share.API, 'create_share_backup',
                         mock.Mock(side_effect=exception_type(**exc_args)))

        if exception_type == exception.InvalidBackup:
            expected_exception = exc.HTTPBadRequest
        else:
            expected_exception = exc.HTTPConflict
        self.assertRaises(expected_exception,
                          self.controller.create,
                          self.backups_req, body)
        self.assertFalse(mock__view_builder_call.called)

    def test_create(self):
        fake_backup, expected_backup = self._get_fake_backup()
        body = {
            'share_backup': {
                'share_id': 'FAKE_SHAREID',
            }
        }
        self.mock_object(share.API, 'get',
                         mock.Mock(return_value={'id': 'FAKE_SHAREID'}))
        self.mock_object(share.API, 'create_share_backup',
                         mock.Mock(return_value=fake_backup))

        req = self.backups_req
        res_dict = self.controller.create(req, body)
        self.assertEqual(expected_backup, res_dict['share_backup'])

    def test_delete_invalid_backup(self):
        fake_exception = exception.ShareBackupNotFound(
            backup_id='FAKE_backup_ID')
        self.mock_object(share_backups.db, 'share_backup_get',
                         mock.Mock(side_effect=fake_exception))
        mock_delete_backup_call = self.mock_object(
            share.API, 'delete_share_backup')

        self.assertRaises(
            exc.HTTPNotFound, self.controller.delete,
            self.backups_req, 'FAKE_backup_ID')
        self.assertFalse(mock_delete_backup_call.called)

    def test_delete_exception(self):
        fake_backup_1 = self._get_fake_backup(
            share_id='FAKE_SHARE_ID',
            status=constants.STATUS_BACKUP_CREATING)[0]
        fake_backup_2 = self._get_fake_backup(
            share_id='FAKE_SHARE_ID',
            status=constants.STATUS_BACKUP_CREATING)[0]
        exception_type = exception.InvalidBackup(reason='xyz')
        self.mock_object(share_backups.db, 'share_backup_get',
                         mock.Mock(return_value=fake_backup_1))
        self.mock_object(
            share_backups.db, 'share_backups_get_all',
            mock.Mock(return_value=[fake_backup_1, fake_backup_2]))
        self.mock_object(share.API, 'delete_share_backup',
                         mock.Mock(side_effect=exception_type))

        self.assertRaises(exc.HTTPBadRequest, self.controller.delete,
                          self.backups_req, 'FAKE_backup_ID')

    def test_delete(self):
        fake_backup = self._get_fake_backup(
            share_id='FAKE_SHARE_ID',
            status=constants.STATUS_AVAILABLE)[0]
        self.mock_object(share_backups.db, 'share_backup_get',
                         mock.Mock(return_value=fake_backup))
        self.mock_object(share.API, 'delete_share_backup')

        resp = self.controller.delete(
            self.backups_req, 'FAKE_backup_ID')

        self.assertEqual(202, resp.status_code)

    def test_restore_invalid_backup_id(self):
        body = {'restore': None}
        fake_exception = exception.ShareBackupNotFound(
            backup_id='FAKE_BACKUP_ID')
        self.mock_object(share.API, 'restore',
                         mock.Mock(side_effect=fake_exception))

        self.assertRaises(exc.HTTPNotFound,
                          self.controller.restore,
                          self.backups_req,
                          'FAKE_BACKUP_ID', body)

    def test_restore(self):
        body = {'restore': {'share_id': 'fake_id'}}
        fake_backup = self._get_fake_backup(
            share_id='FAKE_SHARE_ID',
            status=constants.STATUS_AVAILABLE)[0]
        self.mock_object(share_backups.db, 'share_backup_get',
                         mock.Mock(return_value=fake_backup))

        fake_backup_restore = {
            'share_id': 'FAKE_SHARE_ID',
            'backup_id': fake_backup['id'],
        }
        mock_api_restore_backup_call = self.mock_object(
            share.API, 'restore_share_backup',
            mock.Mock(return_value=fake_backup_restore))
        self.mock_object(share.API, 'get',
                         mock.Mock(return_value={'id': 'FAKE_SHAREID'}))

        resp = self.controller.restore(self.backups_req,
                                       fake_backup['id'], body)

        self.assertEqual(fake_backup_restore, resp['restore'])
        self.assertTrue(mock_api_restore_backup_call.called)

    def test_update(self):
        fake_backup = self._get_fake_backup(
            share_id='FAKE_SHARE_ID',
            status=constants.STATUS_AVAILABLE)[0]
        self.mock_object(share_backups.db, 'share_backup_get',
                         mock.Mock(return_value=fake_backup))

        body = {'share_backup': {'name': 'backup1'}}
        fake_backup_update = {
            'share_id': 'FAKE_SHARE_ID',
            'backup_id': fake_backup['id'],
            'display_name': 'backup1'
        }
        mock_api_update_backup_call = self.mock_object(
            share.API, 'update_share_backup',
            mock.Mock(return_value=fake_backup_update))

        resp = self.controller.update(self.backups_req,
                                      fake_backup['id'], body)

        self.assertEqual(fake_backup_update['display_name'],
                         resp['share_backup']['name'])
        self.assertTrue(mock_api_update_backup_call.called)

    @ddt.data('index', 'detail')
    def test_policy_not_authorized(self, method_name):

        method = getattr(self.controller, method_name)
        arguments = {
            'id': 'FAKE_backup_ID',
            'body': {'FAKE_KEY': 'FAKE_VAL'},
        }
        if method_name in ('index', 'detail'):
            arguments.clear()

        noauthexc = exception.PolicyNotAuthorized(action=method)

        with mock.patch.object(
                policy, 'check_policy', mock.Mock(side_effect=noauthexc)):

            self.assertRaises(
                exc.HTTPForbidden, method, self.backups_req, **arguments)

    @ddt.data('index', 'detail', 'show', 'create', 'delete')
    def test_upsupported_microversion(self, method_name):

        unsupported_microversions = ('1.0', '2.2', '2.18')
        method = getattr(self.controller, method_name)
        arguments = {
            'id': 'FAKE_BACKUP_ID',
            'body': {'FAKE_KEY': 'FAKE_VAL'},
        }
        if method_name in ('index', 'detail'):
            arguments.clear()

        for microversion in unsupported_microversions:
            req = fakes.HTTPRequest.blank(
                '/share-backups', version=microversion,
                experimental=True)
            self.assertRaises(exception.VersionNotFoundForAPIMethod,
                              method, req, **arguments)
