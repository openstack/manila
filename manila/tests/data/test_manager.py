# Copyright 2015, Hitachi Data Systems.
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

"""
Tests For Data Manager
"""

from unittest import mock

import ddt
from oslo_config import cfg

from manila.common import constants
from manila import context
from manila.data import helper
from manila.data import manager
from manila.data import utils as data_utils
from manila import db
from manila import exception
from manila import quota
from manila.share import rpcapi as share_rpc
from manila import test
from manila.tests import db_utils
from manila import utils


CONF = cfg.CONF


@ddt.ddt
class DataManagerTestCase(test.TestCase):
    """Test case for data manager."""

    def setUp(self):
        super(DataManagerTestCase, self).setUp()
        self.manager = manager.DataManager()
        self.context = context.get_admin_context()
        self.topic = 'fake_topic'
        self.share = db_utils.create_share()
        manager.CONF.set_default('mount_tmp_location', '/tmp/')
        manager.CONF.set_default('backup_mount_tmp_location', '/tmp/')
        manager.CONF.set_default(
            'backup_driver',
            'manila.tests.fake_backup_driver.FakeBackupDriver')

    def test_init(self):
        manager = self.manager
        self.assertIsNotNone(manager)

    @ddt.data(constants.TASK_STATE_DATA_COPYING_COMPLETING,
              constants.TASK_STATE_DATA_COPYING_STARTING,
              constants.TASK_STATE_DATA_COPYING_IN_PROGRESS)
    def test_init_host(self, status):

        share = db_utils.create_share(
            task_state=status)

        # mocks
        self.mock_object(db, 'share_get_all', mock.Mock(
            return_value=[share]))
        self.mock_object(db, 'share_update')

        # run
        self.manager.init_host()

        # asserts
        db.share_get_all.assert_called_once_with(
            utils.IsAMatcher(context.RequestContext))

        db.share_update.assert_called_with(
            utils.IsAMatcher(context.RequestContext), share['id'],
            {'task_state': constants.TASK_STATE_DATA_COPYING_ERROR})

    @ddt.data(None, Exception('fake'), exception.ShareDataCopyCancelled())
    def test_migration_start(self, exc):

        migration_info_src = {
            'mount': 'mount_cmd_src',
            'unmount': 'unmount_cmd_src',
        }
        migration_info_dest = {
            'mount': 'mount_cmd_dest',
            'unmount': 'unmount_cmd_dest',
        }
        # mocks
        self.mock_object(db, 'share_get', mock.Mock(return_value=self.share))
        self.mock_object(db, 'share_instance_get', mock.Mock(
            return_value=self.share.instance))

        self.mock_object(data_utils, 'Copy',
                         mock.Mock(return_value='fake_copy'))

        if exc is None:
            self.manager.busy_tasks_shares[self.share['id']] = 'fake_copy'

        self.mock_object(self.manager, '_copy_share_data',
                         mock.Mock(side_effect=exc))

        self.mock_object(share_rpc.ShareAPI, 'migration_complete')

        if exc is not None and not isinstance(
                exc, exception.ShareDataCopyCancelled):
            self.mock_object(db, 'share_update')

        # run
        if exc is None or isinstance(exc, exception.ShareDataCopyCancelled):
            self.manager.migration_start(
                self.context, [], self.share['id'],
                'ins1_id', 'ins2_id', migration_info_src,
                migration_info_dest)
        else:
            self.assertRaises(
                exception.ShareDataCopyFailed, self.manager.migration_start,
                self.context, [], self.share['id'], 'ins1_id', 'ins2_id',
                migration_info_src, migration_info_dest)

            db.share_update.assert_called_once_with(
                self.context, self.share['id'],
                {'task_state': constants.TASK_STATE_DATA_COPYING_ERROR})

        # asserts
        self.assertFalse(self.manager.busy_tasks_shares.get(self.share['id']))

        if exc:
            share_rpc.ShareAPI.migration_complete.assert_called_once_with(
                self.context, self.share.instance, 'ins2_id')

    @ddt.data(
        {'cancelled': False, 'exc': None, 'case': 'migration'},
        {'cancelled': False, 'exc': Exception('fake'), 'case': 'migration'},
        {'cancelled': True, 'exc': None, 'case': 'migration'},
        {'cancelled': False, 'exc': None, 'case': 'backup'},
        {'cancelled': False, 'exc': Exception('fake'), 'case': 'backup'},
        {'cancelled': True, 'exc': None, 'case': 'backup'},
        {'cancelled': False, 'exc': None, 'case': 'restore'},
        {'cancelled': False, 'exc': Exception('fake'), 'case': 'restore'},
        {'cancelled': True, 'exc': None, 'case': 'restore'},
    )
    @ddt.unpack
    def test__copy_share_data(self, cancelled, exc, case):

        access = db_utils.create_access(share_id=self.share['id'])

        if case == 'migration':
            connection_info_src = {
                'mount': 'mount_cmd_src',
                'unmount': 'unmount_cmd_src',
                'share_id': self.share['id'],
                'share_instance_id': 'ins1_id',
                'mount_point': '/tmp/ins1_id',
            }
            connection_info_dest = {
                'mount': 'mount_cmd_dest',
                'unmount': 'unmount_cmd_dest',
                'share_id': None,
                'share_instance_id': 'ins2_id',
                'mount_point': '/tmp/ins2_id',
            }
        if case == 'backup':
            connection_info_src = {
                'mount': 'mount_cmd_src',
                'unmount': 'unmount_cmd_src',
                'share_id': self.share['id'],
                'share_instance_id': 'ins1_id',
                'mount_point': '/tmp/ins1_id',
            }
            connection_info_dest = {
                'mount': 'mount_cmd_dest',
                'unmount': 'unmount_cmd_dest',
                'share_id': None,
                'share_instance_id': None,
                'mount_point': '/tmp/backup_id',
                'backup': True
            }
        if case == 'restore':
            connection_info_src = {
                'mount': 'mount_cmd_src',
                'unmount': 'unmount_cmd_src',
                'share_id': None,
                'share_instance_id': None,
                'mount_point': '/tmp/backup_id',
                'restore': True
            }
            connection_info_dest = {
                'mount': 'mount_cmd_dest',
                'unmount': 'unmount_cmd_dest',
                'share_id': self.share['id'],
                'share_instance_id': 'ins2_id',
                'mount_point': '/tmp/ins2_id',
            }

        get_progress = {'total_progress': 100}

        # mocks
        fake_copy = mock.MagicMock(cancelled=cancelled)

        self.mock_object(db, 'share_update')
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=[self.share['instance'],
                                                self.share['instance']]))
        self.mock_object(helper.DataServiceHelper,
                         'allow_access_to_data_service',
                         mock.Mock(return_value=[access]))

        self.mock_object(helper.DataServiceHelper,
                         'mount_share_instance_or_backup')

        self.mock_object(fake_copy, 'run', mock.Mock(side_effect=exc))

        self.mock_object(fake_copy, 'get_progress',
                         mock.Mock(return_value=get_progress))

        self.mock_object(helper.DataServiceHelper,
                         'unmount_share_instance_or_backup',
                         mock.Mock(side_effect=Exception('fake')))

        self.mock_object(helper.DataServiceHelper,
                         'deny_access_to_data_service',
                         mock.Mock(side_effect=Exception('fake')))

        extra_updates = None

        # run
        if cancelled:
            self.assertRaises(
                exception.ShareDataCopyCancelled,
                self.manager._copy_share_data, self.context, fake_copy,
                connection_info_src, connection_info_dest)
            extra_updates = [
                mock.call(
                    self.context, self.share['id'],
                    {'task_state':
                     constants.TASK_STATE_DATA_COPYING_COMPLETING}),
                mock.call(
                    self.context, self.share['id'],
                    {'task_state':
                     constants.TASK_STATE_DATA_COPYING_CANCELLED})
            ]

        elif exc:
            self.assertRaises(
                exception.ShareDataCopyFailed, self.manager._copy_share_data,
                self.context, fake_copy, connection_info_src,
                connection_info_dest)

        else:
            self.manager._copy_share_data(
                self.context, fake_copy, connection_info_src,
                connection_info_dest)
            extra_updates = [
                mock.call(
                    self.context, self.share['id'],
                    {'task_state':
                     constants.TASK_STATE_DATA_COPYING_COMPLETING}),
                mock.call(
                    self.context, self.share['id'],
                    {'task_state':
                     constants.TASK_STATE_DATA_COPYING_COMPLETED})
            ]

        # asserts
        self.assertEqual(
            self.manager.busy_tasks_shares[self.share['id']], fake_copy)

        update_list = [
            mock.call(
                self.context, self.share['id'],
                {'task_state': constants.TASK_STATE_DATA_COPYING_STARTING}),
            mock.call(
                self.context, self.share['id'],
                {'task_state': constants.TASK_STATE_DATA_COPYING_IN_PROGRESS}),
        ]
        if extra_updates:
            update_list = update_list + extra_updates

        db.share_update.assert_has_calls(update_list)

        helper.DataServiceHelper.\
            mount_share_instance_or_backup.assert_has_calls([
                mock.call(connection_info_src, '/tmp/'),
                mock.call(connection_info_dest, '/tmp/')])

        fake_copy.run.assert_called_once_with()
        if exc is None:
            fake_copy.get_progress.assert_called_once_with()

        helper.DataServiceHelper.\
            unmount_share_instance_or_backup.assert_has_calls([
                mock.call(connection_info_src, '/tmp/'),
                mock.call(connection_info_dest, '/tmp/')])

    def test__copy_share_data_exception_access(self):

        connection_info_src = {
            'mount': 'mount_cmd_src',
            'unmount': 'unmount_cmd_src',
            'share_id': self.share['id'],
            'share_instance_id': 'ins1_id',
            'mount_point': '/tmp/ins1_id',
        }
        connection_info_dest = {
            'mount': 'mount_cmd_dest',
            'unmount': 'unmount_cmd_dest',
            'share_id': None,
            'share_instance_id': 'ins2_id',
            'mount_point': '/tmp/ins2_id',
        }

        fake_copy = mock.MagicMock(cancelled=False)

        # mocks
        self.mock_object(db, 'share_update')
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=[self.share['instance'],
                                                self.share['instance']]))

        self.mock_object(
            helper.DataServiceHelper, 'allow_access_to_data_service',
            mock.Mock(
                side_effect=exception.ShareDataCopyFailed(reason='fake')))

        self.mock_object(helper.DataServiceHelper, 'cleanup_data_access')

        # run
        self.assertRaises(exception.ShareDataCopyFailed,
                          self.manager._copy_share_data, self.context,
                          fake_copy, connection_info_src, connection_info_dest)

        # asserts
        db.share_update.assert_called_once_with(
            self.context, self.share['id'],
            {'task_state': constants.TASK_STATE_DATA_COPYING_STARTING})

        (helper.DataServiceHelper.allow_access_to_data_service.
            assert_called_once_with(
                self.share['instance'], connection_info_src,
                self.share['instance'], connection_info_dest))

    def test__copy_share_data_exception_mount_1(self):

        access = db_utils.create_access(share_id=self.share['id'])

        connection_info_src = {
            'mount': 'mount_cmd_src',
            'unmount': 'unmount_cmd_src',
            'share_id': self.share['id'],
            'share_instance_id': 'ins1_id',
            'mount_point': '/tmp/ins1_id',
        }
        connection_info_dest = {
            'mount': 'mount_cmd_dest',
            'unmount': 'unmount_cmd_dest',
            'share_id': None,
            'share_instance_id': 'ins2_id',
            'mount_point': '/tmp/ins2_id',
        }

        fake_copy = mock.MagicMock(cancelled=False)

        # mocks
        self.mock_object(db, 'share_update')
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=[self.share['instance'],
                                                self.share['instance']]))

        self.mock_object(helper.DataServiceHelper,
                         'allow_access_to_data_service',
                         mock.Mock(return_value=[access]))

        self.mock_object(helper.DataServiceHelper,
                         'mount_share_instance_or_backup',
                         mock.Mock(side_effect=Exception('fake')))

        self.mock_object(helper.DataServiceHelper, 'cleanup_data_access')
        self.mock_object(helper.DataServiceHelper, 'cleanup_temp_folder')

        # run
        self.assertRaises(exception.ShareDataCopyFailed,
                          self.manager._copy_share_data, self.context,
                          fake_copy, connection_info_src, connection_info_dest)

        # asserts
        db.share_update.assert_called_once_with(
            self.context, self.share['id'],
            {'task_state': constants.TASK_STATE_DATA_COPYING_STARTING})

        helper.DataServiceHelper.\
            mount_share_instance_or_backup.assert_called_once_with(
                connection_info_src, '/tmp/')

        helper.DataServiceHelper.cleanup_temp_folder.assert_called_once_with(
            '/tmp/', 'ins1_id')

        helper.DataServiceHelper.cleanup_data_access.assert_has_calls([
            mock.call([access], self.share['instance']),
            mock.call([access], self.share['instance'])])

    def test__copy_share_data_exception_mount_2(self):

        access = db_utils.create_access(share_id=self.share['id'])

        connection_info_src = {
            'mount': 'mount_cmd_src',
            'unmount': 'unmount_cmd_src',
            'share_id': self.share['id'],
            'share_instance_id': 'ins1_id',
            'mount_point': '/tmp/ins1_id',
        }
        connection_info_dest = {
            'mount': 'mount_cmd_dest',
            'unmount': 'unmount_cmd_dest',
            'share_id': None,
            'share_instance_id': 'ins2_id',
            'mount_point': '/tmp/ins2_id',
        }

        fake_copy = mock.MagicMock(cancelled=False)

        # mocks
        self.mock_object(db, 'share_update')
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(side_effect=[self.share['instance'],
                                                self.share['instance']]))

        self.mock_object(helper.DataServiceHelper,
                         'allow_access_to_data_service',
                         mock.Mock(return_value=[access]))

        self.mock_object(helper.DataServiceHelper,
                         'mount_share_instance_or_backup',
                         mock.Mock(side_effect=[None, Exception('fake')]))

        self.mock_object(helper.DataServiceHelper, 'cleanup_data_access')
        self.mock_object(helper.DataServiceHelper, 'cleanup_temp_folder')
        self.mock_object(helper.DataServiceHelper,
                         'cleanup_unmount_temp_folder')

        # run
        self.assertRaises(exception.ShareDataCopyFailed,
                          self.manager._copy_share_data, self.context,
                          fake_copy, connection_info_src, connection_info_dest)

        # asserts
        db.share_update.assert_called_once_with(
            self.context, self.share['id'],
            {'task_state': constants.TASK_STATE_DATA_COPYING_STARTING})

        helper.DataServiceHelper.\
            mount_share_instance_or_backup.assert_has_calls([
                mock.call(connection_info_src, '/tmp/'),
                mock.call(connection_info_dest, '/tmp/')])

        helper.DataServiceHelper.cleanup_unmount_temp_folder.\
            assert_called_once_with(connection_info_src, '/tmp/')

        helper.DataServiceHelper.cleanup_temp_folder.assert_has_calls([
            mock.call('/tmp/', 'ins2_id'), mock.call('/tmp/', 'ins1_id')])

    def test_data_copy_cancel(self):

        share = db_utils.create_share()

        self.manager.busy_tasks_shares[share['id']] = data_utils.Copy

        # mocks
        self.mock_object(data_utils.Copy, 'cancel')

        # run
        self.manager.data_copy_cancel(self.context, share['id'])

        # asserts
        data_utils.Copy.cancel.assert_called_once_with()

    def test_data_copy_cancel_not_copying(self):

        self.assertRaises(exception.InvalidShare,
                          self.manager.data_copy_cancel, self.context,
                          'fake_id')

    def test_data_copy_get_progress(self):

        share = db_utils.create_share()

        self.manager.busy_tasks_shares[share['id']] = data_utils.Copy

        expected = 'fake_progress'

        # mocks
        self.mock_object(data_utils.Copy, 'get_progress',
                         mock.Mock(return_value=expected))

        # run
        result = self.manager.data_copy_get_progress(self.context, share['id'])

        # asserts
        self.assertEqual(expected, result)

        data_utils.Copy.get_progress.assert_called_once_with()

    def test_data_copy_get_progress_not_copying(self):

        self.assertRaises(exception.InvalidShare,
                          self.manager.data_copy_get_progress, self.context,
                          'fake_id')

    def test_create_share_backup(self):
        share_info = db_utils.create_share(
            status=constants.STATUS_BACKUP_CREATING)
        backup_info = db_utils.create_backup(
            share_info['id'], status=constants.STATUS_CREATING)

        # mocks
        self.mock_object(db, 'share_update')
        self.mock_object(db, 'share_backup_update')
        self.mock_object(db, 'share_get', mock.Mock(return_value=share_info))
        self.mock_object(db, 'share_backup_get',
                         mock.Mock(return_value=backup_info))
        self.mock_object(self.manager, '_run_backup',
                         mock.Mock(side_effect=None))
        self.manager.create_backup(self.context, backup_info)
        db.share_update.assert_called_with(
            self.context, share_info['id'],
            {'status': constants.STATUS_AVAILABLE})
        db.share_backup_update.assert_called_with(
            self.context, backup_info['id'],
            {'status': constants.STATUS_AVAILABLE, 'progress': '100'})

    def test_create_share_backup_exception(self):
        share_info = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        backup_info = db_utils.create_backup(
            share_info['id'], status=constants.STATUS_AVAILABLE, size=2)

        # mocks
        self.mock_object(db, 'share_update')
        self.mock_object(db, 'share_backup_update')
        self.mock_object(db, 'share_get', mock.Mock(return_value=share_info))
        self.mock_object(db, 'share_backup_get',
                         mock.Mock(return_value=backup_info))
        self.mock_object(
            self.manager, '_run_backup',
            mock.Mock(
                side_effect=exception.ShareDataCopyFailed(reason='fake')))
        self.assertRaises(exception.ManilaException,
                          self.manager.create_backup,
                          self.context, backup_info)
        db.share_update.assert_called_with(
            self.context, share_info['id'],
            {'status': constants.STATUS_AVAILABLE})
        db.share_backup_update.assert_called()

    @ddt.data('90', '100')
    def test_create_share_backup_continue(self, progress):
        share_info = db_utils.create_share(
            status=constants.STATUS_BACKUP_CREATING)
        backup_info = db_utils.create_backup(
            share_info['id'], status=constants.STATUS_CREATING,
            topic=CONF.data_topic)
        # mocks
        self.mock_object(db, 'share_update')
        self.mock_object(db, 'share_backup_update')
        self.mock_object(db, 'share_backups_get_all',
                         mock.Mock(return_value=[backup_info]))
        self.mock_object(self.manager, 'data_copy_get_progress',
                         mock.Mock(return_value={'total_progress': progress}))

        self.manager.create_backup_continue(self.context)
        if progress == '100':
            db.share_backup_update.assert_called_with(
                self.context, backup_info['id'],
                {'status': constants.STATUS_AVAILABLE, 'progress': '100'})
            db.share_update.assert_called_with(
                self.context, share_info['id'],
                {'status': constants.STATUS_AVAILABLE})
        else:
            db.share_backup_update.assert_called_with(
                self.context, backup_info['id'],
                {'progress': progress})

    def test_create_share_backup_continue_exception(self):
        share_info = db_utils.create_share(
            status=constants.STATUS_BACKUP_CREATING)
        backup_info = db_utils.create_backup(
            share_info['id'], status=constants.STATUS_CREATING,
            topic=CONF.data_topic)
        # mocks
        self.mock_object(db, 'share_update')
        self.mock_object(db, 'share_backup_update')
        self.mock_object(db, 'share_backups_get_all',
                         mock.Mock(return_value=[backup_info]))
        self.mock_object(self.manager, 'data_copy_get_progress',
                         mock.Mock(side_effect=exception.ManilaException))

        self.manager.create_backup_continue(self.context)

        db.share_backup_update.assert_called_with(
            self.context, backup_info['id'],
            {'status': constants.STATUS_ERROR, 'progress': '0'})
        db.share_update.assert_called_with(
            self.context, share_info['id'],
            {'status': constants.STATUS_AVAILABLE})

    @ddt.data(None, exception.ShareDataCopyFailed())
    def test__run_backup(self, exc):
        share_info = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        backup_info = db_utils.create_backup(
            share_info['id'], status=constants.STATUS_AVAILABLE, size=2)
        share_instance = {
            'export_locations': [{
                'path': 'test_path',
                "is_admin_only": False
                }, ],
            'share_proto': 'nfs',
        }

        # mocks
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=share_instance))

        self.mock_object(data_utils, 'Copy',
                         mock.Mock(return_value='fake_copy'))
        self.manager.busy_tasks_shares[self.share['id']] = 'fake_copy'
        self.mock_object(self.manager, '_copy_share_data',
                         mock.Mock(side_effect=exc))

        self.mock_object(self.manager, '_run_backup')

        if exc is isinstance(exc, exception.ShareDataCopyFailed):
            self.assertRaises(exception.ShareDataCopyFailed,
                              self.manager._run_backup, self.context,
                              backup_info, share_info)
        else:
            self.manager._run_backup(self.context, backup_info, share_info)

    def test_delete_share_backup(self):
        share_info = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        backup_info = db_utils.create_backup(
            share_info['id'], status=constants.STATUS_AVAILABLE, size=2)
        # mocks
        self.mock_object(db, 'share_backup_delete')
        self.mock_object(db, 'share_backup_get',
                         mock.Mock(return_value=backup_info))
        self.mock_object(utils, 'execute')

        reservation = 'fake'
        self.mock_object(quota.QUOTAS, 'reserve',
                         mock.Mock(return_value=reservation))
        self.mock_object(quota.QUOTAS, 'commit')

        self.manager.delete_backup(self.context, backup_info)
        db.share_backup_delete.assert_called_with(
            self.context, backup_info['id'])

    def test_delete_share_backup_exception(self):
        share_info = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        backup_info = db_utils.create_backup(
            share_info['id'], status=constants.STATUS_AVAILABLE, size=2)
        # mocks
        self.mock_object(db, 'share_backup_get',
                         mock.Mock(return_value=backup_info))
        self.mock_object(utils, 'execute')

        self.mock_object(
            quota.QUOTAS, 'reserve',
            mock.Mock(side_effect=exception.ManilaException))
        self.assertRaises(exception.ManilaException,
                          self.manager.delete_backup, self.context,
                          backup_info)

    def test_restore_share_backup(self):
        share_info = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        backup_info = db_utils.create_backup(
            share_info['id'], status=constants.STATUS_AVAILABLE, size=2)
        share_id = share_info['id']

        # mocks
        self.mock_object(db, 'share_update')
        self.mock_object(db, 'share_backup_update')
        self.mock_object(db, 'share_get', mock.Mock(return_value=share_info))
        self.mock_object(db, 'share_backup_get',
                         mock.Mock(return_value=backup_info))
        self.mock_object(self.manager, '_run_restore')
        self.manager.restore_backup(self.context, backup_info, share_id)
        db.share_update.assert_called_with(
            self.context, share_info['id'],
            {'status': constants.STATUS_AVAILABLE})
        db.share_backup_update.assert_called_with(
            self.context, backup_info['id'],
            {'status': constants.STATUS_AVAILABLE, 'restore_progress': '100'})

    def test_restore_share_backup_exception(self):
        share_info = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        backup_info = db_utils.create_backup(
            share_info['id'], status=constants.STATUS_AVAILABLE, size=2)
        share_id = share_info['id']

        # mocks
        self.mock_object(db, 'share_update')
        self.mock_object(db, 'share_get', mock.Mock(return_value=share_info))
        self.mock_object(db, 'share_backup_get',
                         mock.Mock(return_value=backup_info))
        self.mock_object(
            self.manager, '_run_restore',
            mock.Mock(
                side_effect=exception.ShareDataCopyFailed(reason='fake')))
        self.assertRaises(exception.ManilaException,
                          self.manager.restore_backup, self.context,
                          backup_info, share_id)
        db.share_update.assert_called_with(
            self.context, share_info['id'],
            {'status': constants.STATUS_BACKUP_RESTORING_ERROR})

    @ddt.data('90', '100')
    def test_restore_share_backup_continue(self, progress):
        share_info = db_utils.create_share(
            status=constants.STATUS_BACKUP_RESTORING)
        backup_info = db_utils.create_backup(
            share_info['id'], status=constants.STATUS_RESTORING,
            topic=CONF.data_topic)
        share_info['source_backup_id'] = backup_info['id']

        # mocks
        self.mock_object(db, 'share_update')
        self.mock_object(db, 'share_backup_update')
        self.mock_object(db, 'share_get_all',
                         mock.Mock(return_value=[share_info]))
        self.mock_object(db, 'share_backups_get_all',
                         mock.Mock(return_value=[backup_info]))
        self.mock_object(self.manager, 'data_copy_get_progress',
                         mock.Mock(return_value={'total_progress': progress}))

        self.manager.restore_backup_continue(self.context)

        if progress == '100':
            db.share_backup_update.assert_called_with(
                self.context, backup_info['id'],
                {'status': constants.STATUS_AVAILABLE,
                 'restore_progress': '100'})
            db.share_update.assert_called_with(
                self.context, share_info['id'],
                {'status': constants.STATUS_AVAILABLE})
        else:
            db.share_backup_update.assert_called_with(
                self.context, backup_info['id'],
                {'restore_progress': progress})

    def test_restore_share_backup_continue_exception(self):
        share_info = db_utils.create_share(
            status=constants.STATUS_BACKUP_RESTORING)
        backup_info = db_utils.create_backup(
            share_info['id'], status=constants.STATUS_RESTORING,
            topic=CONF.data_topic)
        share_info['source_backup_id'] = backup_info['id']

        # mocks
        self.mock_object(db, 'share_update')
        self.mock_object(db, 'share_backup_update')
        self.mock_object(db, 'share_get_all',
                         mock.Mock(return_value=[share_info]))
        self.mock_object(db, 'share_backups_get_all',
                         mock.Mock(return_value=[backup_info]))
        self.mock_object(self.manager, 'data_copy_get_progress',
                         mock.Mock(side_effect=exception.ManilaException))

        self.manager.restore_backup_continue(self.context)
        db.share_backup_update.assert_called_with(
            self.context, backup_info['id'],
            {'status': constants.STATUS_AVAILABLE, 'restore_progress': '0'})
        db.share_update.assert_called_with(
            self.context, share_info['id'],
            {'status': constants.STATUS_BACKUP_RESTORING_ERROR})

    @ddt.data(None, exception.ShareDataCopyFailed())
    def test__run_restore(self, exc):
        share_info = db_utils.create_share(status=constants.STATUS_AVAILABLE)
        backup_info = db_utils.create_backup(
            share_info['id'], status=constants.STATUS_AVAILABLE, size=2)
        share_instance = {
            'export_locations': [{
                'path': 'test_path',
                "is_admin_only": False
                }, ],
            'share_proto': 'nfs',
        }

        # mocks
        self.mock_object(db, 'share_instance_get',
                         mock.Mock(return_value=share_instance))

        self.mock_object(data_utils, 'Copy',
                         mock.Mock(return_value='fake_copy'))
        self.manager.busy_tasks_shares[self.share['id']] = 'fake_copy'
        self.mock_object(self.manager, '_copy_share_data',
                         mock.Mock(side_effect=exc))

        self.mock_object(self.manager, '_run_restore')

        if exc is isinstance(exc, exception.ShareDataCopyFailed):
            self.assertRaises(exception.ShareDataCopyFailed,
                              self.manager._run_restore, self.context,
                              backup_info, share_info)
        else:
            self.manager._run_restore(self.context, backup_info, share_info)
