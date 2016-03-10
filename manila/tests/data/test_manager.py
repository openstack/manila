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
import ddt
import mock

from manila.common import constants
from manila import context
from manila.data import helper
from manila.data import manager
from manila.data import utils as data_utils
from manila import db
from manila import exception
from manila.share import rpcapi as share_rpc
from manila import test
from manila.tests import db_utils
from manila import utils


@ddt.ddt
class DataManagerTestCase(test.TestCase):
    """Test case for data manager."""

    def setUp(self):
        super(DataManagerTestCase, self).setUp()
        self.manager = manager.DataManager()
        self.context = context.get_admin_context()
        self.topic = 'fake_topic'
        self.share = db_utils.create_share()
        manager.CONF.set_default('migration_tmp_location', '/tmp/')

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

    @ddt.data({'notify': True, 'exc': None},
              {'notify': False, 'exc': None},
              {'notify': 'fake',
               'exc': exception.ShareDataCopyCancelled(src_instance='ins1',
                                                       dest_instance='ins2')},
              {'notify': 'fake', 'exc': Exception('fake')})
    @ddt.unpack
    def test_migration_start(self, notify, exc):

        # mocks
        self.mock_object(db, 'share_get', mock.Mock(return_value=self.share))

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
                'ins1_id', 'ins2_id', 'info_src', 'info_dest', notify)
        else:
            self.assertRaises(
                exception.ShareDataCopyFailed, self.manager.migration_start,
                self.context, [], self.share['id'], 'ins1_id', 'ins2_id',
                'info_src', 'info_dest', notify)

            db.share_update.assert_called_once_with(
                self.context, self.share['id'],
                {'task_state': constants.TASK_STATE_DATA_COPYING_ERROR})

        # asserts
        self.assertFalse(self.manager.busy_tasks_shares.get(self.share['id']))

        self.manager._copy_share_data.assert_called_once_with(
            self.context, 'fake_copy', self.share, 'ins1_id', 'ins2_id',
            'info_src', 'info_dest')

        if notify or exc:
            share_rpc.ShareAPI.migration_complete.assert_called_once_with(
                self.context, self.share, 'ins1_id', 'ins2_id')

    @ddt.data({'cancelled': False, 'exc': None},
              {'cancelled': False, 'exc': Exception('fake')},
              {'cancelled': True, 'exc': None})
    @ddt.unpack
    def test__copy_share_data(self, cancelled, exc):

        access = db_utils.create_access(share_id=self.share['id'])

        migration_info_src = {'mount': 'mount_cmd_src',
                              'unmount': 'unmount_cmd_src'}
        migration_info_dest = {'mount': 'mount_cmd_dest',
                               'unmount': 'unmount_cmd_dest'}

        get_progress = {'total_progress': 100}

        # mocks
        fake_copy = mock.MagicMock(cancelled=cancelled)

        self.mock_object(db, 'share_update')

        self.mock_object(helper.DataServiceHelper,
                         'allow_access_to_data_service',
                         mock.Mock(return_value=access))

        self.mock_object(helper.DataServiceHelper, 'mount_share_instance')

        self.mock_object(fake_copy, 'run', mock.Mock(side_effect=exc))

        self.mock_object(fake_copy, 'get_progress',
                         mock.Mock(return_value=get_progress))

        self.mock_object(helper.DataServiceHelper, 'unmount_share_instance',
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
                self.share, 'ins1_id', 'ins2_id', migration_info_src,
                migration_info_dest)
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
                self.context, fake_copy, self.share, 'ins1_id',
                'ins2_id', migration_info_src, migration_info_dest)

        else:
            self.manager._copy_share_data(
                self.context, fake_copy, self.share, 'ins1_id',
                'ins2_id', migration_info_src, migration_info_dest)
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

        helper.DataServiceHelper.allow_access_to_data_service.\
            assert_called_once_with(self.share, 'ins1_id', 'ins2_id')

        helper.DataServiceHelper.mount_share_instance.assert_has_calls([
            mock.call(migration_info_src['mount'], '/tmp/', 'ins1_id'),
            mock.call(migration_info_dest['mount'], '/tmp/', 'ins2_id')])

        fake_copy.run.assert_called_once_with()
        if exc is None:
            fake_copy.get_progress.assert_called_once_with()

        helper.DataServiceHelper.unmount_share_instance.assert_has_calls([
            mock.call(migration_info_src['unmount'], '/tmp/', 'ins1_id'),
            mock.call(migration_info_dest['unmount'], '/tmp/', 'ins2_id')])

        helper.DataServiceHelper.deny_access_to_data_service.assert_has_calls([
            mock.call(access, 'ins1_id'), mock.call(access, 'ins2_id')])

    def test__copy_share_data_exception_access(self):

        migration_info_src = {'mount': 'mount_cmd_src',
                              'unmount': 'unmount_cmd_src'}
        migration_info_dest = {'mount': 'mount_cmd_src',
                               'unmount': 'unmount_cmd_src'}

        fake_copy = mock.MagicMock(cancelled=False)

        # mocks
        self.mock_object(db, 'share_update')

        self.mock_object(
            helper.DataServiceHelper, 'allow_access_to_data_service',
            mock.Mock(
                side_effect=exception.ShareDataCopyFailed(reason='fake')))

        self.mock_object(helper.DataServiceHelper, 'cleanup_data_access')

        # run
        self.assertRaises(exception.ShareDataCopyFailed,
                          self.manager._copy_share_data, self.context,
                          fake_copy, self.share, 'ins1_id', 'ins2_id',
                          migration_info_src, migration_info_dest)

        # asserts
        db.share_update.assert_called_once_with(
            self.context, self.share['id'],
            {'task_state': constants.TASK_STATE_DATA_COPYING_STARTING})

        helper.DataServiceHelper.allow_access_to_data_service.\
            assert_called_once_with(self.share, 'ins1_id', 'ins2_id')

    def test__copy_share_data_exception_mount_1(self):

        access = db_utils.create_access(share_id=self.share['id'])

        migration_info_src = {'mount': 'mount_cmd_src',
                              'unmount': 'unmount_cmd_src'}
        migration_info_dest = {'mount': 'mount_cmd_src',
                               'unmount': 'unmount_cmd_src'}

        fake_copy = mock.MagicMock(cancelled=False)

        # mocks
        self.mock_object(db, 'share_update')

        self.mock_object(helper.DataServiceHelper,
                         'allow_access_to_data_service',
                         mock.Mock(return_value=access))

        self.mock_object(helper.DataServiceHelper, 'mount_share_instance',
                         mock.Mock(side_effect=Exception('fake')))

        self.mock_object(helper.DataServiceHelper, 'cleanup_data_access')
        self.mock_object(helper.DataServiceHelper, 'cleanup_temp_folder')

        # run
        self.assertRaises(exception.ShareDataCopyFailed,
                          self.manager._copy_share_data, self.context,
                          fake_copy, self.share, 'ins1_id', 'ins2_id',
                          migration_info_src, migration_info_dest)

        # asserts
        db.share_update.assert_called_once_with(
            self.context, self.share['id'],
            {'task_state': constants.TASK_STATE_DATA_COPYING_STARTING})

        helper.DataServiceHelper.allow_access_to_data_service.\
            assert_called_once_with(self.share, 'ins1_id', 'ins2_id')

        helper.DataServiceHelper.mount_share_instance.assert_called_once_with(
            migration_info_src['mount'], '/tmp/', 'ins1_id')

        helper.DataServiceHelper.cleanup_temp_folder.assert_called_once_with(
            'ins1_id', '/tmp/')

        helper.DataServiceHelper.cleanup_data_access.assert_has_calls([
            mock.call(access, 'ins2_id'), mock.call(access, 'ins1_id')])

    def test__copy_share_data_exception_mount_2(self):

        access = db_utils.create_access(share_id=self.share['id'])

        migration_info_src = {'mount': 'mount_cmd_src',
                              'unmount': 'unmount_cmd_src'}
        migration_info_dest = {'mount': 'mount_cmd_src',
                               'unmount': 'unmount_cmd_src'}

        fake_copy = mock.MagicMock(cancelled=False)

        # mocks
        self.mock_object(db, 'share_update')

        self.mock_object(helper.DataServiceHelper,
                         'allow_access_to_data_service',
                         mock.Mock(return_value=access))

        self.mock_object(helper.DataServiceHelper, 'mount_share_instance',
                         mock.Mock(side_effect=[None, Exception('fake')]))

        self.mock_object(helper.DataServiceHelper, 'cleanup_data_access')
        self.mock_object(helper.DataServiceHelper, 'cleanup_temp_folder')
        self.mock_object(helper.DataServiceHelper,
                         'cleanup_unmount_temp_folder')

        # run
        self.assertRaises(exception.ShareDataCopyFailed,
                          self.manager._copy_share_data, self.context,
                          fake_copy, self.share, 'ins1_id', 'ins2_id',
                          migration_info_src, migration_info_dest)

        # asserts
        db.share_update.assert_called_once_with(
            self.context, self.share['id'],
            {'task_state': constants.TASK_STATE_DATA_COPYING_STARTING})

        helper.DataServiceHelper.allow_access_to_data_service.\
            assert_called_once_with(self.share, 'ins1_id', 'ins2_id')

        helper.DataServiceHelper.mount_share_instance.assert_has_calls([
            mock.call(migration_info_src['mount'], '/tmp/', 'ins1_id'),
            mock.call(migration_info_dest['mount'], '/tmp/', 'ins2_id')])

        helper.DataServiceHelper.cleanup_unmount_temp_folder.\
            assert_called_once_with(
                migration_info_src['unmount'], '/tmp/', 'ins1_id')

        helper.DataServiceHelper.cleanup_temp_folder.assert_has_calls([
            mock.call('ins2_id', '/tmp/'), mock.call('ins1_id', '/tmp/')])

        helper.DataServiceHelper.cleanup_data_access.assert_has_calls([
            mock.call(access, 'ins2_id'), mock.call(access, 'ins1_id')])

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
