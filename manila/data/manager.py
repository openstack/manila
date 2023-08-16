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
Data Service
"""

import os
import shutil

from oslo_config import cfg
from oslo_log import log
from oslo_service import periodic_task
from oslo_utils import excutils
from oslo_utils import importutils

from manila.common import constants
from manila import context
from manila.data import helper
from manila.data import utils as data_utils
from manila import exception
from manila import manager
from manila import quota
from manila.share import rpcapi as share_rpc
from manila import utils

QUOTAS = quota.QUOTAS

from manila.i18n import _

LOG = log.getLogger(__name__)

backup_opts = [
    cfg.StrOpt(
        'backup_driver',
        default='manila.data.drivers.nfs.NFSBackupDriver',
        help='Driver to use for backups.'),
    cfg.StrOpt(
        'backup_share_mount_template',
        default='mount -vt %(proto)s %(options)s %(export)s %(path)s',
        help="The template for mounting shares during backup. Must specify "
             "the executable with all necessary parameters for the protocol "
             "supported. 'proto' template element may not be required if "
             "included in the command. 'export' and 'path' template elements "
             "are required. It is advisable to separate different commands "
             "per backend."),
    cfg.StrOpt(
        'backup_share_unmount_template',
        default='umount -v %(path)s',
        help="The template for unmounting shares during backup. Must "
             "specify the executable with all necessary parameters for the "
             "protocol supported. 'path' template element is required. It is "
             "advisable to separate different commands per backend."),
    cfg.ListOpt(
        'backup_ignore_files',
        default=['lost+found'],
        help="List of files and folders to be ignored when backing up "
             "shares. Items should be names (not including any path)."),
    cfg.DictOpt(
        'backup_protocol_access_mapping',
        default={'ip': ['nfs']},
        help="Protocol access mapping for backup. Should be a "
             "dictionary comprised of "
             "{'access_type1': ['share_proto1', 'share_proto2'],"
             " 'access_type2': ['share_proto2', 'share_proto3']}."),
]

data_opts = [
    cfg.StrOpt(
        'mount_tmp_location',
        default='/tmp/',
        help="Temporary path to create and mount shares during migration."),
    cfg.StrOpt(
        'backup_mount_tmp_location',
        default='/tmp/',
        help="Temporary path to create and mount backup during share backup."),
    cfg.BoolOpt(
        'check_hash',
        default=False,
        help="Chooses whether hash of each file should be checked on data "
             "copying."),
    cfg.IntOpt(
        'backup_continue_update_interval',
        default=10,
        help='This value, specified in seconds, determines how often '
             'the data manager will poll to perform the next steps of '
             'backup such as fetch the progress of backup.'),
    cfg.IntOpt(
        'restore_continue_update_interval',
        default=10,
        help='This value, specified in seconds, determines how often '
             'the data manager will poll to perform the next steps of '
             'restore such as fetch the progress of restore.')
]


CONF = cfg.CONF
CONF.register_opts(data_opts)
CONF.register_opts(backup_opts)


class DataManager(manager.Manager):
    """Receives requests to handle data and sends responses."""

    RPC_API_VERSION = '1.1'

    def __init__(self, service_name=None, *args, **kwargs):
        super(DataManager, self).__init__(*args, **kwargs)
        self.backup_driver = importutils.import_object(CONF.backup_driver)
        self.busy_tasks_shares = {}
        self.service_id = None

    def init_host(self, service_id=None):
        self.service_id = service_id
        ctxt = context.get_admin_context()
        shares = self.db.share_get_all(ctxt)
        for share in shares:
            if share['task_state'] in constants.BUSY_COPYING_STATES:
                self.db.share_update(
                    ctxt, share['id'],
                    {'task_state': constants.TASK_STATE_DATA_COPYING_ERROR})

    def migration_start(self, context, ignore_list, share_id,
                        share_instance_id, dest_share_instance_id,
                        connection_info_src, connection_info_dest):

        LOG.debug(
            "Received request to migrate share content from share instance "
            "%(instance_id)s to instance %(dest_instance_id)s.",
            {'instance_id': share_instance_id,
             'dest_instance_id': dest_share_instance_id})

        share_ref = self.db.share_get(context, share_id)
        share_instance_ref = self.db.share_instance_get(
            context, share_instance_id, with_share_data=True)

        share_rpcapi = share_rpc.ShareAPI()

        mount_path = CONF.mount_tmp_location

        try:
            copy = data_utils.Copy(
                os.path.join(mount_path, share_instance_id),
                os.path.join(mount_path, dest_share_instance_id),
                ignore_list, CONF.check_hash)

            info_src = {
                'share_id': share_ref['id'],
                'share_instance_id': share_instance_id,
                'mount': connection_info_src['mount'],
                'unmount': connection_info_src['unmount'],
                'access_mapping': connection_info_src.get(
                    'access_mapping', {}),
                'mount_point': os.path.join(mount_path,
                                            share_instance_id),
            }

            info_dest = {
                'share_id': None,
                'share_instance_id': dest_share_instance_id,
                'mount': connection_info_dest['mount'],
                'unmount': connection_info_dest['unmount'],
                'access_mapping': connection_info_dest.get(
                    'access_mapping', {}),
                'mount_point': os.path.join(mount_path,
                                            dest_share_instance_id),
            }

            self._copy_share_data(context, copy, info_src, info_dest)
        except exception.ShareDataCopyCancelled:
            share_rpcapi.migration_complete(
                context, share_instance_ref, dest_share_instance_id)
            return
        except Exception:
            self.db.share_update(
                context, share_id,
                {'task_state': constants.TASK_STATE_DATA_COPYING_ERROR})
            msg = _("Failed to copy contents from instance %(src)s to "
                    "instance %(dest)s.") % {'src': share_instance_id,
                                             'dest': dest_share_instance_id}
            LOG.exception(msg)
            share_rpcapi.migration_complete(
                context, share_instance_ref, dest_share_instance_id)
            raise exception.ShareDataCopyFailed(reason=msg)
        finally:
            self.busy_tasks_shares.pop(share_id, None)

        LOG.info(
            "Completed copy operation of migrating share content from share "
            "instance %(instance_id)s to instance %(dest_instance_id)s.",
            {'instance_id': share_instance_id,
             'dest_instance_id': dest_share_instance_id})

    def data_copy_cancel(self, context, share_id):
        LOG.debug("Received request to cancel data copy "
                  "of share %s.", share_id)
        copy = self.busy_tasks_shares.get(share_id)
        if copy:
            copy.cancel()
        else:
            msg = _("Data copy for migration of share %s cannot be cancelled"
                    " at this moment.") % share_id
            LOG.error(msg)
            raise exception.InvalidShare(reason=msg)

    def data_copy_get_progress(self, context, share_id):
        LOG.debug("Received request to get data copy information "
                  "of share %s.", share_id)
        copy = self.busy_tasks_shares.get(share_id)
        if copy:
            result = copy.get_progress()
            LOG.info("Obtained following data copy information "
                     "of share %(share)s: %(info)s.",
                     {'share': share_id,
                      'info': result})
            return result
        else:
            msg = _("Migration of share %s data copy progress cannot be "
                    "obtained at this moment.") % share_id
            LOG.error(msg)
            raise exception.InvalidShare(reason=msg)

    def _copy_share_data(self, context, copy, info_src, info_dest):
        """Copy share data between source and destination.

        e.g. During migration source and destination both are shares
        and during backup create, destination is backup location
        while during backup restore, source is backup location.
        1. Mount source and destination. Create access rules.
        2. Perform copy
        3. Unmount source and destination. Cleanup access rules.
        """
        mount_path = CONF.mount_tmp_location

        if info_src.get('share_id'):
            share_id = info_src['share_id']
        elif info_dest.get('share_id'):
            share_id = info_dest['share_id']
        else:
            msg = _("Share data copy failed because of undefined share.")
            LOG.exception(msg)
            raise exception.ShareDataCopyFailed(reason=msg)

        share_instance_src = None
        share_instance_dest = None
        if info_src['share_instance_id']:
            share_instance_src = self.db.share_instance_get(
                context, info_src['share_instance_id'], with_share_data=True)
        if info_dest['share_instance_id']:
            share_instance_dest = self.db.share_instance_get(
                context, info_dest['share_instance_id'], with_share_data=True)

        share = self.db.share_get(context, share_id)
        self.db.share_update(
            context, share['id'],
            {'task_state': constants.TASK_STATE_DATA_COPYING_STARTING})

        helper_src = helper.DataServiceHelper(context, self.db, share)
        helper_dest = helper_src

        if share_instance_src:
            access_ref_src = helper_src.allow_access_to_data_service(
                share_instance_src, info_src, share_instance_dest, info_dest)
            access_ref_dest = access_ref_src
        elif share_instance_dest:
            access_ref_src = helper_src.allow_access_to_data_service(
                share_instance_dest, info_dest, share_instance_src, info_src)
            access_ref_dest = access_ref_src

        def _call_cleanups(items):
            for item in items:
                if 'unmount_src' == item:
                    helper_src.cleanup_unmount_temp_folder(
                        info_src, mount_path)
                elif 'temp_folder_src' == item:
                    helper_src.cleanup_temp_folder(
                        mount_path, info_src['share_instance_id'])
                elif 'temp_folder_dest' == item:
                    helper_dest.cleanup_temp_folder(
                        mount_path, info_dest['share_instance_id'])
                elif 'access_src' == item and share_instance_src:
                    helper_src.cleanup_data_access(
                        access_ref_src, share_instance_src)
                elif 'access_dest' == item and share_instance_dest:
                    helper_dest.cleanup_data_access(
                        access_ref_dest, share_instance_dest)
        try:
            helper_src.mount_share_instance_or_backup(info_src, mount_path)
        except Exception:
            msg = _("Share data copy failed attempting to mount source "
                    "at %s.") % info_src['mount_point']
            LOG.exception(msg)
            _call_cleanups(['temp_folder_src', 'access_dest', 'access_src'])
            raise exception.ShareDataCopyFailed(reason=msg)

        try:
            helper_dest.mount_share_instance_or_backup(info_dest, mount_path)
        except Exception:
            msg = _("Share data copy failed attempting to mount destination "
                    "at %s.") % info_dest['mount_point']
            LOG.exception(msg)
            _call_cleanups(['temp_folder_dest', 'unmount_src',
                            'temp_folder_src', 'access_dest', 'access_src'])
            raise exception.ShareDataCopyFailed(reason=msg)

        self.busy_tasks_shares[share['id']] = copy
        self.db.share_update(
            context, share['id'],
            {'task_state': constants.TASK_STATE_DATA_COPYING_IN_PROGRESS})

        copied = False
        try:
            copy.run()
            self.db.share_update(
                context, share['id'],
                {'task_state': constants.TASK_STATE_DATA_COPYING_COMPLETING})
            if copy.get_progress()['total_progress'] == 100:
                copied = True
        except Exception:
            LOG.exception("Failed to copy data from source to destination "
                          "%(src)s to %(dest)s.",
                          {'src': info_src['mount_point'],
                           'dest': info_dest['mount_point']})

        try:
            helper_src.unmount_share_instance_or_backup(info_src,
                                                        mount_path)
        except Exception:
            LOG.exception("Could not unmount src %s after its data copy.",
                          info_src['mount_point'])

        try:
            helper_dest.unmount_share_instance_or_backup(info_dest,
                                                         mount_path)
        except Exception:
            LOG.exception("Could not unmount dest %s after its data copy.",
                          info_dest['mount_point'])

        try:
            if info_src['share_instance_id']:
                helper_src.deny_access_to_data_service(access_ref_src,
                                                       share_instance_src)
        except Exception:
            LOG.exception("Could not deny access to src instance %s after "
                          "its data copy.", info_src['share_instance_id'])

        try:
            if info_dest['share_instance_id']:
                helper_dest.deny_access_to_data_service(access_ref_dest,
                                                        share_instance_dest)
        except Exception:
            LOG.exception("Could not deny access to dest instance %s after "
                          "its data copy.", info_dest['share_instance_id'])

        if copy and copy.cancelled:
            self.db.share_update(
                context, share['id'],
                {'task_state': constants.TASK_STATE_DATA_COPYING_CANCELLED})
            LOG.warning("Copy of data from source "
                        "%(src)s to destination %(dest)s was cancelled.",
                        {'src': info_src['mount_point'],
                         'dest': info_dest['mount_point']})
            raise exception.ShareDataCopyCancelled()
        elif not copied:
            msg = _("Copying data from source %(src)s "
                    "to destination %(dest)s did not succeed.") % (
                        {'src': info_src['mount_point'],
                         'dest': info_dest['mount_point']})
            raise exception.ShareDataCopyFailed(reason=msg)

        self.db.share_update(
            context, share['id'],
            {'task_state': constants.TASK_STATE_DATA_COPYING_COMPLETED})

        LOG.debug("Copy of data from source %(src)s to destination "
                  "%(dest)s was successful.", {
                      'src': info_src['mount_point'],
                      'dest': info_dest['mount_point']})

    def create_backup(self, context, backup):
        share_id = backup['share_id']
        backup_id = backup['id']
        share = self.db.share_get(context, share_id)
        backup = self.db.share_backup_get(context, backup_id)

        self.db.share_backup_update(context, backup_id, {'host': self.host})

        LOG.info('Create backup started, backup: %(backup_id)s '
                 'share: %(share_id)s.',
                 {'backup_id': backup_id, 'share_id': share_id})

        try:
            self._run_backup(context, backup, share)
        except Exception as err:
            with excutils.save_and_reraise_exception():
                LOG.error("Failed to create share backup %s by data driver.",
                          backup['id'])
                self.db.share_update(
                    context, share_id,
                    {'status': constants.STATUS_AVAILABLE})
                self.db.share_backup_update(
                    context, backup_id,
                    {'status': constants.STATUS_ERROR, 'fail_reason': err})
        self.db.share_update(
            context, share_id, {'status': constants.STATUS_AVAILABLE})
        self.db.share_backup_update(
            context, backup_id,
            {'status': constants.STATUS_AVAILABLE, 'progress': '100'})
        LOG.info("Created share backup %s successfully.", backup_id)

    @periodic_task.periodic_task(
        spacing=CONF.backup_continue_update_interval)
    def create_backup_continue(self, context):
        filters = {
            'status': constants.STATUS_CREATING,
            'host': self.host,
            'topic': CONF.data_topic
        }
        backups = self.db.share_backups_get_all(context, filters)

        for backup in backups:
            backup_id = backup['id']
            share_id = backup['share_id']
            result = {}
            try:
                result = self.data_copy_get_progress(context, share_id)
                progress = result.get('total_progress', '0')
                backup_values = {'progress': progress}
                if progress == '100':
                    self.db.share_update(
                        context, share_id,
                        {'status': constants.STATUS_AVAILABLE})
                    backup_values.update(
                        {'status': constants.STATUS_AVAILABLE})
                    LOG.info("Created share backup %s successfully.",
                             backup_id)
                self.db.share_backup_update(context, backup_id, backup_values)
            except Exception:
                LOG.warning("Failed to get progress of share %(share)s "
                            "backing up in share_backup %(backup).",
                            {'share': share_id, 'backup': backup_id})
                self.db.share_update(
                    context, share_id,
                    {'status': constants.STATUS_AVAILABLE})
                self.db.share_backup_update(
                    context, backup_id,
                    {'status': constants.STATUS_ERROR, 'progress': '0'})

    def _get_share_mount_info(self, share_instance):
        mount_template = CONF.backup_share_mount_template

        path = next((x['path'] for x in share_instance['export_locations']
                    if x['is_admin_only']), None)
        if not path:
            path = share_instance['export_locations'][0]['path']

        format_args = {
            'proto': share_instance['share_proto'].lower(),
            'export': path,
            'path': '%(path)s',
            'options': '%(options)s',
        }

        unmount_template = CONF.backup_share_unmount_template
        mount_info = {
            'mount': mount_template % format_args,
            'unmount': unmount_template,
        }
        return mount_info

    def _get_backup_access_mapping(self, share):
        mapping = CONF.backup_protocol_access_mapping
        result = {}
        share_proto = share['share_proto'].lower()
        for access_type, protocols in mapping.items():
            if share_proto in [y.lower() for y in protocols]:
                result[access_type] = result.get(access_type, [])
                result[access_type].append(share_proto)
        return result

    def _run_backup(self, context, backup, share):
        share_instance_id = share.instance.get('id')
        share_instance = self.db.share_instance_get(
            context, share_instance_id, with_share_data=True)

        access_mapping = self._get_backup_access_mapping(share)
        ignore_list = CONF.backup_ignore_files
        mount_path = CONF.mount_tmp_location
        backup_mount_path = CONF.backup_mount_tmp_location

        mount_info = self._get_share_mount_info(share_instance)
        dest_backup_info = self.backup_driver.get_backup_info(backup)

        dest_backup_mount_point = os.path.join(backup_mount_path, backup['id'])
        backup_folder = os.path.join(dest_backup_mount_point, backup['id'])

        try:
            copy = data_utils.Copy(
                os.path.join(mount_path, share_instance_id),
                backup_folder,
                ignore_list)

            info_src = {
                'share_id': share['id'],
                'share_instance_id': share_instance_id,
                'mount': mount_info['mount'],
                'unmount': mount_info['unmount'],
                'mount_point': os.path.join(mount_path, share_instance_id),
                'access_mapping': access_mapping
            }

            info_dest = {
                'share_id': None,
                'share_instance_id': None,
                'backup': True,
                'backup_id': backup['id'],
                'mount': dest_backup_info['mount'],
                'unmount': dest_backup_info['unmount'],
                'mount_point': dest_backup_mount_point,
                'access_mapping': access_mapping
            }
            self._copy_share_data(context, copy, info_src, info_dest)
            self.db.share_update(context, share['id'], {'task_state': None})
        except Exception:
            self.db.share_update(
                context, share['id'],
                {'task_state': constants.TASK_STATE_DATA_COPYING_ERROR})
            msg = _("Failed to copy contents from share %(src)s to "
                    "backup %(dest)s.") % (
                        {'src': share_instance_id, 'dest': backup['id']})
            LOG.exception(msg)
            raise exception.ShareDataCopyFailed(reason=msg)
        finally:
            self.busy_tasks_shares.pop(share['id'], None)

    def delete_backup(self, context, backup):
        backup_id = backup['id']
        LOG.info('Delete backup started, backup: %s.', backup_id)

        backup = self.db.share_backup_get(context, backup_id)
        try:
            dest_backup_info = self.backup_driver.get_backup_info(backup)
            backup_mount_path = CONF.backup_mount_tmp_location
            mount_point = os.path.join(backup_mount_path, backup['id'])
            backup_folder = os.path.join(mount_point, backup['id'])
            if not os.path.exists(backup_folder):
                os.makedirs(backup_folder)
            if not os.path.exists(backup_folder):
                raise exception.NotFound("Path %s could not be "
                                         "found." % backup_folder)

            mount_template = dest_backup_info['mount']
            unmount_template = dest_backup_info['unmount']
            mount_command = mount_template % {'path': mount_point}
            unmount_command = unmount_template % {'path': mount_point}
            utils.execute(*(mount_command.split()), run_as_root=True)

            # backup_folder should exist after mount, else backup is
            # already deleted
            if os.path.exists(backup_folder):
                for filename in os.listdir(backup_folder):
                    if filename in CONF.backup_ignore_files:
                        continue
                    file_path = os.path.join(backup_folder, filename)
                    try:
                        if (os.path.isfile(file_path) or
                                os.path.islink(file_path)):
                            os.unlink(file_path)
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                    except Exception as e:
                        LOG.debug("Failed to delete %(file_path)s. Reason: "
                                  "%(err)s", {'file_path': file_path,
                                              'err': e})
                shutil.rmtree(backup_folder)
            utils.execute(*(unmount_command.split()), run_as_root=True)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error("Failed to delete share backup %s.", backup['id'])
                self.db.share_backup_update(
                    context, backup['id'],
                    {'status': constants.STATUS_ERROR_DELETING})

        try:
            reserve_opts = {
                'backups': -1,
                'backup_gigabytes': -backup['size'],
            }
            reservations = QUOTAS.reserve(
                context, project_id=backup['project_id'], **reserve_opts)
        except Exception as e:
            reservations = None
            LOG.warning("Failed to update backup quota for %(pid)s: %(err)s.",
                        {'pid': backup['project_id'], 'err': e})
            raise

        if reservations:
            QUOTAS.commit(context, reservations,
                          project_id=backup['project_id'])

        self.db.share_backup_delete(context, backup_id)
        LOG.info("Share backup %s deleted successfully.", backup_id)

    def restore_backup(self, context, backup, share_id):
        backup_id = backup['id']
        LOG.info('Restore backup started, backup: %(backup_id)s '
                 'share: %(share_id)s.',
                 {'backup_id': backup['id'], 'share_id': share_id})

        share = self.db.share_get(context, share_id)
        backup = self.db.share_backup_get(context, backup_id)

        try:
            self._run_restore(context, backup, share)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error("Failed to restore backup %(backup)s to share "
                          "%(share)s by data driver.",
                          {'backup': backup['id'], 'share': share_id})
                self.db.share_update(
                    context, share_id,
                    {'status': constants.STATUS_BACKUP_RESTORING_ERROR})
                self.db.share_backup_update(
                    context, backup_id,
                    {'status': constants.STATUS_AVAILABLE})
        self.db.share_update(
            context, share_id, {'status': constants.STATUS_AVAILABLE})
        self.db.share_backup_update(
            context, backup_id,
            {'status': constants.STATUS_AVAILABLE, 'restore_progress': '100'})
        LOG.info("Share backup %s restored successfully.", backup_id)

    @periodic_task.periodic_task(
        spacing=CONF.restore_continue_update_interval)
    def restore_backup_continue(self, context):
        filters = {
            'status': constants.STATUS_RESTORING,
            'host': self.host,
            'topic': CONF.data_topic
        }
        backups = self.db.share_backups_get_all(context, filters)
        for backup in backups:
            backup_id = backup['id']
            try:
                filters = {
                    'source_backup_id': backup_id,
                }
                shares = self.db.share_get_all(context, filters)
            except Exception:
                LOG.warning('Failed to get shares for backup %s', backup_id)
                continue

            for share in shares:
                if share['status'] != constants.STATUS_BACKUP_RESTORING:
                    continue

                share_id = share['id']
                result = {}
                try:
                    result = self.data_copy_get_progress(context, share_id)
                    progress = result.get('total_progress', '0')
                    backup_values = {'restore_progress': progress}
                    if progress == '100':
                        self.db.share_update(
                            context, share_id,
                            {'status': constants.STATUS_AVAILABLE})
                        backup_values.update(
                            {'status': constants.STATUS_AVAILABLE})
                        LOG.info("Share backup %s restored successfully.",
                                 backup_id)
                    self.db.share_backup_update(context, backup_id,
                                                backup_values)
                except Exception:
                    LOG.exception("Failed to get progress of share_backup "
                                  "%(backup)s restoring in share %(share).",
                                  {'share': share_id, 'backup': backup_id})
                    self.db.share_update(
                        context, share_id,
                        {'status': constants.STATUS_BACKUP_RESTORING_ERROR})
                    self.db.share_backup_update(
                        context, backup_id,
                        {'status': constants.STATUS_AVAILABLE,
                         'restore_progress': '0'})

    def _run_restore(self, context, backup, share):
        share_instance_id = share.instance.get('id')
        share_instance = self.db.share_instance_get(
            context, share_instance_id, with_share_data=True)

        access_mapping = self._get_backup_access_mapping(share)
        mount_path = CONF.mount_tmp_location
        backup_mount_path = CONF.backup_mount_tmp_location
        ignore_list = CONF.backup_ignore_files

        mount_info = self._get_share_mount_info(share_instance)
        src_backup_info = self.backup_driver.get_backup_info(backup)

        src_backup_mount_point = os.path.join(backup_mount_path, backup['id'])
        backup_folder = os.path.join(src_backup_mount_point, backup['id'])

        try:
            copy = data_utils.Copy(
                backup_folder,
                os.path.join(mount_path, share_instance_id),
                ignore_list)

            info_src = {
                'share_id': None,
                'share_instance_id': None,
                'restore': True,
                'backup_id': backup['id'],
                'mount': src_backup_info['mount'],
                'unmount': src_backup_info['unmount'],
                'mount_point': src_backup_mount_point,
                'access_mapping': access_mapping
            }

            info_dest = {
                'share_id': share['id'],
                'share_instance_id': share_instance_id,
                'mount': mount_info['mount'],
                'unmount': mount_info['unmount'],
                'mount_point': os.path.join(mount_path, share_instance_id),
                'access_mapping': access_mapping
            }

            self._copy_share_data(context, copy, info_src, info_dest)
            self.db.share_update(context, share['id'], {'task_state': None})
        except Exception:
            self.db.share_update(
                context, share['id'],
                {'task_state': constants.TASK_STATE_DATA_COPYING_ERROR})
            msg = _("Failed to copy/restore contents from backup %(src)s "
                    "to share %(dest)s.") % (
                        {'src': backup['id'], 'dest': share_instance_id})
            LOG.exception(msg)
            raise exception.ShareDataCopyFailed(reason=msg)
        finally:
            self.busy_tasks_shares.pop(share['id'], None)
