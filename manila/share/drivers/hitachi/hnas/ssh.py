# Copyright (c) 2015 Hitachi Data Systems, Inc.
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

from oslo_concurrency import processutils
from oslo_log import log
from oslo_utils import strutils
from oslo_utils import units
import paramiko
import six

import os
import time

from manila import exception
from manila.i18n import _
from manila import utils as mutils

LOG = log.getLogger(__name__)


class HNASSSHBackend(object):
    def __init__(self, hnas_ip, hnas_username, hnas_password, ssh_private_key,
                 cluster_admin_ip0, evs_id, evs_ip, fs_name, job_timeout):
        self.ip = hnas_ip
        self.port = 22
        self.user = hnas_username
        self.password = hnas_password
        self.priv_key = ssh_private_key
        self.admin_ip0 = cluster_admin_ip0
        self.evs_id = six.text_type(evs_id)
        self.fs_name = fs_name
        self.evs_ip = evs_ip
        self.sshpool = None
        self.job_timeout = job_timeout
        LOG.debug("Hitachi HNAS Driver using SSH backend.")

    def get_stats(self):
        """Get the stats from file-system.

        :returns:
        fs_capacity.size = Total size from filesystem.
        available_space = Free space currently on filesystem.
        dedupe = True if dedupe is enabled on filesystem.
        """
        command = ['df', '-a', '-f', self.fs_name]
        try:
            output, err = self._execute(command)

        except processutils.ProcessExecutionError:
            msg = _("Could not get HNAS backend stats.")
            LOG.exception(msg)
            raise exception.HNASBackendException(msg=msg)

        line = output.split('\n')
        fs = Filesystem(line[3])
        available_space = fs.size - fs.used
        return fs.size, available_space, fs.dedupe

    def nfs_export_add(self, share_id, snapshot_id=None):
        if snapshot_id is not None:
            path = os.path.join('/snapshots', share_id, snapshot_id)
            name = os.path.join('/snapshots', snapshot_id)
        else:
            path = name = os.path.join('/shares', share_id)

        command = ['nfs-export', 'add', '-S', 'disable', '-c', '127.0.0.1',
                   name, self.fs_name, path]
        try:
            self._execute(command)
        except processutils.ProcessExecutionError:
            msg = _("Could not create NFS export %s.") % name
            LOG.exception(msg)
            raise exception.HNASBackendException(msg=msg)

    def nfs_export_del(self, share_id=None, snapshot_id=None):
        if share_id is not None:
            name = os.path.join('/shares', share_id)
        elif snapshot_id is not None:
            name = os.path.join('/snapshots', snapshot_id)
        else:
            msg = _("NFS export not specified to delete.")
            raise exception.HNASBackendException(msg=msg)

        command = ['nfs-export', 'del', name]
        try:
            self._execute(command)
        except processutils.ProcessExecutionError as e:
            if 'does not exist' in e.stderr:
                LOG.warning("Export %s does not exist on "
                            "backend anymore.", name)
            else:
                msg = _("Could not delete NFS export %s.") % name
                LOG.exception(msg)
                raise exception.HNASBackendException(msg=msg)

    def cifs_share_add(self, share_id, snapshot_id=None):
        if snapshot_id is not None:
            path = r'\\snapshots\\' + share_id + r'\\' + snapshot_id
            name = snapshot_id
        else:
            path = r'\\shares\\' + share_id
            name = share_id
        command = ['cifs-share', 'add', '-S', 'disable', '--enable-abe',
                   '--nodefaultsaa', name, self.fs_name, path]
        try:
            self._execute(command)
        except processutils.ProcessExecutionError:
            msg = _("Could not create CIFS share %s.") % name
            LOG.exception(msg)
            raise exception.HNASBackendException(msg=msg)

    def cifs_share_del(self, name):
        command = ['cifs-share', 'del', '--target-label', self.fs_name,
                   name]
        try:
            self._execute(command)
        except processutils.ProcessExecutionError as e:
            if e.exit_code == 1:
                LOG.warning("CIFS share %s does not exist on "
                            "backend anymore.", name)
            else:
                msg = _("Could not delete CIFS share %s.") % name
                LOG.exception(msg)
                raise exception.HNASBackendException(msg=msg)

    def get_nfs_host_list(self, share_id):
        export = self._get_export(share_id)
        return export[0].export_configuration

    def update_nfs_access_rule(self, host_list, share_id=None,
                               snapshot_id=None):
        if share_id is not None:
            name = os.path.join('/shares', share_id)
        elif snapshot_id is not None:
            name = os.path.join('/snapshots', snapshot_id)
        else:
            msg = _("No share/snapshot provided to update NFS rules.")
            raise exception.HNASBackendException(msg=msg)

        command = ['nfs-export', 'mod', '-c']

        if len(host_list) == 0:
            command.append('127.0.0.1')
        else:
            string_command = '"' + six.text_type(host_list[0])

            for i in range(1, len(host_list)):
                string_command += ',' + (six.text_type(host_list[i]))
            string_command += '"'
            command.append(string_command)

        command.append(name)
        try:
            self._execute(command)
        except processutils.ProcessExecutionError:
            msg = _("Could not update access rules for NFS export %s.") % name
            LOG.exception(msg)
            raise exception.HNASBackendException(msg=msg)

    def cifs_allow_access(self, name, user, permission, is_snapshot=False):
        command = ['cifs-saa', 'add', '--target-label', self.fs_name,
                   name, user, permission]

        try:
            self._execute(command)
        except processutils.ProcessExecutionError as e:
            if 'already listed as a user' in e.stderr:
                if is_snapshot:
                    LOG.debug('User %(user)s already allowed to access '
                              'snapshot %(snapshot)s.', {
                                  'user': user,
                                  'snapshot': name,
                              })
                else:
                    self._update_cifs_rule(name, user, permission)
            else:
                entity_type = "share"
                if is_snapshot:
                    entity_type = "snapshot"

                msg = _("Could not add access of user %(user)s to "
                        "%(entity_type)s %(name)s.") % {
                            'user': user,
                            'name': name,
                            'entity_type': entity_type,
                    }
                LOG.exception(msg)
                raise exception.HNASBackendException(msg=msg)

    def _update_cifs_rule(self, name, user, permission):
        LOG.debug('User %(user)s already allowed to access '
                  'share %(share)s. Updating access level...', {
                      'user': user,
                      'share': name,
                  })

        command = ['cifs-saa', 'change', '--target-label', self.fs_name,
                   name, user, permission]
        try:
            self._execute(command)
        except processutils.ProcessExecutionError:
            msg = _("Could not update access of user %(user)s to "
                    "share %(share)s.") % {
                        'user': user,
                        'share': name,
                }
            LOG.exception(msg)
            raise exception.HNASBackendException(msg=msg)

    def cifs_deny_access(self, name, user, is_snapshot=False):
        command = ['cifs-saa', 'delete', '--target-label', self.fs_name,
                   name, user]

        entity_type = "share"
        if is_snapshot:
            entity_type = "snapshot"

        try:
            self._execute(command)
        except processutils.ProcessExecutionError as e:
            if ('not listed as a user' in e.stderr or
                    'Could not delete user/group' in e.stderr):
                LOG.warning('User %(user)s already not allowed to access '
                            '%(entity_type)s %(name)s.', {
                                'entity_type': entity_type,
                                'user': user,
                                'name': name
                            })
            else:
                msg = _("Could not delete access of user %(user)s to "
                        "%(entity_type)s %(name)s.") % {
                    'user': user,
                    'name': name,
                    'entity_type': entity_type,
                    }
                LOG.exception(msg)
                raise exception.HNASBackendException(msg=msg)

    def list_cifs_permissions(self, hnas_share_id):
        command = ['cifs-saa', 'list', '--target-label', self.fs_name,
                   hnas_share_id]
        try:
            output, err = self._execute(command)
        except processutils.ProcessExecutionError as e:
            if 'No entries for this share' in e.stderr:
                LOG.debug('Share %(share)s does not have any permission '
                          'added.', {'share': hnas_share_id})
                return []
            else:
                msg = _("Could not list access of share %s.") % hnas_share_id
                LOG.exception(msg)
                raise exception.HNASBackendException(msg=msg)

        permissions = CIFSPermissions(output)

        return permissions.permission_list

    def tree_clone(self, src_path, dest_path):
        command = ['tree-clone-job-submit', '-e', '-f', self.fs_name,
                   src_path, dest_path]
        try:
            output, err = self._execute(command)
        except processutils.ProcessExecutionError as e:
            if ('Cannot find any clonable files in the source directory' in
                    e.stderr):
                msg = _("Source path %s is empty.") % src_path
                LOG.debug(msg)
                raise exception.HNASNothingToCloneException(msg=msg)
            else:
                msg = _("Could not submit tree clone job to clone from %(src)s"
                        " to %(dest)s.") % {'src': src_path, 'dest': dest_path}
                LOG.exception(msg)
                raise exception.HNASBackendException(msg=msg)

        job_submit = JobSubmit(output)
        if job_submit.request_status == 'Request submitted successfully':
            job_id = job_submit.job_id

            job_status = None
            progress = ''
            job_rechecks = 0
            starttime = time.time()
            deadline = starttime + self.job_timeout
            while (not job_status or
                   job_status.job_state != "Job was completed"):

                command = ['tree-clone-job-status', job_id]
                output, err = self._execute(command)
                job_status = JobStatus(output)

                if job_status.job_state == 'Job failed':
                    break

                old_progress = progress
                progress = job_status.data_bytes_processed

                if old_progress == progress:
                    job_rechecks += 1
                    now = time.time()
                    if now > deadline:
                        command = ['tree-clone-job-abort', job_id]
                        self._execute(command)
                        LOG.error("Timeout in snapshot creation from "
                                  "source path %s.", src_path)
                        msg = _("Share snapshot of source path %s "
                                "was not created.") % src_path
                        raise exception.HNASBackendException(msg=msg)
                    else:
                        time.sleep(job_rechecks ** 2)
                else:
                    job_rechecks = 0

            if (job_status.job_state, job_status.job_status,
                job_status.directories_missing,
                job_status.files_missing) == ("Job was completed",
                                              "Success", '0', '0'):

                LOG.debug("Snapshot of source path %(src)s to destination "
                          "path %(dest)s created successfully.",
                          {'src': src_path,
                           'dest': dest_path})
            else:
                LOG.error('Error creating snapshot of source path %s.',
                          src_path)
                msg = _('Snapshot of source path %s was not '
                        'created.') % src_path
                raise exception.HNASBackendException(msg=msg)

    def tree_delete(self, path):
        command = ['tree-delete-job-submit', '--confirm', '-f', self.fs_name,
                   path]
        try:
            self._execute(command)
        except processutils.ProcessExecutionError as e:
            if 'Source path: Cannot access' in e.stderr:
                LOG.warning("Attempted to delete path %s "
                            "but it does not exist.", path)
            else:
                msg = _("Could not submit tree delete job to delete path "
                        "%s.") % path
                LOG.exception(msg)
                raise exception.HNASBackendException(msg=msg)

    @mutils.retry(exception=exception.HNASSSCContextChange, wait_random=True,
                  retries=5)
    def create_directory(self, dest_path):
        self._locked_selectfs('create', dest_path)
        if not self.check_directory(dest_path):
            msg = _("Command to create directory %(path)s was run in another "
                    "filesystem instead of %(fs)s.") % {
                'path': dest_path,
                'fs': self.fs_name,
            }
            LOG.warning(msg)
            raise exception.HNASSSCContextChange(msg=msg)

    @mutils.retry(exception=exception.HNASSSCContextChange, wait_random=True,
                  retries=5)
    def delete_directory(self, path):
        try:
            self._locked_selectfs('delete', path)
        except exception.HNASDirectoryNotEmpty:
            pass
        else:
            if self.check_directory(path):
                msg = _("Command to delete empty directory %(path)s was run in"
                        " another filesystem instead of %(fs)s.") % {
                            'path': path,
                            'fs': self.fs_name,
                    }
                LOG.debug(msg)
                raise exception.HNASSSCContextChange(msg=msg)

    @mutils.retry(exception=exception.HNASSSCIsBusy, wait_random=True,
                  retries=5)
    def check_directory(self, path):
        command = ['path-to-object-number', '-f', self.fs_name, path]

        try:
            self._execute(command)
        except processutils.ProcessExecutionError as e:
            if 'path-to-object-number is currently running' in e.stdout:
                msg = (_("SSC command path-to-object-number for path %s "
                         "is currently busy.") % path)
                raise exception.HNASSSCIsBusy(msg=msg)
            if 'Unable to locate component:' in e.stdout:
                LOG.debug("Cannot find %(path)s: %(out)s",
                          {'path': path, 'out': e.stdout})
                return False
            else:
                msg = _("Could not check if path %s exists.") % path
                LOG.exception(msg)
                raise exception.HNASBackendException(msg=msg)
        return True

    def check_fs_mounted(self):
        command = ['df', '-a', '-f', self.fs_name]
        output, err = self._execute(command)
        if "not found" in output:
            msg = _("Filesystem %s does not exist or it is not available "
                    "in the current EVS context.") % self.fs_name
            LOG.error(msg)
            raise exception.HNASItemNotFoundException(msg=msg)
        else:
            line = output.split('\n')
            fs = Filesystem(line[3])
            return fs.mounted

    def mount(self):
        command = ['mount', self.fs_name]
        try:
            self._execute(command)
        except processutils.ProcessExecutionError as e:
            if 'file system is already mounted' not in e.stderr:
                msg = _("Failed to mount filesystem %s.") % self.fs_name
                LOG.exception(msg)
                raise exception.HNASBackendException(msg=msg)

    def vvol_create(self, vvol_name):
        # create a virtual-volume inside directory
        path = '/shares/' + vvol_name
        command = ['virtual-volume', 'add', '--ensure', self.fs_name,
                   vvol_name, path]
        try:
            self._execute(command)
        except processutils.ProcessExecutionError:
            msg = _("Failed to create vvol %s.") % vvol_name
            LOG.exception(msg)
            raise exception.HNASBackendException(msg=msg)

    def vvol_delete(self, vvol_name):
        path = '/shares/' + vvol_name
        # Virtual-volume and quota are deleted together
        command = ['tree-delete-job-submit', '--confirm', '-f',
                   self.fs_name, path]
        try:
            self._execute(command)
        except processutils.ProcessExecutionError as e:
            if 'Source path: Cannot access' in e.stderr:
                LOG.warning("Share %s does not exist.", vvol_name)
            else:
                msg = _("Failed to delete vvol %s.") % vvol_name
                LOG.exception(msg)
                raise exception.HNASBackendException(msg=msg)

    def quota_add(self, vvol_name, vvol_quota):
        str_quota = six.text_type(vvol_quota) + 'G'
        command = ['quota', 'add', '--usage-limit',
                   str_quota, '--usage-hard-limit',
                   'yes', self.fs_name, vvol_name]
        try:
            self._execute(command)
        except processutils.ProcessExecutionError:
            msg = _("Failed to add %(quota)s quota to vvol "
                    "%(vvol)s.") % {'quota': str_quota, 'vvol': vvol_name}
            LOG.exception(msg)
            raise exception.HNASBackendException(msg=msg)

    def modify_quota(self, vvol_name, new_size):
        str_quota = six.text_type(new_size) + 'G'
        command = ['quota', 'mod', '--usage-limit', str_quota,
                   self.fs_name, vvol_name]
        try:
            self._execute(command)
        except processutils.ProcessExecutionError:
            msg = _("Failed to update quota of vvol %(vvol)s to "
                    "%(quota)s.") % {'quota': str_quota, 'vvol': vvol_name}
            LOG.exception(msg)
            raise exception.HNASBackendException(msg=msg)

    def check_vvol(self, vvol_name):
        command = ['virtual-volume', 'list', '--verbose', self.fs_name,
                   vvol_name]
        try:
            self._execute(command)
        except processutils.ProcessExecutionError:
            msg = _("Virtual volume %s does not exist.") % vvol_name
            LOG.exception(msg)
            raise exception.HNASItemNotFoundException(msg=msg)

    def check_quota(self, vvol_name):
        command = ['quota', 'list', '--verbose', self.fs_name, vvol_name]
        try:
            output, err = self._execute(command)

        except processutils.ProcessExecutionError:
            msg = _("Could not check quota of vvol %s.") % vvol_name
            LOG.exception(msg)
            raise exception.HNASBackendException(msg=msg)

        if 'No quotas matching specified filter criteria' in output:
            msg = _("Virtual volume %s does not have any"
                    " quota.") % vvol_name
            LOG.error(msg)
            raise exception.HNASItemNotFoundException(msg=msg)

    def check_export(self, vvol_name, is_snapshot=False):
        export = self._get_export(vvol_name, is_snapshot=is_snapshot)
        if (vvol_name in export[0].export_name and
                self.fs_name in export[0].file_system_label):
            return
        else:
            msg = _("Export %s does not exist.") % export[0].export_name
            LOG.error(msg)
            raise exception.HNASItemNotFoundException(msg=msg)

    def check_cifs(self, vvol_name):
        output = self._cifs_list(vvol_name)

        cifs_share = CIFSShare(output)

        if self.fs_name != cifs_share.fs:
            msg = _("CIFS share %(share)s is not located in "
                    "configured filesystem "
                    "%(fs)s.") % {'share': vvol_name,
                                  'fs': self.fs_name}
            LOG.error(msg)
            raise exception.HNASItemNotFoundException(msg=msg)

    def is_cifs_in_use(self, vvol_name):
        output = self._cifs_list(vvol_name)

        cifs_share = CIFSShare(output)

        return cifs_share.is_mounted

    def _cifs_list(self, vvol_name):
        command = ['cifs-share', 'list', vvol_name]
        try:
            output, err = self._execute(command)
        except processutils.ProcessExecutionError as e:
            if 'does not exist' in e.stderr:
                msg = _("CIFS share %(share)s was not found in EVS "
                        "%(evs_id)s") % {'share': vvol_name,
                                         'evs_id': self.evs_id}
                LOG.exception(msg)
                raise exception.HNASItemNotFoundException(msg=msg)
            else:
                msg = _("Could not list CIFS shares by vvol name "
                        "%s.") % vvol_name
                LOG.exception(msg)
                raise exception.HNASBackendException(msg=msg)

        return output

    def get_share_quota(self, share_id):
        command = ['quota', 'list', self.fs_name, share_id]
        output, err = self._execute(command)

        quota = Quota(output)

        if quota.limit is None:
            return None

        if quota.limit_unit == 'TB':
            return quota.limit * units.Ki
        elif quota.limit_unit == 'GB':
            return quota.limit
        else:
            msg = _("Share %s does not support quota values "
                    "below 1G.") % share_id
            LOG.error(msg)
            raise exception.HNASBackendException(msg=msg)

    def get_share_usage(self, share_id):
        command = ['quota', 'list', self.fs_name, share_id]
        output, err = self._execute(command)

        quota = Quota(output)

        if quota.usage is None:
            msg = _("Virtual volume %s does not have any quota.") % share_id
            LOG.error(msg)
            raise exception.HNASItemNotFoundException(msg=msg)
        else:
            bytes_usage = strutils.string_to_bytes(six.text_type(quota.usage) +
                                                   quota.usage_unit)
            return bytes_usage / units.Gi

    def _get_export(self, name, is_snapshot=False):
        if is_snapshot:
            name = '/snapshots/' + name
        else:
            name = '/shares/' + name

        command = ['nfs-export', 'list ', name]
        export_list = []
        try:
            output, err = self._execute(command)
        except processutils.ProcessExecutionError as e:
            if 'does not exist' in e.stderr:
                msg = _("Export %(name)s was not found in EVS "
                        "%(evs_id)s.") % {
                            'name': name,
                            'evs_id': self.evs_id,
                }
                LOG.exception(msg)
                raise exception.HNASItemNotFoundException(msg=msg)
            else:
                msg = _("Could not list NFS exports by name %s.") % name
                LOG.exception(msg)
                raise exception.HNASBackendException(msg=msg)
        items = output.split('Export name')

        if items[0][0] == '\n':
            items.pop(0)

        for i in range(0, len(items)):
            export_list.append(Export(items[i]))
        return export_list

    @mutils.retry(exception=exception.HNASConnException, wait_random=True)
    def _execute(self, commands):
        command = ['ssc', '127.0.0.1']
        if self.admin_ip0 is not None:
            command = ['ssc', '--smuauth', self.admin_ip0]

        command += ['console-context', '--evs', self.evs_id]
        commands = command + commands

        mutils.check_ssh_injection(commands)
        commands = ' '.join(commands)

        if not self.sshpool:
            self.sshpool = mutils.SSHPool(ip=self.ip,
                                          port=self.port,
                                          conn_timeout=None,
                                          login=self.user,
                                          password=self.password,
                                          privatekey=self.priv_key)
        with self.sshpool.item() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                out, err = processutils.ssh_execute(ssh, commands,
                                                    check_exit_code=True)
                LOG.debug("Command %(cmd)s result: out = %(out)s - err = "
                          "%(err)s.", {
                              'cmd': commands,
                              'out': out,
                              'err': err,
                          })
                return out, err
            except processutils.ProcessExecutionError as e:
                if 'Failed to establish SSC connection' in e.stderr:
                    msg = _("Failed to establish SSC connection.")
                    LOG.debug(msg)
                    raise exception.HNASConnException(msg=msg)
                else:
                    LOG.debug("Error running SSH command. "
                              "Command %(cmd)s result: out = %(out)s - err = "
                              "%(err)s - exit = %(exit)s.", {
                                  'cmd': e.cmd,
                                  'out': e.stdout,
                                  'err': e.stderr,
                                  'exit': e.exit_code,
                              })
                    raise

    @mutils.synchronized("hitachi_hnas_select_fs", external=True)
    def _locked_selectfs(self, op, path):
        if op == 'create':
            command = ['selectfs', self.fs_name, '\n',
                       'ssc', '127.0.0.1', 'console-context', '--evs',
                       self.evs_id, 'mkdir', '-p', path]
            try:
                self._execute(command)
            except processutils.ProcessExecutionError as e:
                if "Current file system invalid: VolumeNotFound" in e.stderr:
                    msg = _("Command to create directory %s failed due to "
                            "context change.") % path
                    LOG.debug(msg)
                    raise exception.HNASSSCContextChange(msg=msg)
                else:
                    msg = _("Failed to create directory %s.") % path
                    LOG.exception(msg)
                    raise exception.HNASBackendException(msg=msg)

        if op == 'delete':
            command = ['selectfs', self.fs_name, '\n',
                       'ssc', '127.0.0.1', 'console-context', '--evs',
                       self.evs_id, 'rmdir', path]
            try:
                self._execute(command)
            except processutils.ProcessExecutionError as e:
                if 'DirectoryNotEmpty' in e.stderr:
                    msg = _("Share %s has more snapshots.") % path
                    LOG.debug(msg)
                    raise exception.HNASDirectoryNotEmpty(msg=msg)
                elif 'cannot remove' in e.stderr and 'NotFound' in e.stderr:
                    LOG.warning("Attempted to delete path %s but it does "
                                "not exist.", path)
                elif 'Current file system invalid: VolumeNotFound' in e.stderr:
                    msg = _("Command to delete empty directory %s failed due "
                            "to context change.") % path
                    LOG.debug(msg)
                    raise exception.HNASSSCContextChange(msg=msg)
                else:
                    msg = _("Failed to delete directory %s.") % path
                    LOG.exception(msg)
                    raise exception.HNASBackendException(msg=msg)


class Export(object):
    def __init__(self, data):
        if data:
            split_data = data.split('Export configuration:\n')
            items = split_data[0].split('\n')

            self.export_name = items[0].split(':')[1].strip()
            self.export_path = items[1].split(':')[1].strip()

            if '*** not available ***' in items[2]:
                self.file_system_info = items[2].split(':')[1].strip()
                index = 0

            else:
                self.file_system_label = items[2].split(':')[1].strip()
                self.file_system_size = items[3].split(':')[1].strip()
                self.file_system_free_space = items[4].split(':')[1].strip()
                self.file_system_state = items[5].split(':')[1]
                self.formatted = items[6].split('=')[1].strip()
                self.mounted = items[7].split('=')[1].strip()
                self.failed = items[8].split('=')[1].strip()
                self.thin_provisioned = items[9].split('=')[1].strip()
                index = 7

            self.access_snapshots = items[3 + index].split(':')[1].strip()
            self.display_snapshots = items[4 + index].split(':')[1].strip()
            self.read_caching = items[5 + index].split(':')[1].strip()
            self.disaster_recovery_setting = items[6 + index].split(':')[1]
            self.recovered = items[7 + index].split('=')[1].strip()
            self.transfer_setting = items[8 + index].split('=')[1].strip()

            self.export_configuration = []
            export_config = split_data[1].split('\n')
            for i in range(0, len(export_config)):
                if any(j.isdigit() or j.isalpha() for j in export_config[i]):
                    self.export_configuration.append(export_config[i])


class JobStatus(object):
    def __init__(self, data):
        if data:
            lines = data.split("\n")

            self.job_id = lines[0].split()[3]
            self.physical_node = lines[2].split()[3]
            self.evs = lines[3].split()[2]
            self.volume_number = lines[4].split()[3]
            self.fs_id = lines[5].split()[4]
            self.fs_name = lines[6].split()[4]
            self.source_path = lines[7].split()[3]
            self.creation_time = " ".join(lines[8].split()[3:5])
            self.destination_path = lines[9].split()[3]
            self.ensure_path_exists = lines[10].split()[5]
            self.job_state = " ".join(lines[12].split()[3:])
            self.job_started = " ".join(lines[14].split()[2:4])
            self.job_ended = " ".join(lines[15].split()[2:4])
            self.job_status = lines[16].split()[2]

            error_details_line = lines[17].split()
            if len(error_details_line) > 3:
                self.error_details = " ".join(error_details_line[3:])
            else:
                self.error_details = None

            self.directories_processed = lines[18].split()[3]
            self.files_processed = lines[19].split()[3]
            self.data_bytes_processed = lines[20].split()[4]
            self.directories_missing = lines[21].split()[4]
            self.files_missing = lines[22].split()[4]
            self.files_skipped = lines[23].split()[4]

            skipping_details_line = lines[24].split()
            if len(skipping_details_line) > 3:
                self.skipping_details = " ".join(skipping_details_line[3:])
            else:
                self.skipping_details = None


class JobSubmit(object):
    def __init__(self, data):
        if data:
            split_data = data.replace(".", "").split()

            self.request_status = " ".join(split_data[1:4])
            self.job_id = split_data[8]


class Filesystem(object):
    def __init__(self, data):
        if data:
            items = data.split()
            self.id = items[0]
            self.label = items[1]
            self.evs = items[2]
            self.size = float(items[3])
            self.size_measure = items[4]
            if self.size_measure == 'TB':
                self.size = self.size * units.Ki
            if items[5:7] == ["Not", "mounted"]:
                self.mounted = False
            else:
                self.mounted = True
                self.used = float(items[5])
                self.used_measure = items[6]
                if self.used_measure == 'TB':
                    self.used = self.used * units.Ki
            self.dedupe = 'dedupe enabled' in data


class Quota(object):
    def __init__(self, data):
        if data:
            if 'No quotas matching' in data:
                self.type = None
                self.target = None
                self.usage = None
                self.usage_unit = None
                self.limit = None
                self.limit_unit = None
            else:
                items = data.split()
                self.type = items[2]
                self.target = items[6]
                self.usage = items[9]
                self.usage_unit = items[10]
                if items[13] == 'Unset':
                    self.limit = None
                else:
                    self.limit = float(items[13])
                    self.limit_unit = items[14]


class CIFSPermissions(object):
    def __init__(self, data):
        self.permission_list = []
        hnas_cifs_permissions = [('Allow Read', 'ar'),
                                 ('Allow Change & Read', 'acr'),
                                 ('Allow Full Control', 'af'),
                                 ('Deny  Read', 'dr'),
                                 ('Deny  Change & Read', 'dcr'),
                                 ('Deny  Full Control', 'df')]

        lines = data.split('\n')

        for line in lines:
            filtered = list(filter(lambda x: x[0] in line,
                                   hnas_cifs_permissions))

            if len(filtered) == 1:
                token, permission = filtered[0]
                user = line.split(token)[1:][0].strip()
                self.permission_list.append((user, permission))


class CIFSShare(object):
    def __init__(self, data):
        lines = data.split('\n')

        for line in lines:
            if 'File system label' in line:
                self.fs = line.split(': ')[1]
            elif 'Share users' in line:
                users = line.split(': ')
                self.is_mounted = users[1] != '0'
