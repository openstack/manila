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
from oslo_utils import units
import paramiko
import six

import time

from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LW
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

    def get_stats(self):
        """Get the stats from file-system.

        The available space is calculated by total space - SUM(quotas).
        :returns:
        total_fs_space = Total size from filesystem in config file.
        available_space = Free space currently on filesystem.
        """
        total_fs_space = self._get_filesystem_capacity()
        total_quota = 0
        share_list = self._get_vvol_list()

        for item in share_list:
            share_quota = self._get_share_quota(item)
            if share_quota is not None:
                total_quota += share_quota
        available_space = total_fs_space - total_quota
        LOG.debug("Available space in the file system: %(space)s.",
                  {'space': available_space})

        return total_fs_space, available_space

    def allow_access(self, share_id, host, share_proto, permission='rw'):
        """Allow access to the share.

        :param share_id: ID of share that access will be allowed.
        :param host: Host to which access will be allowed.
        :param share_proto: Storage protocol of share. Currently,
        only NFS storage protocol is supported.
        :param permission: permission (e.g. 'rw', 'ro') that will be allowed.
        """
        # check if the share exists
        self.ensure_share(share_id, share_proto)
        export = self._nfs_export_list(share_id)

        # get the list that contains all the hosts allowed on the share
        host_list = export[0].export_configuration

        if permission in ('ro', 'rw'):
            host_access = host + '(' + permission + ')'
        else:
            msg = (_("Permission should be 'ro' or 'rw' instead "
                     "of %s") % permission)
            raise exception.HNASBackendException(msg=msg)

        # check if the host(s) is already allowed
        if any(host in x for x in host_list):
            if host_access in host_list:
                LOG.debug("Host: %(host)s is already allowed.",
                          {'host': host})
            else:
                # remove all the hosts with different permissions
                host_list = [
                    x for x in host_list if not x.startswith(host)]
                # add the host with new permission
                host_list.append(host_access)
                self._update_access_rule(share_id, host_list)
        else:
            host_list.append(host_access)
            self._update_access_rule(share_id, host_list)

    def deny_access(self, share_id, host, share_proto, permission):
        """Deny access to the share.

        :param share_id: ID of share that access will be denied.
        :param host: Host to which access will be denied.
        :param share_proto: Storage protocol of share. Currently,
        only NFS storage protocol is supported.
        :param permission: permission (e.g. 'rw', 'ro') that will be denied.
        """
        # check if the share exists
        self.ensure_share(share_id, share_proto)
        export = self._nfs_export_list(share_id)

        # get the list that contains all the hosts allowed on the share
        host_list = export[0].export_configuration

        if permission in ('ro', 'rw'):
            host_access = host + '(' + permission + ')'
        else:
            msg = (_("Permission should be 'ro' or 'rw' instead "
                     "of %s") % permission)
            raise exception.HNASBackendException(msg=msg)

        # check if the host(s) is already not allowed
        if host_access not in host_list:
            LOG.debug("Host: %(host)s is already not allowed.",
                      {'host': host})
        else:
            # remove the host on host_list
            host_list.remove(host_access)
            self._update_access_rule(share_id, host_list)

    def delete_share(self, share_id, share_proto):
        """Deletes share.

        It uses tree-delete-job-submit to format and delete virtual-volumes.
        Quota is deleted with virtual-volume.
        :param share_id: ID of share that will be deleted.
        :param share_proto: Storage protocol of share. Currently,
        only NFS storage protocol is supported.
        """
        try:
            self.ensure_share(share_id, share_proto)
        except exception.HNASBackendException as e:
            LOG.warning(_LW("Share %s does not exist on backend anymore."),
                        share_id)
            LOG.exception(six.text_type(e))

        self._nfs_export_del(share_id)
        self._vvol_delete(share_id)

        LOG.debug("Export and share successfully deleted: %(shr)s on Manila.",
                  {'shr': share_id})

    def ensure_share(self, share_id, share_proto):
        """Ensure that share is exported.

        :param share_id: ID of share that will be checked.
        :param share_proto: Storage protocol of share. Currently,
        only NFS storage protocol is supported.
        :returns: Returns a path of /shares/share_id if the export is ok.
        """
        path = '/shares/' + share_id

        if not self._check_fs_mounted(self.fs_name):
            self._mount(self.fs_name)
            LOG.debug("Filesystem %(fs)s is unmounted. Mounting...",
                      {'fs': self.fs_name})
        self._check_vvol(share_id)
        self._check_quota(share_id)
        self._check_export(share_id)
        return path

    def create_share(self, share_id, share_size, share_proto):
        """Creates share.

        Creates a virtual-volume, adds a quota limit and exports it.
        :param share_id: ID of share that will be created.
        :param share_size: Size limit of share.
        :param share_proto: Storage protocol of share. Currently,
        only NFS storage protocol is supported.
        :returns: Returns a path of /shares/share_id if the export was
        created successfully.
        """
        path = '/shares/' + share_id
        self._vvol_create(share_id, share_size)
        LOG.debug("Share created with id %(shr)s, size %(size)sG.",
                  {'shr': share_id, 'size': share_size})
        try:
            # Create NFS export
            self._nfs_export_add(share_id)
            LOG.debug("NFS Export created to %(shr)s.",
                      {'shr': share_id})
            return path
        except processutils.ProcessExecutionError as e:
            self._vvol_delete(share_id)
            msg = six.text_type(e)
            LOG.exception(msg)
            raise e

    def extend_share(self, share_id, share_size, share_proto):
        """Extends a share to new size.

        :param share_id: ID of share that will be extended.
        :param share_size: New size of share.
        :param share_proto: Storage protocol of share. Currently,
        only NFS storage protocol is supported.
        """
        self.ensure_share(share_id, share_proto)

        total, available_space = self.get_stats()

        LOG.debug("Available space in filesystem: %(space)s.",
                  {'space': available_space})

        if share_size < available_space:
            self._extend_quota(share_id, share_size)
        else:
            msg = (_("Failed to extend share %s.") % share_id)
            raise exception.HNASBackendException(msg=msg)

    def manage_existing(self, share_proto, share_id):
        """Manages a share that exists on backend.

        :param share_proto: Storage protocol of share. Currently,
        only NFS storage protocol is supported.
        :param share_id: ID of share that will be managed.
        :returns: Returns a dict with size of share managed
        and its location (your path in file-system).
        """
        self.ensure_share(share_id, share_proto)

        share_size = self._get_share_quota(share_id)
        if share_size is None:
            msg = (_("The share %s trying to be managed does not have a "
                     "quota limit, please set it before manage.") % share_id)
            raise exception.HNASBackendException(msg=msg)

        path = six.text_type(self.evs_ip) + ':/shares/' + share_id

        return {'size': share_size, 'export_locations': [path]}

    def create_snapshot(self, share_id, snapshot_id):
        """Creates a snapshot of share.

        It copies the directory and all files to a new directory inside
        /snapshots/share_id/.
        :param share_id: ID of share for snapshot.
        :param snapshot_id: ID of new snapshot.
        """

        export = self._nfs_export_list(share_id)
        saved_list = export[0].export_configuration
        new_list = []
        for access in saved_list:
            new_list.append(access.replace('(rw)', '(ro)'))
        self._update_access_rule(share_id, new_list)

        src_path = '/shares/' + share_id
        snap_path = '/snapshots/' + share_id + '/' + snapshot_id

        try:
            command = ['tree-clone-job-submit', '-e', '-f', self.fs_name,
                       src_path, snap_path]

            output, err = self._execute(command)
            job_submit = JobSubmit(output)
            if job_submit.request_status == 'Request submitted successfully':
                job_id = job_submit.job_id

                job_status = None
                progress = ''
                job_rechecks = 0
                starttime = time.time()
                deadline = starttime + self.job_timeout
                while not job_status or \
                        job_status.job_state != "Job was completed":

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
                            output, err = self._execute(command)
                            LOG.error(_LE("Timeout in snapshot %s creation.") %
                                      snapshot_id)
                            msg = (_("Share snapshot %s was not created.")
                                   % snapshot_id)
                            raise exception.HNASBackendException(msg=msg)
                        else:
                            time.sleep(job_rechecks ** 2)
                    else:
                        job_rechecks = 0

                if (job_status.job_state, job_status.job_status,
                    job_status.directories_missing,
                    job_status.files_missing) == ("Job was completed",
                                                  "Success", '0', '0'):

                    LOG.debug("Snapshot %(snapshot_id)s from share "
                              "%(share_id)s created successfully.",
                              {'snapshot_id': snapshot_id,
                               'share_id': share_id})
                else:
                    LOG.error(_LE('Error in snapshot %s creation.'),
                              snapshot_id)
                    msg = (_('Share snapshot %s was not created.') %
                           snapshot_id)
                    raise exception.HNASBackendException(msg=msg)

        except processutils.ProcessExecutionError as e:
            if ('Cannot find any clonable files in the source directory' in
                    e.stderr):

                LOG.warning(_LW("Source directory is empty, creating an empty "
                                "snapshot."))
                self._locked_selectfs('create', snap_path)
            else:
                msg = six.text_type(e)
                LOG.exception(msg)
                raise exception.HNASBackendException(msg=msg)
        finally:
            self._update_access_rule(share_id, saved_list)

    def delete_snapshot(self, share_id, snapshot_id):
        """Deletes snapshot.

        It receives the share_id only to mount the path for snapshot.
        :param share_id: ID of share that snapshot was created.
        :param snapshot_id: ID of snapshot.
        """
        path = '/snapshots/' + share_id + '/' + snapshot_id
        command = ['tree-delete-job-submit', '--confirm', '-f', self.fs_name,
                   path]
        try:
            output, err = self._execute(command)
            path = '/snapshots/' + share_id
            if 'Request submitted successfully' in output:
                self._locked_selectfs('delete', path)

        except processutils.ProcessExecutionError as e:
            if 'Source path: Cannot access' not in e.stderr:
                msg = six.text_type(e)
                LOG.exception(msg)
                raise e

    def create_share_from_snapshot(self, share, snapshot):
        """Creates a new share from snapshot.

        It copies everything from snapshot directory to a new vvol,
        set a quota limit for it and export.
        :param share: a dict from new share.
        :param snapshot: a dict from snapshot that will be copied to
        new share.
        :returns: Returns the path for new share.
        """
        output = ''
        dst_path = '/shares/' + share['id']
        src_path = '/snapshots/' + snapshot['share_id'] + '/' + snapshot['id']

        # Before copying everything to new vvol, we need to create it,
        # because we only can transform an empty directory into a vvol.
        quota = self._get_share_quota(snapshot['share_id'])
        LOG.debug("Share size: %(quota)s.", {'quota': six.text_type(quota)})

        if quota is None:
            msg = (_("The original share %s does not have a quota limit, "
                     "please set it before creating a new "
                     "share.") % share['id'])
            raise exception.HNASBackendException(msg=msg)

        self._vvol_create(share['id'], quota)

        try:
            # Copy the directory to new vvol
            # Syntax: tree-clone-job-submit <source-directory> <new-share>
            LOG.debug("Started share create from: %(shr)s.",
                      {'shr': six.text_type(snapshot['share_id'])})
            command = ['tree-clone-job-submit', '-f', self.fs_name,
                       src_path, dst_path]
            output, err = self._execute(command)
        except processutils.ProcessExecutionError as e:
            if ('Cannot find any clonable files in the source directory' in
                    e.stderr):
                LOG.warning(_LW("Source directory is empty, exporting "
                                "directory."))
                if self._nfs_export_add(share['id']):
                    return dst_path

        if 'Request submitted successfully' in output:
            # Create NFS export
            if self._nfs_export_add(share['id']):
                # Return export path
                return dst_path
        else:
            msg = (_("Share %s was not created.") % share['id'])
            raise exception.HNASBackendException(msg=msg)

    def _execute(self, commands):
        command = ['ssc', '127.0.0.1']
        if self.admin_ip0 is not None:
            command = ['ssc', '--smuauth', self.admin_ip0]

        command = command + ['console-context', '--evs', self.evs_id]
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
                          "%(err)s.", {'cmd': commands,
                                       'out': out, 'err': err})
                return out, err
            except processutils.ProcessExecutionError as e:
                LOG.debug("Command %(cmd)s result: out = %(out)s - err = "
                          "%(err)s - exit = %(exit)s.", {'cmd': e.cmd,
                                                         'out': e.stdout,
                                                         'err': e.stderr,
                                                         'exit': e.exit_code})
                LOG.error(_LE("Error running SSH command."))
                raise

    def _check_fs_mounted(self, fs_name):
        self._check_fs()
        fs_list = self._get_filesystem_list()
        for i in range(0, len(fs_list)):
            if fs_list[i].name == fs_name and fs_list[i].state == 'Mount':
                return True
        return False

    def _get_filesystem_list(self):
        command = ['filesystem-list']
        output, err = self._execute(command)
        items = output.split('\n')
        filesystem_list = []
        fs_name = None
        if len(items) > 2:
            j = 0
            for i in range(2, len(items) - 1):
                if "Filesystem " in items[i] and len(items[i].split()) == 2:
                    description, fs_name = items[i].split()
                    fs_name = fs_name[:len(fs_name) - 1]
                elif "NoEVS" not in items[i]:
                    # Not considering FS without EVS
                    filesystem_list.append(FileSystem(items[i]))
                    if fs_name is not None:
                        filesystem_list[j].name = fs_name
                        fs_name = None
                    j += 1
                else:
                    LOG.debug("Ignoring filesystems without EVS.")

        return filesystem_list

    def _nfs_export_add(self, share_id):
        path = '/shares/' + share_id
        # nfs-export add -S disable -c <export-name> <file-system> <path>
        command = ['nfs-export', 'add', '-S', 'disable', '-c', '127.0.0.1',
                   path, self.fs_name, path]
        output, err = self._execute(command)
        return True

    def _nfs_export_del(self, share_id):
        path = '/shares/' + share_id
        command = ['nfs-export', 'del', path]

        try:
            output, err = self._execute(command)
        except exception.HNASBackendException as e:
            LOG.warning(_LW("Export %s does not exist on backend anymore."),
                        path)
            LOG.exception(six.text_type(e))

    def _update_access_rule(self, share_id, host_list):
        # mount the command line
        command = ['nfs-export', 'mod', '-c']

        if len(host_list) == 0:
            command.append('127.0.0.1')
        else:
            string_command = '"' + six.text_type(host_list[0])

            for i in range(1, len(host_list)):
                string_command += ',' + (six.text_type(host_list[i]))
            string_command += '"'
            command.append(string_command)

        path = '/shares/' + share_id
        command.append(path)
        output, err = self._execute(command)

        if ("Export modified successfully" in output or
                "Export modified successfully" in err):
            return True
        else:
            return False

    def _nfs_export_list(self, share_id=''):
        if share_id is not '':
            share_id = '/shares/' + share_id
        command = ['nfs-export', 'list ', six.text_type(share_id)]
        output, err = self._execute(command)
        nfs_export_list = []

        if 'No exports are currently configured' not in output:
            items = output.split('Export name')

            if items[0][0] == '\n':
                items.pop(0)

            for i in range(0, len(items)):
                nfs_export_list.append(Export(items[i]))

        return nfs_export_list

    def _mount(self, fs):
        command = ['mount', fs]
        try:
            output, err = self._execute(command)
            if 'successfully mounted' in output:
                return True
        except processutils.ProcessExecutionError as e:
            if 'file system is already mounted' in e.stderr:
                return True
            else:
                msg = six.text_type(e)
                LOG.exception(msg)
                raise e

    def _vvol_create(self, vvol_name, vvol_quota):
        # create a virtual-volume inside directory
        if self._check_fs():
            path = '/shares/' + vvol_name
            command = ['virtual-volume', 'add', '--ensure', self.fs_name,
                       vvol_name, path]
            output, err = self._execute(command)

            # put a quota limit in virtual-volume to deny expand abuses
            self._quota_add(vvol_name, vvol_quota)
            return True
        else:
            msg = (_("Filesystem %s does not exist or it is not available "
                     "in the current EVS context.") % self.fs_name)
            raise exception.HNASBackendException(msg=msg)

    def _quota_add(self, vvol_name, vvol_quota):
        if vvol_quota > 0:
            str_quota = six.text_type(vvol_quota) + 'G'
            command = ['quota', 'add', '--usage-limit',
                       str_quota, '--usage-hard-limit',
                       'yes', self.fs_name, vvol_name]
            output, err = self._execute(command)
            return True
        return False

    def _vvol_delete(self, vvol_name):
        path = '/shares/' + vvol_name
        # Virtual-volume and quota are deleted together
        command = ['tree-delete-job-submit', '--confirm', '-f',
                   self.fs_name, path]
        try:
            output, err = self._execute(command)
            return True
        except processutils.ProcessExecutionError as e:
            if 'Source path: Cannot access' in e.stderr:
                LOG.debug("Share %(shr)s does not exist.",
                          {'shr': six.text_type(vvol_name)})
            else:
                msg = six.text_type(e)
                LOG.exception(msg)
                raise e

    def _extend_quota(self, vvol_name, new_size):
        str_quota = six.text_type(new_size) + 'G'
        command = ['quota', 'mod', '--usage-limit', str_quota,
                   self.fs_name, vvol_name]
        output, err = self._execute(command)
        return True

    def _check_fs(self):
        fs_list = self._get_filesystem_list()
        fs_name_list = []
        for i in range(0, len(fs_list)):
            fs_name_list.append(fs_list[i].name)
            if fs_list[i].name == self.fs_name:
                return True
        return False

    def _check_vvol(self, vvol_name):
        command = ['virtual-volume', 'list', '--verbose', self.fs_name,
                   vvol_name]
        try:
            output, err = self._execute(command)
            return True
        except processutils.ProcessExecutionError as e:
            msg = six.text_type(e)
            LOG.exception(msg)
            msg = (_("Virtual volume %s does not exist.") % vvol_name)
            raise exception.HNASBackendException(msg=msg)

    def _check_quota(self, vvol_name):
        command = ['quota', 'list', '--verbose', self.fs_name, vvol_name]
        output, err = self._execute(command)

        if 'No quotas matching specified filter criteria' not in output:
            return True
        else:
            msg = (_("Virtual volume %s does not have any quota.") % vvol_name)
            raise exception.HNASBackendException(msg=msg)

    def _check_export(self, vvol_name):
        export = self._nfs_export_list(vvol_name)
        if (vvol_name in export[0].export_name and
                self.fs_name in export[0].file_system_label):
            return True
        else:
            msg = (_("Export %s does not exist.") % export[0].export_name)
            raise exception.HNASBackendException(msg=msg)

    def _get_share_quota(self, share_id):
        command = ['quota', 'list', self.fs_name, six.text_type(share_id)]
        output, err = self._execute(command)
        items = output.split('\n')

        for i in range(0, len(items) - 1):
            if ('Unset' not in items[i] and
                    'No quotas matching' not in items[i]):
                if 'Limit' in items[i] and 'Hard' in items[i]:
                    quota = float(items[i].split(' ')[12])

                    # If the quota is 1 or more TB, converts to GB
                    if items[i].split(' ')[13] == 'TB':
                        return quota * units.Ki

                    return quota
            else:
                # Returns None if the quota is unset
                return None

    def _get_vvol_list(self):
        command = ['virtual-volume', 'list', self.fs_name]
        output, err = self._execute(command)

        vvol_list = []
        items = output.split('\n')

        for i in range(0, len(items) - 1):
            if ":" not in items[i]:
                vvol_list.append(items[i])

        return vvol_list

    def _get_filesystem_capacity(self):
        command = ['filesystem-limits', self.fs_name]
        output, err = self._execute(command)

        items = output.split('\n')

        for i in range(0, len(items) - 1):
            if 'Current capacity' in items[i]:
                fs_capacity = items[i].split(' ')

                # Gets the index of the file system capacity (EX: 20GiB)
                index = [i for i, string in enumerate(fs_capacity)
                         if 'GiB' in string]

                fs_capacity = fs_capacity[index[0]]
                fs_capacity = fs_capacity.split('GiB')[0]

                return int(fs_capacity)

    @mutils.synchronized("hds_hnas_select_fs", external=True)
    def _locked_selectfs(self, op, path):
        if op == 'create':
            command = ['selectfs', self.fs_name, '\n',
                       'ssc', '127.0.0.1', 'console-context', '--evs',
                       self.evs_id, 'mkdir', '-p', path]
            output, err = self._execute(command)

        if op == 'delete':
            command = ['selectfs', self.fs_name, '\n',
                       'ssc', '127.0.0.1', 'console-context', '--evs',
                       self.evs_id, 'rmdir', path]
            try:
                output, err = self._execute(command)
            except processutils.ProcessExecutionError:
                LOG.debug("Share %(path)s has more snapshots.", {'path': path})


class FileSystem(object):
    def __init__(self, data):
        if data:
            items = data.split()
            if len(items) >= 7:
                self.name = items[0]
                self.dev = items[1]
                self.on_span = items[2]
                self.state = items[3]
                self.evs = int(items[4])
                self.capacity = int(items[5])
                self.confined = int(items[6])
                if len(items) == 8:
                    self.flag = items[7]
                else:
                    self.flag = ''


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
