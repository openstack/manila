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

import time

import ddt
import mock
from oslo_concurrency import processutils as putils
from oslo_config import cfg
import paramiko
import six

from manila import exception
from manila.share.drivers.hitachi import ssh
from manila import test
from manila import utils as mutils


CONF = cfg.CONF

HNAS_RESULT_empty = ""

HNAS_RESULT_limits = """
Filesystem Ensure on span fake_fs:

Current capacity                             50GiB

Thin provision:                           disabled

Filesystem is confined to:                  100GiB
    (Run 'filesystem-confine')
Free space on span allows expansion to:     143GiB
    (Run 'span-expand')
Chunk size allows growth to:               1069GiB
    (This is a conservative estimate)
Largest filesystem that can be checked:  262144GiB
    (This is a hard limit)
This server model allows growth to:      262144GiB
    (Upgrade the server) """

HNAS_RESULT_expdel = """Deleting the export '/dir1' on fs 'fake_fs'...
NFS Export Delete: Export successfully deleted"""

HNAS_RESULT_vvoldel = """
Warning: Clearing dangling space trackers from empty vivol"""

HNAS_RESULT_selectfs = "Current selected file system: fake_fs, number(1)"

HNAS_RESULT_fs = """ \
Instance name      Dev   On span            State   EVS  Cap/GiB Confined Flag
-----------------  ----  -------            ------  ---  ------- -------- ----
Filesystem 8e6e2c85-fake-long-filesystem-b9b4-e4b09993841e:
8e6e2c8..9993841e  1057  fake_span           Mount   2        4        3
fake_fs            1051  fake_span           NoEVS   -      100     1024
file_system        1055  fake_span           Mount   2        4        5    1
"""

HNAS_RESULT_u_fs = """ \
Instance name      Dev   On span            State   EVS  Cap/GiB Confined Flag
-----------------  ----  -------            ------  ---  ------- -------- ----
file_system        1055  fake_span          Umount   2        4      5
file_system2       1050  fake_span2         NoEVS    -      10       0     1
fake_fs            1051  fake_span          Umount   2      100     1024   """

HNAS_RESULT_one_fs = """ \
Instance name      Dev   On span            State   EVS  Cap/GiB Confined Flag
-----------------  ----  -------            ------  ---  ------- -------- ----
fake_fs            1051  fake_span          Mount   2      100    1024  1"""

HNAS_RESULT_expadd = "NFS Export Add: Export added successfully"

HNAS_RESULT_vvol = """vvol_test
  email        :
  root         : /vvol_test
  tag          : 39
  usage  bytes : 0 B  files: 1
  last modified: 2015-06-23 22:36:12.830698800+00:00"""

HNAS_RESULT_vvol_error = "The virtual volume does not exist."

HNAS_RESULT_mount = """ \
Request to mount file system fake_fs submitted successfully.
File system fake_fs successfully mounted."""

HNAS_RESULT_quota = """Type            : Explicit
Target          : ViVol: vvol_test
Usage           : 1 GB
  Limit         : 5 GB (Hard)
  Warning       : Unset
  Critical      : Unset
  Reset         : 5% (51.2 MB)
File Count      : 1
  Limit         : Unset
  Warning       : Unset
  Critical      : Unset
  Reset         : 5% (0)
Generate Events : Disabled
Global id       : 28a3c9f8-ae05-11d0-9025-836896aada5d
Last modified   : 2015-06-23 22:37:17.363660800+00:00 """

HNAS_RESULT_quota_tb = """Type            : Explicit
Target          : ViVol: vvol_test
Usage           : 1 TB
  Limit         : 1 TB (Hard)
  Warning       : Unset
  Critical      : Unset
  Reset         : 5% (51.2 MB)
File Count      : 1
  Limit         : Unset
  Warning       : Unset
  Critical      : Unset
  Reset         : 5% (0)
Generate Events : Disabled
Global id       : 28a3c9f8-ae05-11d0-9025-836896aada5d
Last modified   : 2015-06-23 22:37:17.363660800+00:00  """

HNAS_RESULT_quota_mb = """Type            : Explicit
Target          : ViVol: vvol_test
Usage           : 20 MB
  Limit         : 500 MB (Hard)
  Warning       : Unset
  Critical      : Unset
  Reset         : 5% (51.2 MB)
File Count      : 1
  Limit         : Unset
  Warning       : Unset
  Critical      : Unset
  Reset         : 5% (0)
Generate Events : Disabled
Global id       : 28a3c9f8-ae05-11d0-9025-836896aada5d
Last modified   : 2015-06-23 22:37:17.363660800+00:00  """

HNAS_RESULT_quota_unset = """Type            : Explicit
Target          : ViVol: vvol_test
Usage           : 0 B
  Limit         : Unset
  Warning       : Unset
  Critical      : Unset
  Reset         : 5% (51.2 MB)
File Count      : 1
  Limit         : Unset
  Warning       : Unset
  Critical      : Unset
  Reset         : 5% (0)
Generate Events : Disabled
Global id       : 28a3c9f8-ae05-11d0-9025-836896aada5d
Last modified   : 2015-06-23 22:37:17.363660800+00:00  """

HNAS_RESULT_quota_err = """No quotas matching specified filter criteria.
"""

HNAS_RESULT_export = """Export name: vvol_test
            Export path: /vvol_test
      File system label: file_system
       File system size: 3.969 GB
 File system free space: 1.848 GB
      File system state:
               formatted = Yes
                 mounted = Yes
                  failed = No
        thin provisioned = No
       Access snapshots: No
      Display snapshots: No
           Read Caching: Disabled
Disaster recovery setting:
                Recovered = No
         Transfer setting = Use file system default \n
   Export configuration:\n
127.0.0.2
"""

HNAS_RESULT_wrong_export = """Export name: wrong_name
            Export path: /vvol_test
      File system label: file_system
       File system size: 3.969 GB
 File system free space: 1.848 GB
      File system state:
               formatted = Yes
                 mounted = Yes
                  failed = No
        thin provisioned = No
       Access snapshots: No
      Display snapshots: No
           Read Caching: Disabled
Disaster recovery setting:
                Recovered = No
         Transfer setting = Use file system default
   Export configuration:
127.0.0.1"""

HNAS_RESULT_exp_no_fs = """
            Export name: no_fs
            Export path: /export_without_fs
       File system info: *** not available ***
       Access snapshots: Yes
      Display snapshots: Yes
           Read Caching: Disabled
Disaster recovery setting:
                Recovered = No
         Transfer setting = Use file system default
   Export configuration:
   """

HNAS_RESULT_export_ip = """
            Export name: vvol_test
            Export path: /vvol_test
      File system label: fake_fs
       File system size: 3.969 GB
 File system free space: 1.848 GB
      File system state:
               formatted = Yes
                 mounted = Yes
                  failed = No
        thin provisioned = No
       Access snapshots: No
      Display snapshots: No
           Read Caching: Disabled
Disaster recovery setting:
                Recovered = No
         Transfer setting = Use file system default
   Export configuration:
127.0.0.1(rw)
"""

HNAS_RESULT_export_ip2 = """
            Export name: vvol_test
            Export path: /vvol_test
      File system label: fake_fs
       File system size: 3.969 GB
 File system free space: 1.848 GB
      File system state:
               formatted = Yes
                 mounted = Yes
                  failed = No
        thin provisioned = No
       Access snapshots: No
      Display snapshots: No
           Read Caching: Disabled
Disaster recovery setting:
                Recovered = No
         Transfer setting = Use file system default
   Export configuration:
127.0.0.1(ro)
"""

HNAS_RESULT_expmod = """Modifying the export '/fake_export' on fs 'fake_fs'...
NFS Export Modify: changing configuration options to: 127.0.0.2 NFS
Export Modify: Export modified successfully"""

HNAS_RESULT_expnotmod = "Export not modified."

HNAS_RESULT_fslimits = """
Filesystem fake_fs on span fake_span:

Current capacity                            100GiB

Thin provision:                           disabled

Free space on span allows expansion to:  10GiB    (Run 'span-expand')
Filesystem is confined to:               1024GiB  (Run 'filesystem-confine')
Chunk size allows growth to:             1024GiB  (This is a conservative \
 estimate)
Largest filesystem that can be checked:  10000GiB (This is a hard limit)
This server model allows growth to:      10000GiB (Upgrade the server)
"""

HNAS_RESULT_fslimits_tb = """ \
Filesystem fake_fs on span fake_span:

Current capacity                            1500GiB

Thin provision:                           disabled

Free space on span allows expansion to:   1000GiB   (Run 'span-expand')
Filesystem is confined to:               10240GiB   (Run 'filesystem-confine')
Chunk size allows growth to:             10240GiB   (This is a conservative \
estimate)
Largest filesystem that can be checked:  10000GiB   (This is a hard limit)
This server model allows growth to:      10000GiB   (Upgrade the server)
"""

HNAS_RESULT_job = """tree-operation-job-submit: Request submitted successfully.
tree-operation-job-submit: Job id = d933100a-b5f6-11d0-91d9-836896aada5d"""

HNAS_RESULT_vvol_list = """vol1
  email        :
  root         : /shares/vol1
  tag          : 10
  usage  bytes : 0 B  files: 1
  last modified: 2015-07-27 22:25:02.746426000+00:00
vol2
  email        :
  root         : /shares/vol2
  tag          : 13
  usage  bytes : 0 B  files: 1
  last modified: 2015-07-28 01:30:21.125671700+00:00
vol3
  email        :
  root         : /shares/vol3
  tag          : 14
  usage  bytes : 5 GB (5368709120 B)  files: 2
  last modified: 2015-07-28 20:23:05.672404600+00:00"""

HNAS_RESULT_tree_job_status_fail = """JOB ID : d933100a-b5f6-11d0-91d9-836896aada5d
      Job request
        Physical node                  : 1
        EVS                            : 1
        Volume number                  : 1
        File system id                 : 2ea361c20ed0f80d0000000000000000
        File system name               : fs1
        Source path                    : "/foo"
        Creation time                  : 2013-09-05 23:16:48-07:00
        Destination path               : "/clone/bar"
        Ensure destination path exists : true

      Job state                        : Job failed
      Job info
        Started                        : 2013-09-05 23:16:48-07:00
        Ended                          : 2013-09-05 23:17:02-07:00
        Status                         : Success
        Error details                  :
        Directories processed          : 220
        Files processed                : 910
        Data bytes processed           : 34.5 MB (36174754 B)
        Source directories missing     : 0
        Source files missing           : 0
        Source files skipped           : 801
        Skipping details               : 104 symlinks, 452 hard links,
47 block special devices, 25 character devices"""

HNAS_RESULT_job = """tree-operation-job-submit: Request submitted successfully.
tree-operation-job-submit: Job id = d933100a-b5f6-11d0-91d9-836896aada5d """

HNAS_RESULT_job_completed = """JOB ID : ab4211b8-aac8-11ce-91af-39e0822ea368
      Job request
        Physical node                  : 1
        EVS                            : 1
        Volume number                  : 1
        File system id                 : 2ea361c20ed0f80d0000000000000000
        File system name               : fs1
        Source path                    : "/foo"
        Creation time                  : 2013-09-05 23:16:48-07:00
        Destination path               : "/clone/bar"
        Ensure destination path exists : true

      Job state                        : Job was completed
      Job info
        Started                        : 2013-09-05 23:16:48-07:00
        Ended                          : 2013-09-05 23:17:02-07:00
        Status                         : Success
        Error details                  :
        Directories processed          : 220
        Files processed                : 910
        Data bytes processed           : 34.5 MB (36174754 B)
        Source directories missing     : 0
        Source files missing           : 0
        Source files skipped           : 801
        Skipping details               : 104 symlinks, 452 hard links, 47 \
block special devices, 25 character devices
"""

HNAS_RESULT_job_running = """JOB ID : ab4211b8-aac8-11ce-91af-39e0822ea368
      Job request
        Physical node                  : 1
        EVS                            : 1
        Volume number                  : 1
        File system id                 : 2ea361c20ed0f80d0000000000000000
        File system name               : fs1
        Source path                    : "/foo"
        Creation time                  : 2013-09-05 23:16:48-07:00
        Destination path               : "/clone/bar"
        Ensure destination path exists : true

      Job state                        : Job is running
      Job info
        Started                        : 2013-09-05 23:16:48-07:00
        Ended                          : 2013-09-05 23:17:02-07:00
        Status                         : Success
        Error details                  :
        Directories processed          : 220
        Files processed                : 910
        Data bytes processed           : 34.5 MB (36174754 B)
        Source directories missing     : 0
        Source files missing           : 0
        Source files skipped           : 801
        Skipping details               : 104 symlinks, 452 hard links, 47 \
block special devices, 25 character devices
"""

HNAS_RESULT_df = """
  ID          Label  EVS      Size            Used  Snapshots  Deduped  \
          Avail  Thin  ThinSize  ThinAvail              FS Type
----  -------------  ---  --------  --------------  ---------  -------  \
-------------  ----  --------  ---------  -------------------
1051  FS-ManilaDev1    3  70.00 GB  10.00 GB (75%)   0 B (0%)       NA  \
18.3 GB (25%)    No                       4 KB,WFS-2,128 DSBs
"""

HNAS_RESULT_df_tb = """
  ID          Label  EVS      Size            Used  Snapshots  Deduped  \
          Avail  Thin  ThinSize  ThinAvail              FS Type
----  -------------  ---  --------  --------------  ---------  -------  \
-------------  ----  --------  ---------  -------------------
1051  FS-ManilaDev1    3.00  7.00 TB  2 TB (75%)   0 B (0%)       NA  \
18.3 GB (25%)    No                       4 KB,WFS-2,128 DSBs
"""

HNAS_RESULT_mounted_filesystem = """
file_system        1055  fake_span           Mount   2        4        5    1
"""

HNAS_RESULT_unmounted_filesystem = """
file_system        1055  fake_span          Umount   2        4        5    1
"""


@ddt.ddt
class HNASSSHTestCase(test.TestCase):
    def setUp(self):
        super(HNASSSHTestCase, self).setUp()

        self.ip = '192.168.1.1'
        self.port = 22
        self.user = 'hnas_user'
        self.password = 'hnas_password'
        self.default_commands = ['ssc', '127.0.0.1']
        self.fs_name = 'file_system'
        self.evs_ip = '172.24.44.1'
        self.evs_id = 2
        self.ssh_private_key = 'private_key'
        self.cluster_admin_ip0 = 'fake'
        self.job_timeout = 30

        self.mock_log = self.mock_object(ssh, 'LOG')

        self._driver_ssh = ssh.HNASSSHBackend(self.ip, self.user,
                                              self.password,
                                              self.ssh_private_key,
                                              self.cluster_admin_ip0,
                                              self.evs_id, self.evs_ip,
                                              self.fs_name, self.job_timeout)

        self.vvol = {
            'id': 'vvol_test',
            'share_proto': 'nfs',
            'size': 4,
            'host': '127.0.0.1',
        }

        self.snapshot = {
            'id': 'snapshot_test',
            'share_proto': 'nfs',
            'size': 4,
            'share_id': 'vvol_test',
            'host': 'ubuntu@hds2#HDS2',
        }

    def test_get_stats(self):
        fake_list_command = ['df', '-a', '-f', 'file_system']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(return_value=(HNAS_RESULT_df_tb, "")))

        total, free = self._driver_ssh.get_stats()

        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)
        self.assertEqual(7168.0, total)
        self.assertEqual(5120.0, free)

    def test_nfs_export_add(self):
        fake_nfs_command = ['nfs-export', 'add', '-S', 'disable', '-c',
                            '127.0.0.1', '/shares/vvol_test', self.fs_name,
                            '/shares/vvol_test']
        self.mock_object(ssh.HNASSSHBackend, '_execute', mock.Mock())

        self._driver_ssh.nfs_export_add('vvol_test')

        self._driver_ssh._execute.assert_called_with(fake_nfs_command)

    def test_nfs_export_del(self):
        fake_nfs_command = ['nfs-export', 'del', '/shares/vvol_test']
        self.mock_object(ssh.HNASSSHBackend, '_execute', mock.Mock())

        self._driver_ssh.nfs_export_del('vvol_test')

        self._driver_ssh._execute.assert_called_with(fake_nfs_command)

    def test_nfs_export_del_inexistent_export(self):
        self.mock_object(ssh.HNASSSHBackend, '_execute', mock.Mock(
            side_effect=[putils.ProcessExecutionError(
                stderr='does not exist')]))

        self._driver_ssh.nfs_export_del('vvol_test')

        self.assertTrue(self.mock_log.warning.called)

    def test_nfs_export_del_error(self):
        self.mock_object(ssh.HNASSSHBackend, '_execute', mock.Mock(
            side_effect=[putils.ProcessExecutionError(stderr='')]))

        self.assertRaises(exception.HNASBackendException,
                          self._driver_ssh.nfs_export_del, 'vvol_test')
        self.assertTrue(self.mock_log.exception.called)

    def test_get_host_list(self):
        self.mock_object(ssh.HNASSSHBackend, "_get_share_export", mock.Mock(
            return_value=[ssh.Export(HNAS_RESULT_export)]))

        host_list = self._driver_ssh.get_host_list('fake_id')

        self.assertEqual(['127.0.0.2'], host_list)

    def test_update_access_rule_empty_host_list(self):
        fake_export_command = ['nfs-export', 'mod', '-c', '127.0.0.1',
                               '/shares/fake_id']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock())

        self._driver_ssh.update_access_rule("fake_id", [])

        self._driver_ssh._execute.assert_called_with(fake_export_command)

    def test_update_access_rule(self):
        fake_export_command = ['nfs-export', 'mod', '-c',
                               u'"127.0.0.1,127.0.0.2"', '/shares/fake_id']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock())

        self._driver_ssh.update_access_rule("fake_id", ['127.0.0.1',
                                                        '127.0.0.2'])

        self._driver_ssh._execute.assert_called_with(fake_export_command)

    def test_tree_clone_nothing_to_clone(self):
        fake_tree_clone_command = ['tree-clone-job-submit', '-e', '-f',
                                   self.fs_name, '/src', '/dst']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            side_effect=[putils.ProcessExecutionError(
                stderr='Cannot find any clonable files in the source directory'
            )]))

        self.assertRaises(exception.HNASNothingToCloneException,
                          self._driver_ssh.tree_clone, "/src", "/dst")
        self._driver_ssh._execute.assert_called_with(fake_tree_clone_command)

    def test_tree_clone_error_cloning(self):
        fake_tree_clone_command = ['tree-clone-job-submit', '-e', '-f',
                                   self.fs_name, '/src', '/dst']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            side_effect=[putils.ProcessExecutionError(stderr='')]))

        self.assertRaises(exception.HNASBackendException,
                          self._driver_ssh.tree_clone, "/src", "/dst")
        self._driver_ssh._execute.assert_called_with(fake_tree_clone_command)
        self.assertTrue(self.mock_log.exception.called)

    def test_tree_clone(self):
        fake_tree_clone_command = ['tree-clone-job-submit', '-e', '-f',
                                   self.fs_name, '/src', '/dst']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            side_effect=[(HNAS_RESULT_job, ''),
                         (HNAS_RESULT_job_completed, '')]))

        self._driver_ssh.tree_clone("/src", "/dst")

        self._driver_ssh._execute.assert_any_call(fake_tree_clone_command)
        self.assertTrue(self.mock_log.debug.called)

    def test_tree_clone_job_failed(self):
        fake_tree_clone_command = ['tree-clone-job-submit', '-e', '-f',
                                   self.fs_name, '/src', '/dst']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            side_effect=[(HNAS_RESULT_job, ''),
                         (HNAS_RESULT_tree_job_status_fail, '')]))

        self.assertRaises(exception.HNASBackendException,
                          self._driver_ssh.tree_clone, "/src", "/dst")
        self._driver_ssh._execute.assert_any_call(fake_tree_clone_command)
        self.assertTrue(self.mock_log.error.called)

    def test_tree_clone_job_timeout(self):
        fake_tree_clone_command = ['tree-clone-job-submit', '-e', '-f',
                                   self.fs_name, '/src', '/dst']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            side_effect=[(HNAS_RESULT_job, ''),
                         (HNAS_RESULT_job_running, ''),
                         (HNAS_RESULT_job_running, ''),
                         (HNAS_RESULT_job_running, ''),
                         (HNAS_RESULT_empty, '')]))
        self.mock_object(time, "time", mock.Mock(side_effect=[0, 0, 200, 200]))
        self.mock_object(time, "sleep", mock.Mock())

        self.assertRaises(exception.HNASBackendException,
                          self._driver_ssh.tree_clone, "/src", "/dst")
        self._driver_ssh._execute.assert_any_call(fake_tree_clone_command)
        self.assertTrue(self.mock_log.error.called)

    def test_tree_delete_path_does_not_exist(self):
        fake_tree_delete_command = ['tree-delete-job-submit', '--confirm',
                                    '-f', self.fs_name, '/path']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            side_effect=[putils.ProcessExecutionError(
                stderr='Source path: Cannot access')]
        ))

        self._driver_ssh.tree_delete("/path")

        self.assertTrue(self.mock_log.warning.called)
        self._driver_ssh._execute.assert_called_with(fake_tree_delete_command)

    def test_tree_delete_error(self):
        fake_tree_delete_command = ['tree-delete-job-submit', '--confirm',
                                    '-f', self.fs_name, '/path']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            side_effect=[putils.ProcessExecutionError(
                stderr='')]
        ))

        self.assertRaises(putils.ProcessExecutionError,
                          self._driver_ssh.tree_delete, "/path")
        self.assertTrue(self.mock_log.exception.called)
        self._driver_ssh._execute.assert_called_with(fake_tree_delete_command)

    def test_create_directory(self):
        locked_selectfs_args = ['create', '/path']
        self.mock_object(ssh.HNASSSHBackend, "_locked_selectfs", mock.Mock())

        self._driver_ssh.create_directory("/path")

        self._driver_ssh._locked_selectfs.assert_called_with(
            *locked_selectfs_args)

    def test_delete_directory(self):
        locked_selectfs_args = ['delete', '/path']
        self.mock_object(ssh.HNASSSHBackend, "_locked_selectfs", mock.Mock())

        self._driver_ssh.delete_directory("/path")

        self._driver_ssh._locked_selectfs.assert_called_with(
            *locked_selectfs_args)

    def test_check_fs_mounted_true(self):
        self.mock_object(ssh.HNASSSHBackend, "_get_filesystem_list",
                         mock.Mock(return_value=[ssh.FileSystem(
                             HNAS_RESULT_mounted_filesystem)]))

        self.assertTrue(self._driver_ssh.check_fs_mounted())

    def test_check_fs_mounted_false(self):
        self.mock_object(ssh.HNASSSHBackend, "_get_filesystem_list",
                         mock.Mock(return_value=[ssh.FileSystem(
                             HNAS_RESULT_unmounted_filesystem)]))

        self.assertFalse(self._driver_ssh.check_fs_mounted())

    def test_check_fs_mounted_eror(self):
        self.mock_object(ssh.HNASSSHBackend, "_get_filesystem_list",
                         mock.Mock(return_value=[]))

        self.assertRaises(exception.HNASItemNotFoundException,
                          self._driver_ssh.check_fs_mounted)

    def test_mount_already_mounted(self):
        fake_mount_command = ['mount', self.fs_name]
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            side_effect=putils.ProcessExecutionError(stderr='')))

        self.assertRaises(putils.ProcessExecutionError, self._driver_ssh.mount)
        self._driver_ssh._execute.assert_called_with(fake_mount_command)

    def test_vvol_create(self):
        fake_vvol_create_command = ['virtual-volume', 'add', '--ensure',
                                    self.fs_name, 'vvol', '/shares/vvol']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock())

        self._driver_ssh.vvol_create("vvol")

        self._driver_ssh._execute.assert_called_with(fake_vvol_create_command)

    def test_vvol_delete_vvol_does_not_exist(self):
        fake_vvol_delete_command = ['tree-delete-job-submit', '--confirm',
                                    '-f', self.fs_name, '/shares/vvol']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            side_effect=[putils.ProcessExecutionError(
                stderr='Source path: Cannot access')]
        ))

        self._driver_ssh.vvol_delete("vvol")

        self.assertTrue(self.mock_log.debug.called)
        self._driver_ssh._execute.assert_called_with(fake_vvol_delete_command)

    def test_vvol_delete_error(self):
        fake_vvol_delete_command = ['tree-delete-job-submit', '--confirm',
                                    '-f', self.fs_name, '/shares/vvol']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            side_effect=[putils.ProcessExecutionError(
                stderr='')]
        ))

        self.assertRaises(putils.ProcessExecutionError,
                          self._driver_ssh.vvol_delete, "vvol")
        self.assertTrue(self.mock_log.exception.called)
        self._driver_ssh._execute.assert_called_with(fake_vvol_delete_command)

    def test_quota_add(self):
        fake_add_quota_command = ['quota', 'add', '--usage-limit', '1G',
                                  '--usage-hard-limit', 'yes',
                                  self.fs_name, 'vvol']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock())

        self._driver_ssh.quota_add('vvol', 1)

        self._driver_ssh._execute.assert_called_with(fake_add_quota_command)

    def test_modify_quota(self):
        fake_modify_quota_command = ['quota', 'mod', '--usage-limit', '1G',
                                     self.fs_name, 'vvol']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock())

        self._driver_ssh.modify_quota('vvol', 1)

        self._driver_ssh._execute.assert_called_with(fake_modify_quota_command)

    def test_check_vvol(self):
        fake_check_vvol_command = ['virtual-volume', 'list', '--verbose',
                                   self.fs_name, 'vvol']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            side_effect=putils.ProcessExecutionError(stderr='')))

        self.assertRaises(exception.HNASItemNotFoundException,
                          self._driver_ssh.check_vvol, 'vvol')
        self._driver_ssh._execute.assert_called_with(fake_check_vvol_command)

    def test_check_quota(self):
        fake_check_quota_command = ['quota', 'list', '--verbose',
                                    self.fs_name, 'vvol']
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            return_value=('No quotas matching specified filter criteria', '')))

        self.assertRaises(exception.HNASItemNotFoundException,
                          self._driver_ssh.check_quota, 'vvol')
        self._driver_ssh._execute.assert_called_with(fake_check_quota_command)

    def test_check_export(self):
        self.mock_object(ssh.HNASSSHBackend, "_get_share_export", mock.Mock(
            return_value=[ssh.Export(HNAS_RESULT_export)]))

        self._driver_ssh.check_export("vvol_test")

    def test_check_export_error(self):
        self.mock_object(ssh.HNASSSHBackend, "_get_share_export", mock.Mock(
            return_value=[ssh.Export(HNAS_RESULT_wrong_export)]))

        self.assertRaises(exception.HNASItemNotFoundException,
                          self._driver_ssh.check_export, "vvol_test")

    def test_get_share_quota(self):
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            return_value=(HNAS_RESULT_quota, '')))

        result = self._driver_ssh.get_share_quota("vvol_test")

        self.assertEqual(5, result)

    @ddt.data(HNAS_RESULT_quota_unset, HNAS_RESULT_quota_err)
    def test_get_share_quota_errors(self, hnas_output):
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            return_value=(hnas_output, '')))

        result = self._driver_ssh.get_share_quota("vvol_test")

        self.assertIsNone(result)

    def test_get_share_quota_tb(self):
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            return_value=(HNAS_RESULT_quota_tb, '')))

        result = self._driver_ssh.get_share_quota("vvol_test")

        self.assertEqual(1024, result)

    def test_get_share_quota_mb(self):
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            return_value=(HNAS_RESULT_quota_mb, '')))

        self.assertRaises(exception.HNASBackendException,
                          self._driver_ssh.get_share_quota, "vvol_test")

    def test_get_share_usage(self):
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            return_value=(HNAS_RESULT_quota, '')))

        self.assertEqual(1, self._driver_ssh.get_share_usage("vvol_test"))

    def test_get_share_usage_error(self):
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            return_value=(HNAS_RESULT_quota_err, '')))

        self.assertRaises(exception.HNASItemNotFoundException,
                          self._driver_ssh.get_share_usage, "vvol_test")

    def test_get_share_usage_mb(self):
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            return_value=(HNAS_RESULT_quota_mb, '')))

        self.assertEqual(0.01953125, self._driver_ssh.get_share_usage(
            "vvol_test"))

    def test_get_share_usage_tb(self):
        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            return_value=(HNAS_RESULT_quota_tb, '')))

        self.assertEqual(1024, self._driver_ssh.get_share_usage("vvol_test"))

    def test__get_share_export(self):
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(return_value=[HNAS_RESULT_export_ip, '']))

        export_list = self._driver_ssh._get_share_export('fake_id')

        self.assertEqual('vvol_test', export_list[0].export_name)
        self.assertEqual('/vvol_test', export_list[0].export_path)
        self.assertEqual('fake_fs', export_list[0].file_system_label)
        self.assertEqual('Yes', export_list[0].mounted)

    def test__get_share_export_exception_not_found(self):

        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            side_effect=putils.ProcessExecutionError(
                stderr="NFS Export List: Export 'id' does not exist.")
        ))

        self.assertRaises(exception.HNASItemNotFoundException,
                          self._driver_ssh._get_share_export, 'fake_id')

    def test__get_share_export_exception_error(self):

        self.mock_object(ssh.HNASSSHBackend, "_execute", mock.Mock(
            side_effect=putils.ProcessExecutionError(stderr="Some error.")
        ))

        self.assertRaises(putils.ProcessExecutionError,
                          self._driver_ssh._get_share_export, 'fake_id')

    def test__get_filesystem_list(self):
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(return_value=[HNAS_RESULT_fs, '']))

        out = self._driver_ssh._get_filesystem_list()

        self.assertEqual('8e6e2c85-fake-long-filesystem-b9b4-e4b09993841e',
                         out[0].name)
        self.assertEqual('fake_span', out[0].on_span)
        self.assertEqual('Mount', out[0].state)
        self.assertEqual(2, out[0].evs)
        self.assertTrue(self.mock_log.debug.called)

    def test__execute(self):
        key = self.ssh_private_key
        commands = ['tree-clone-job-submit', '-e', '/src', '/dst']
        concat_command = ('ssc --smuauth fake console-context --evs 2 '
                          'tree-clone-job-submit -e /src /dst')
        self.mock_object(paramiko.SSHClient, 'connect')
        self.mock_object(putils, 'ssh_execute',
                         mock.Mock(return_value=[HNAS_RESULT_job, '']))

        output, err = self._driver_ssh._execute(commands)

        putils.ssh_execute.assert_called_once_with(mock.ANY, concat_command,
                                                   check_exit_code=True)
        paramiko.SSHClient.connect.assert_called_with(self.ip,
                                                      username=self.user,
                                                      key_filename=key,
                                                      look_for_keys=False,
                                                      timeout=None,
                                                      password=self.password,
                                                      port=self.port)
        self.assertIn('Request submitted successfully.', output)

    def test__execute_ssh_exception(self):
        commands = ['tree-clone-job-submit', '-e', '/src', '/dst']
        concat_command = ('ssc --smuauth fake console-context --evs 2 '
                          'tree-clone-job-submit -e /src /dst')
        msg = 'Failed to establish SSC connection'

        self.mock_object(time, "sleep", mock.Mock())
        self.mock_object(paramiko.SSHClient, 'connect')
        self.mock_object(putils, 'ssh_execute',
                         mock.Mock(side_effect=[
                             putils.ProcessExecutionError(stderr=msg),
                             putils.ProcessExecutionError(stderr='Invalid!')]))
        self.mock_object(mutils.SSHPool, "item",
                         mock.Mock(return_value=paramiko.SSHClient()))
        self.mock_object(paramiko.SSHClient, "set_missing_host_key_policy")

        self.assertRaises(putils.ProcessExecutionError,
                          self._driver_ssh._execute, commands)

        putils.ssh_execute.assert_called_with(mock.ANY, concat_command,
                                              check_exit_code=True)

        self.assertTrue(self.mock_log.debug.called)
        self.assertTrue(self.mock_log.error.called)

    def test__locked_selectfs_create_operation(self):
        exec_command = ['selectfs', self.fs_name, '\n', 'ssc', '127.0.0.1',
                        'console-context', '--evs', six.text_type(self.evs_id),
                        'mkdir', '-p', '/path']
        self.mock_object(ssh.HNASSSHBackend, '_execute', mock.Mock())

        self._driver_ssh._locked_selectfs('create', '/path')

        self._driver_ssh._execute.assert_called_with(exec_command)

    def test__locked_selectfs_delete_operation_successfull(self):
        exec_command = ['selectfs', self.fs_name, '\n', 'ssc', '127.0.0.1',
                        'console-context', '--evs', six.text_type(self.evs_id),
                        'rmdir', '/path']
        self.mock_object(ssh.HNASSSHBackend, '_execute', mock.Mock())

        self._driver_ssh._locked_selectfs('delete', '/path')

        self._driver_ssh._execute.assert_called_with(exec_command)

    def test__locked_selectfs_deleting_not_empty_directory(self):
        msg = 'This path has more snapshot. Currenty DirectoryNotEmpty'

        self.mock_object(ssh.HNASSSHBackend, '_execute', mock.Mock(
            side_effect=[putils.ProcessExecutionError(stderr=msg)]))

        self._driver_ssh._locked_selectfs('delete', '/path')

        self.assertTrue(self.mock_log.debug.called)

    def test__locked_selectfs_delete_exception(self):
        msg = 'rmdir: cannot remove \'/path\''

        self.mock_object(ssh.HNASSSHBackend, '_execute', mock.Mock(
            side_effect=[putils.ProcessExecutionError(stderr=msg)]))

        self.assertRaises(putils.ProcessExecutionError,
                          self._driver_ssh._locked_selectfs, 'delete', 'path')
        self.assertTrue(self.mock_log.exception.called)
