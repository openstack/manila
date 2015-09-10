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

import mock
from oslo_concurrency import processutils as putils
from oslo_config import cfg
import paramiko

from manila import exception
from manila.share.drivers.hitachi import ssh
from manila import test

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
file_system        1055  fake_span           Mount   2        4        5    1
fake_fs            1051  fake_span           Mount   2      100     1024   """

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
Usage           : 0 B
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
Usage           : 0 B
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

HNAS_RESULT_export = """
Export name: vvol_test
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

HNAS_RESULT_wrong_export = """
Export name: wrong_name
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

HNAS_RESULT_tree_job_status_fail = """
tree-clone-job-status: Job id = d933100a-b5f6-11d0-91d9-836896aada5d
   JOB ID : d933100a-b5f6-11d0-91d9-836896aada5d
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

HNAS_RESULT_job_completed = """
   tree-clone-job-status: Job id = ab4211b8-aac8-11ce-91af-39e0822ea368
   JOB ID : ab4211b8-aac8-11ce-91af-39e0822ea368
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

HNAS_RESULT_job_running = """
   tree-clone-job-status: Job id = ab4211b8-aac8-11ce-91af-39e0822ea368
   JOB ID : ab4211b8-aac8-11ce-91af-39e0822ea368
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

        self._driver = ssh.HNASSSHBackend(self.ip, self.user, self.password,
                                          self.ssh_private_key,
                                          self.cluster_admin_ip0, self.evs_id,
                                          self.evs_ip, self.fs_name,
                                          self.job_timeout)

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
        expected_debug_calls = [
            ('Total space in file system: %(total)s GB.', {'total': 7168.0}),
            ('Used space in the file system: %(used)s GB.', {'used': 2048.0}),
            ('Available space in the file system: %(space)s GB.',
             {'space': 5120.0})
        ]

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(return_value=(HNAS_RESULT_df_tb, "")))

        total, free = self._driver.get_stats()

        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)
        self.mock_log.debug.assert_has_calls([mock.call(*a) for a in
                                              expected_debug_calls])
        self.assertEqual(7168.0, total)
        self.assertEqual(5120.0, free)

    def test_get_stats_terabytes(self):
        fake_list_command = ['df', '-a', '-f', 'file_system']
        expected_debug_calls = [
            ('Total space in file system: %(total)s GB.', {'total': 7168.0}),
            ('Used space in the file system: %(used)s GB.', {'used': 2048.0}),
            ('Available space in the file system: %(space)s GB.',
             {'space': 5120.0})
        ]

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(return_value=(HNAS_RESULT_df_tb, "")))

        total, free = self._driver.get_stats()

        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)
        self.mock_log.debug.assert_has_calls([mock.call(*a) for a in
                                              expected_debug_calls])
        self.assertEqual(7168.0, total)
        self.assertEqual(5120.0, free)

    def test_allow_access(self):
        fake_mod_command = ['nfs-export', 'mod', '-c',
                            '"127.0.0.2,127.0.0.1(rw)"', '/shares/vvol_test']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_export, ""),
                                                (HNAS_RESULT_export, ""),
                                                (HNAS_RESULT_expmod, "")]))

        self._driver.allow_access(self.vvol['id'], self.vvol['host'],
                                  self.vvol['share_proto'])

        # Assert that _execute sent the right mod command
        ssh.HNASSSHBackend._execute.assert_called_with(fake_mod_command)

    def test_allow_access_host_allowed(self):
        fake_mod_command = ['nfs-export', 'list ', '/shares/vvol_test']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_export, ""),
                                                (HNAS_RESULT_export_ip, "")]))

        self._driver.allow_access(self.vvol['id'], self.vvol['host'],
                                  self.vvol['share_proto'])

        self.assertTrue(self.mock_log.debug.called)
        # Assert that _execute sent the right list command
        ssh.HNASSSHBackend._execute.assert_called_with(fake_mod_command)

    def test_allow_access_host_with_other_permission(self):
        fake_mod_command = ['nfs-export', 'mod', '-c', '"127.0.0.1(rw)"',
                            '/shares/vvol_test']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_export, ""),
                                                (HNAS_RESULT_export_ip2, ""),
                                                (HNAS_RESULT_expmod, "")]))

        self._driver.allow_access(self.vvol['id'], self.vvol['host'],
                                  self.vvol['share_proto'])

        # Assert that _execute sent the right mod command
        ssh.HNASSSHBackend._execute.assert_called_with(fake_mod_command)

    def test_allow_access_wrong_permission(self):
        fake_list_command = ['nfs-export', 'list ', '/shares/vvol_test']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_export, ""),
                                                (HNAS_RESULT_export, "")]))

        self.assertRaises(exception.HNASBackendException,
                          self._driver.allow_access, self.vvol['id'],
                          self.vvol['host'], self.vvol['share_proto'],
                          'fake_permission')

        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)

    def test_deny_access(self):
        fake_mod_command = ['nfs-export', 'mod', '-c', '127.0.0.1',
                            '/shares/vvol_test']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_export, ""),
                                                (HNAS_RESULT_export_ip2, ""),
                                                (HNAS_RESULT_expmod, "")]))

        self._driver.deny_access(self.vvol['id'], self.vvol['host'],
                                 self.vvol['share_proto'], 'ro')

        # Assert that _execute sent the right mod command
        ssh.HNASSSHBackend._execute.assert_called_with(fake_mod_command)

    def test_deny_access_host_not_allowed(self):
        fake_list_command = ['nfs-export', 'list ', '/shares/vvol_test']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_export, ""),
                                                (HNAS_RESULT_export, ""),
                                                (HNAS_RESULT_expmod, "")]))

        self._driver.deny_access(self.vvol['id'], self.vvol['host'],
                                 self.vvol['share_proto'], 'rw')

        # Assert that _execute sent the right list command
        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)

    def test_deny_access_export_modified(self):
        fake_mod_command = ['nfs-export', 'mod', '-c', '127.0.0.1',
                            '/shares/vvol_test']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_export, ""),
                                                (HNAS_RESULT_export_ip2, ""),
                                                (HNAS_RESULT_expnotmod, "")]))

        self._driver.deny_access(self.vvol['id'], self.vvol['host'],
                                 self.vvol['share_proto'], 'ro')

        # Assert that _execute sent the right mod command
        ssh.HNASSSHBackend._execute.assert_called_with(fake_mod_command)

    def test_deny_access_wrong_permission(self):
        fake_list_command = ['nfs-export', 'list ', '/shares/vvol_test']
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_export, ""),
                                                (HNAS_RESULT_export, "")]))

        self.assertRaises(exception.HNASBackendException,
                          self._driver.deny_access, self.vvol['id'],
                          self.vvol['host'], self.vvol['share_proto'],
                          'fake_permission')

        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)

    def test_delete_share(self):
        fake_delete_command = ['tree-delete-job-submit', '--confirm', '-f',
                               'file_system', '/shares/vvol_test']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_export, ""),
                                                (HNAS_RESULT_expdel, ""),
                                                (HNAS_RESULT_job, "")]))

        self._driver.delete_share(self.vvol['id'], self.vvol['share_proto'])

        self.assertTrue(self.mock_log.debug.called)
        # Assert that _execute sent the right tree-delete command
        ssh.HNASSSHBackend._execute.assert_called_with(fake_delete_command)

    def test_delete_inexistent_share(self):
        fake_delete_command = ['tree-delete-job-submit', '--confirm', '-f',
                               'file_system', '/shares/vvol_test']
        msg = 'Share does not exists.'
        msg_err = 'Source path: Cannot access'

        self.mock_object(ssh.HNASSSHBackend, 'ensure_share',
                         mock.Mock(side_effect=exception.HNASBackendException
                                   (msg)))
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[exception.HNASBackendException
                                                (msg_err),
                                                putils.ProcessExecutionError
                                                (stderr=msg_err)]))

        self._driver.delete_share(self.vvol['id'], self.vvol['share_proto'])

        self.assertTrue(self.mock_log.warning.called)
        self.assertTrue(self.mock_log.debug.called)
        # Assert that _execute sent the right tree-delete command
        ssh.HNASSSHBackend._execute.assert_called_with(fake_delete_command)

    def test_delete_share_fails(self):
        msg = 'Share does not exists.'
        msg_err = 'Cannot delete share'
        fake_tree_command = ['tree-delete-job-submit', '--confirm', '-f',
                             'file_system', '/shares/vvol_test']

        self.mock_object(ssh.HNASSSHBackend, 'ensure_share',
                         mock.Mock(side_effect=exception.HNASBackendException
                                   (msg)))
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_expdel, ""),
                                                putils.ProcessExecutionError
                                                (stderr=msg_err)]))

        self.assertRaises(putils.ProcessExecutionError,
                          self._driver.delete_share, self.vvol['id'],
                          self.vvol['share_proto'])

        self.assertTrue(self.mock_log.warning.called)
        ssh.HNASSSHBackend._execute.assert_called_with(fake_tree_command)

    def test_ensure_share(self):
        fake_list_command = ['nfs-export', 'list ', '/shares/vvol_test']
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_export, "")]))

        path = self._driver.ensure_share(self.vvol['id'],
                                         self.vvol['share_proto'])

        self.assertEqual('/shares/' + self.vvol['id'], path)
        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)

    def test_ensure_share_umounted_fs(self):
        fake_list_command = ['nfs-export', 'list ', '/shares/vvol_test']
        # Tests when filesystem is unmounted
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_u_fs, ""),
                                                (HNAS_RESULT_mount, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_export, "")]))

        path = self._driver.ensure_share(self.vvol['id'],
                                         self.vvol['share_proto'])

        self.assertTrue(self.mock_log.debug.called)
        self.assertEqual('/shares/' + self.vvol['id'], path)
        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)

    def test_ensure_share_inexistent_vvol(self):
        fake_list_command = ['virtual-volume', 'list', '--verbose',
                             'file_system', 'vvol_test']
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                putils.ProcessExecutionError]))

        # Raise exception when vvol doesnt exist
        self.assertRaises(exception.HNASBackendException,
                          self._driver.ensure_share, self.vvol['id'],
                          self.vvol['share_proto'])
        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)

    def test_ensure_share_quota_unset(self):
        fake_quota_list_command = ['quota', 'list', '--verbose', 'file_system',
                                   'vvol_test']
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota_err, "")
                                                ]))

        self.assertRaises(exception.HNASBackendException,
                          self._driver.ensure_share, self.vvol['id'],
                          self.vvol['share_proto'])
        ssh.HNASSSHBackend._execute.assert_called_with(fake_quota_list_command)

    def test_ensure_share_wrong_export_name(self):
        fake_list_command = ['nfs-export', 'list ', '/shares/vvol_test']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_wrong_export, "")
                                                ]))

        # Raise exception when vvol name != export name
        self.assertRaises(exception.HNASBackendException,
                          self._driver.ensure_share, self.vvol['id'],
                          self.vvol['share_proto'])

        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)

    def test_ensure_share_export_with_no_fs(self):
        fake_list_command = ['nfs-export', 'list ', '/shares/vvol_test']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_exp_no_fs, "")]))

        self.assertRaises(exception.HNASBackendException,
                          self._driver.ensure_share, self.vvol['id'],
                          self.vvol['share_proto'])

        # Assert that _execute sent the right list command
        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)

    def test_create_share(self):
        fake_list_command = ['nfs-export', 'add', '-S', 'disable', '-c',
                             '127.0.0.1', '/shares/vvol_test', 'file_system',
                             '/shares/vvol_test']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_empty, ""),
                                                (HNAS_RESULT_empty, ""),
                                                (HNAS_RESULT_expadd, "")]))

        path = self._driver.create_share(self.vvol['id'],
                                         self.vvol['size'],
                                         self.vvol['share_proto'])

        self.assertEqual('/shares/' + self.vvol['id'], path)
        # Assert that _execute sent the right export add command
        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)
        self.assertTrue(self.mock_log.debug.called)

    def test_create_share_without_fs(self):
        fake_list_command = ['filesystem-list']
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_one_fs, "")]))

        self.assertRaises(exception.HNASBackendException,
                          self._driver.create_share, self.vvol['id'],
                          self.vvol['size'], self.vvol['share_proto'])

        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)

    def test_create_share_fails(self):
        fake_tree_command = ['tree-delete-job-submit', '--confirm', '-f',
                             'file_system', '/shares/vvol_test']
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_empty, ""),
                                                (HNAS_RESULT_empty, ""),
                                                putils.ProcessExecutionError,
                                                (HNAS_RESULT_empty, "")]))

        self.assertRaises(putils.ProcessExecutionError,
                          self._driver.create_share, self.vvol['id'],
                          self.vvol['size'],
                          self.vvol['share_proto'])

        self.assertTrue(self.mock_log.debug.called)
        ssh.HNASSSHBackend._execute.assert_called_with(fake_tree_command)

    def test_create_share_without_size(self):
        fake_add_command = ['nfs-export', 'add', '-S', 'disable', '-c',
                            '127.0.0.1', '/shares/vvol_test', 'file_system',
                            '/shares/vvol_test']
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_empty, ""),
                                                (HNAS_RESULT_empty, ""),
                                                (HNAS_RESULT_expadd, "")]))

        path = self._driver.create_share(self.vvol['id'],
                                         0, self.vvol['share_proto'])

        self.assertEqual('/shares/' + self.vvol['id'], path)
        self.assertTrue(self.mock_log.debug.called)
        ssh.HNASSSHBackend._execute.assert_called_with(fake_add_command)

    def test_extend_share(self):
        fake_quota_mod_command = ['quota', 'mod', '--usage-limit', '4G',
                                  'file_system', 'vvol_test']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_export, ""),
                                                (HNAS_RESULT_df, ""),
                                                (HNAS_RESULT_empty, "")]))

        self._driver.extend_share(self.vvol['id'],
                                  self.vvol['size'],
                                  self.vvol['share_proto'])

        self.assertTrue(self.mock_log.debug.called)
        # Assert that _execute sent the right quota modify command
        ssh.HNASSSHBackend._execute.assert_called_with(fake_quota_mod_command)

    def test_extend_share_no_space(self):
        fake_list_command = ['df', '-a', '-f', 'file_system']
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_export, ""),
                                                (HNAS_RESULT_df, "")]))

        # Tests when try to create a share bigger than available free space
        self.assertRaises(exception.HNASBackendException,
                          self._driver.extend_share, self.vvol['id'],
                          100, self.vvol['share_proto'])

        self.assertTrue(self.mock_log.debug.called)
        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)

    def test_manage_existing(self):
        fake_list_command = ['quota', 'list', 'file_system', 'vvol_test']
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_export, ""),
                                                (HNAS_RESULT_quota_tb, "")]))

        output = self._driver.manage_existing(self.vvol, self.vvol['id'])

        self.assertEqual({'export_locations':
                          ['172.24.44.1:/shares/vvol_test'],
                          'size': 1024.0}, output)
        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)

    def test_manage_existing_share_without_size(self):
        fake_list_command = ['quota', 'list', 'file_system', 'vvol_test']
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_vvol, ""),
                                                (HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_export, ""),
                                                (HNAS_RESULT_quota_err, "")]))

        self.assertRaises(exception.HNASBackendException,
                          self._driver.manage_existing,
                          self.vvol, self.vvol['id'])
        ssh.HNASSSHBackend._execute.assert_called_with(fake_list_command)

    def test_create_snapshot(self):
        fake_create_command = ['tree-clone-job-submit', '-e',
                               '-f', 'file_system', '/shares/vvol_test',
                               '/snapshots/vvol_test/snapshot_test']
        fake_progress_command = ['tree-clone-job-status',
                                 'd933100a-b5f6-11d0-91d9-836896aada5d']

        # Tests when a tree job is successfully submitted
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[
                             (HNAS_RESULT_export, ""),
                             (HNAS_RESULT_empty, ""),
                             (HNAS_RESULT_job, ""),
                             (HNAS_RESULT_job_completed, ""),
                             (HNAS_RESULT_empty, "")]))

        self._driver.create_snapshot(self.vvol['id'],
                                     self.snapshot['id'])

        self.assertTrue(self.mock_log.debug.called)

        # Assert that _execute sent the right tree-clone command
        ssh.HNASSSHBackend._execute.assert_any_call(fake_create_command)
        ssh.HNASSSHBackend._execute.assert_any_call(fake_progress_command)

    def test_create_snapshot_hnas_timeout(self):
        self.mock_object(time, 'time', mock.Mock(side_effect=[1, 1, 200, 300]))
        self.mock_object(time, 'sleep')

        # Tests when a running tree job stalls at HNAS
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[
                             (HNAS_RESULT_export, ""),
                             (HNAS_RESULT_empty, ""),
                             (HNAS_RESULT_job, ""),
                             (HNAS_RESULT_job_running, ""),
                             (HNAS_RESULT_job_running, ""),
                             (HNAS_RESULT_job_running, ""),
                             (HNAS_RESULT_empty, ""),
                             (HNAS_RESULT_empty, "")]))

        self.assertRaises(exception.HNASBackendException,
                          self._driver.create_snapshot,
                          self.vvol['id'], self.snapshot['id'])

    def test_create_snapshot_job_fails(self):
        # Tests when running a tree job fails
        fake_create_command = ['tree-clone-job-status',
                               'd933100a-b5f6-11d0-91d9-836896aada5d']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[
                             (HNAS_RESULT_export, ""),
                             (HNAS_RESULT_empty, ""),
                             (HNAS_RESULT_job, ""),
                             (HNAS_RESULT_tree_job_status_fail, ""),
                             (HNAS_RESULT_empty, "")]))
        mock_log = self.mock_object(ssh, 'LOG')

        self.assertRaises(exception.HNASBackendException,
                          self._driver.create_snapshot, self.vvol['id'],
                          self.snapshot['id'])
        self.assertTrue(mock_log.error.called)

        ssh.HNASSSHBackend._execute.assert_any_call(fake_create_command)

    def test_create_empty_snapshot(self):
        fake_create_command = ['selectfs', 'file_system', '\n', 'ssc',
                               '127.0.0.1', 'console-context',
                               '--evs', '2', 'mkdir', '-p',
                               '/snapshots/vvol_test/snapshot_test']
        # Tests when submit a tree job of an empty directory
        msg = 'Cannot find any clonable files in the source directory'

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[
                             (HNAS_RESULT_export, ""),
                             (HNAS_RESULT_empty, ""),
                             (putils.ProcessExecutionError(stderr=msg)),
                             (HNAS_RESULT_empty, ""),
                             (HNAS_RESULT_empty, "")]))

        self._driver.create_snapshot(self.vvol['id'], self.snapshot['id'])

        self.assertTrue(self.mock_log.warning.called)

        # Assert that _execute sent the right command to select fs and create
        # a directory.
        ssh.HNASSSHBackend._execute.assert_any_call(fake_create_command)

    def test_create_snapshot_submit_fails(self):
        fake_create_command = ['tree-clone-job-submit', '-e', '-f',
                               'file_system', '/shares/vvol_test',
                               '/snapshots/vvol_test/snapshot_test']
        # Tests when submit a tree job fails
        msg = 'Cannot create copy from this directory'

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[
                             (HNAS_RESULT_export, ""),
                             (HNAS_RESULT_empty, ""),
                             putils.ProcessExecutionError(stderr=msg),
                             (HNAS_RESULT_empty, "")]))

        self.assertRaises(exception.HNASBackendException,
                          self._driver.create_snapshot, self.vvol['id'],
                          self.snapshot['id'])

        self.assertTrue(self.mock_log.exception.called)
        ssh.HNASSSHBackend._execute.assert_any_call(fake_create_command)

    def test_delete_snapshot(self):
        fake_delete_command = ['selectfs', 'file_system', '\n', 'ssc',
                               '127.0.0.1', 'console-context', '--evs', '2',
                               'rmdir', '/snapshots/vvol_test']

        # Tests when successfully delete the snapshot
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_job, ""),
                                                putils.ProcessExecutionError]))

        self._driver.delete_snapshot(self.vvol['id'],
                                     self.snapshot['id'])

        self.assertTrue(self.mock_log.debug.called)
        # Assert that _execute sent the right command to select fs and
        # delete the directory.
        ssh.HNASSSHBackend._execute.assert_called_with(fake_delete_command)

    def test_delete_snapshot_last_snapshot(self):
        fake_delete_command = ['selectfs', 'file_system', '\n', 'ssc',
                               '127.0.0.1', 'console-context', '--evs', '2',
                               'rmdir', '/snapshots/vvol_test']

        # Tests when successfully delete the last snapshot (it requires delete
        # the parent directory).
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(return_value=(HNAS_RESULT_job, "")))

        self._driver.delete_snapshot(self.vvol['id'],
                                     self.snapshot['id'])

        # Assert that _execute sent the right command to select fs and
        # delete the directory.
        ssh.HNASSSHBackend._execute.assert_called_with(fake_delete_command)

    def test_delete_snapshot_submit_fails(self):
        msg = 'Cannot delete snapshot.'
        fake_tree_del_command = ['tree-delete-job-submit', '--confirm',
                                 '-f', 'file_system',
                                 '/snapshots/vvol_test/snapshot_test']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=putils.ProcessExecutionError
                                   (stderr=msg)))

        self.assertRaises(putils.ProcessExecutionError,
                          self._driver.delete_snapshot,
                          self.vvol['id'], self.snapshot['id'])

        self.assertTrue(self.mock_log.exception.called)
        ssh.HNASSSHBackend._execute.assert_called_with(fake_tree_del_command)

    def test_create_share_from_snapshot(self):
        fake_export_command = ['nfs-export', 'add', '-S', 'disable', '-c',
                               '127.0.0.1', '/shares/vvol_test', 'file_system',
                               '/shares/vvol_test']
        # Tests when successfully creates a share from snapshot
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_empty, ""),
                                                (HNAS_RESULT_empty, ""),
                                                (HNAS_RESULT_job, ""),
                                                (HNAS_RESULT_export, "")]))

        output = self._driver.create_share_from_snapshot(self.vvol,
                                                         self.snapshot)

        self.assertEqual('/shares/' + self.vvol['id'], output)
        self.assertTrue(self.mock_log.debug.called)
        ssh.HNASSSHBackend._execute.assert_called_with(fake_export_command)

    def test_create_share_from_snapshot_quota_unset(self):
        # Tests when quota is unset
        fake_quota_command = ['quota', 'list', 'file_system', 'vvol_test']
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(return_value=(HNAS_RESULT_quota_err, "")))

        self.assertRaises(exception.HNASBackendException,
                          self._driver.create_share_from_snapshot,
                          self.vvol, self.snapshot)
        ssh.HNASSSHBackend._execute.assert_called_with(fake_quota_command)

    def test_create_share_from_empty_snapshot(self):
        msg = 'Cannot find any clonable files in the source directory'
        fake_export_command = ['nfs-export', 'add', '-S', 'disable', '-c',
                               '127.0.0.1', '/shares/vvol_test',
                               'file_system', '/shares/vvol_test']

        # Tests when successfully creates a share from snapshot
        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_empty, ""),
                                                (HNAS_RESULT_empty, ""),
                                                (putils.ProcessExecutionError
                                                 (stderr=msg)),
                                                (HNAS_RESULT_export, "")]))

        output = self._driver.create_share_from_snapshot(self.vvol,
                                                         self.snapshot)

        self.assertEqual('/shares/' + self.vvol['id'], output)
        self.assertTrue(self.mock_log.debug.called)
        self.assertTrue(self.mock_log.warning.called)
        ssh.HNASSSHBackend._execute.assert_called_with(fake_export_command)

    def test_create_share_from_snapshot_fails(self):
        msg = 'Cannot copy from source directory'
        fake_submit_command = ['tree-clone-job-submit', '-f', 'file_system',
                               '/snapshots/vvol_test/snapshot_test',
                               '/shares/vvol_test']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[(HNAS_RESULT_quota, ""),
                                                (HNAS_RESULT_fs, ""),
                                                (HNAS_RESULT_empty, ""),
                                                (HNAS_RESULT_empty, ""),
                                                (putils.ProcessExecutionError
                                                 (stderr=msg)),
                                                (HNAS_RESULT_export, "")]))

        self.assertRaises(exception.HNASBackendException,
                          self._driver.create_share_from_snapshot,
                          self.vvol, self.snapshot)

        self.assertTrue(self.mock_log.debug.called)
        ssh.HNASSSHBackend._execute.assert_called_with(fake_submit_command)

    def test__execute(self):
        key = self.ssh_private_key
        commands = ['tree-clone-job-submit', '-e', '/src', '/dst']
        concat_command = ('ssc --smuauth fake console-context --evs 2 '
                          'tree-clone-job-submit -e /src /dst')
        self.mock_object(paramiko.SSHClient, 'connect')
        self.mock_object(putils, 'ssh_execute',
                         mock.Mock(return_value=[HNAS_RESULT_job, '']))

        output, err = self._driver._execute(commands)

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
        key = self.ssh_private_key
        commands = ['tree-clone-job-submit', '-e', '/src', '/dst']
        concat_command = ('ssc --smuauth fake console-context --evs 2 '
                          'tree-clone-job-submit -e /src /dst')
        self.mock_object(paramiko.SSHClient, 'connect')
        self.mock_object(putils, 'ssh_execute',
                         mock.Mock(side_effect=putils.ProcessExecutionError))

        self.assertRaises(putils.ProcessExecutionError,
                          self._driver._execute, commands)

        putils.ssh_execute.assert_called_once_with(mock.ANY, concat_command,
                                                   check_exit_code=True)
        paramiko.SSHClient.connect.assert_called_with(self.ip,
                                                      username=self.user,
                                                      key_filename=key,
                                                      look_for_keys=False,
                                                      timeout=None,
                                                      password=self.password,
                                                      port=self.port)
        self.assertTrue(self.mock_log.debug.called)
        self.assertTrue(self.mock_log.error.called)

    def test_mount_fs_already_mounted(self):
        msg = 'file system is already mounted'
        fake_mount_command = ['mount', 'file_system']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[putils.ProcessExecutionError
                                                (stderr=msg)]))

        output = self._driver._mount(self.fs_name)

        self.assertTrue(output)
        ssh.HNASSSHBackend._execute.assert_called_with(fake_mount_command)

    def test_error_mount_fs(self):
        msg = 'File system not found.'
        fake_mount_command = ['mount', 'file_system']

        self.mock_object(ssh.HNASSSHBackend, '_execute',
                         mock.Mock(side_effect=[putils.ProcessExecutionError
                                                (stderr=msg)]))

        self.assertRaises(putils.ProcessExecutionError,
                          self._driver._mount, self.fs_name)
        ssh.HNASSSHBackend._execute.assert_called_with(fake_mount_command)
