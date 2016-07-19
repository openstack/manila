# Copyright 2023 Cloudification GmbH.
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

"""Implementation of a backup service that uses NFS storage as the backend."""

from oslo_config import cfg

from manila.data import backup_driver


nfsbackup_service_opts = [
    cfg.StrOpt('backup_mount_template',
               default='mount -vt %(proto)s %(options)s %(export)s %(path)s',
               help='The template for mounting NFS shares.'),
    cfg.StrOpt('backup_unmount_template',
               default='umount -v %(path)s',
               help='The template for unmounting NFS shares.'),
    cfg.StrOpt('backup_mount_export',
               help='NFS backup export location in hostname:path, '
                    'ipv4addr:path, or "[ipv6addr]:path" format.'),
    cfg.StrOpt('backup_mount_proto',
               default='nfs',
               help='Mount Protocol for mounting NFS shares'),
    cfg.StrOpt('backup_mount_options',
               default='',
               help='Mount options passed to the NFS client. See NFS '
                    'man page for details.'),
]

CONF = cfg.CONF
CONF.register_opts(nfsbackup_service_opts)


class NFSBackupDriver(backup_driver.BackupDriver):
    """Provides backup, restore and delete using NFS supplied repository."""

    def __init__(self):
        self.backup_mount_export = CONF.backup_mount_export
        self.backup_mount_template = CONF.backup_mount_template
        self.backup_unmount_template = CONF.backup_unmount_template
        self.backup_mount_options = CONF.backup_mount_options
        self.backup_mount_proto = CONF.backup_mount_proto
        super(NFSBackupDriver, self).__init__()

    def get_backup_info(self, backup):
        """Get backup info of a specified backup."""
        mount_template = (
            self.backup_mount_template % {
                'proto': self.backup_mount_proto,
                'options': self.backup_mount_options,
                'export': self.backup_mount_export,
                'path': '%(path)s',
            }
        )
        unmount_template = self.backup_unmount_template

        backup_info = {
            'mount': mount_template,
            'unmount': unmount_template,
        }

        return backup_info
