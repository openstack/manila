#    Copyright 2023 Cloudification GmbH.
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

from manila.data import backup_driver


class FakeBackupDriver(backup_driver.BackupDriver):
    """Fake Backup driver."""

    def __init__(self, *args, **kwargs):
        super(FakeBackupDriver, self).__init__(*args, **kwargs)
        pass

    def backup(self, backup, share):
        """Start a backup of a specified share."""
        pass

    def restore(self, backup, share):
        """Restore a saved backup."""
        pass

    def delete(self, backup):
        """Delete a saved backup."""
        pass

    def get_backup_info(self, backup):
        """Get backup capabilities information of driver."""
        backup_info = {
            'mount': 'mount -vt fake_proto /fake-export %(path)s',
            'unmount': 'umount -v %(path)s',
        }
        return backup_info
