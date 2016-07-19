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

"""Base class for all backup drivers."""


class BackupDriver(object):

    def __init__(self):
        super(BackupDriver, self).__init__()

        # This flag indicates if backup driver implement backup, restore and
        # delete operation by its own or uses data manager.
        self.use_data_manager = True

    def backup(self, backup, share):
        """Start a backup of a specified share."""
        return

    def restore(self, backup, share):
        """Restore a saved backup."""
        return

    def delete(self, backup):
        """Delete a saved backup."""
        return

    def get_backup_info(self, backup):
        """Get backup capabilities information of driver."""
        return
