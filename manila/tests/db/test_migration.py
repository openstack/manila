# Copyright 2014 Mirantis Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import alembic
import mock

from manila.db import migration
from manila import test


class MigrationTestCase(test.TestCase):
    def setUp(self):
        super(MigrationTestCase, self).setUp()
        self.config_patcher = mock.patch(
            'manila.db.migrations.alembic.migration._alembic_config')
        self.config = self.config_patcher.start()
        self.config.return_value = 'fake_config'
        self.addCleanup(self.config_patcher.stop)

    @mock.patch('alembic.command.upgrade')
    def test_upgrade(self, upgrade):
        migration.upgrade('version_1')
        upgrade.assert_called_once_with('fake_config', 'version_1')

    @mock.patch('alembic.command.upgrade')
    def test_upgrade_none_version(self, upgrade):
        migration.upgrade(None)
        upgrade.assert_called_once_with('fake_config', 'head')

    @mock.patch('alembic.command.downgrade')
    def test_downgrade(self, downgrade):
        migration.downgrade('version_1')
        downgrade.assert_called_once_with('fake_config', 'version_1')

    @mock.patch('alembic.command.downgrade')
    def test_downgrade_none_version(self, downgrade):
        migration.downgrade(None)
        downgrade.assert_called_once_with('fake_config', 'base')

    @mock.patch('alembic.command.stamp')
    def test_stamp(self, stamp):
        migration.stamp('version_1')
        stamp.assert_called_once_with('fake_config', 'version_1')

    @mock.patch('alembic.command.stamp')
    def test_stamp_none_version(self, stamp):
        migration.stamp(None)
        stamp.assert_called_once_with('fake_config', 'head')

    @mock.patch('alembic.command.revision')
    def test_revision(self, revision):
        migration.revision('test_message', 'autogenerate_value')
        revision.assert_called_once_with('fake_config', 'test_message',
                                         'autogenerate_value')

    @mock.patch.object(alembic.migration.MigrationContext, 'configure',
                       mock.Mock())
    def test_version(self):
        context = mock.Mock()
        context.get_current_revision = mock.Mock()
        alembic.migration.MigrationContext.configure.return_value = context
        migration.version()
        context.get_current_revision.assert_called_once_with()
