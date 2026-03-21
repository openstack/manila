# Copyright (c) 2018 NEC, Corp.
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

from unittest import mock

from oslo_config import cfg
from oslo_upgradecheck import upgradecheck

from manila.cmd import status
from manila import test

CONF = cfg.CONF


class TestUpgradeChecks(test.TestCase):

    def setUp(self):
        super(TestUpgradeChecks, self).setUp()
        self.cmd = status.Checks()

    def test_checks_is_upgrade_commands_subclass(self):
        self.assertIsInstance(self.cmd, upgradecheck.UpgradeCommands)

    def test_upgrade_checks_tuple_is_not_empty(self):
        self.assertGreater(len(self.cmd._upgrade_checks), 0)

    def test_upgrade_checks_policy_json_check_succeeds(self):
        self.mock_object(
            CONF, 'find_file', mock.Mock(return_value=None))
        result = self.cmd.check()
        self.assertEqual(upgradecheck.Code.SUCCESS, result)

    def test_main_calls_upgradecheck_main(self):
        mock_main = self.mock_object(
            upgradecheck, 'main', mock.Mock(return_value=0))

        result = status.main()

        self.assertEqual(0, result)
        mock_main.assert_called_once()
        self.assertIs(CONF, mock_main.call_args.args[0])
        self.assertEqual('manila', mock_main.call_args.kwargs['project'])
        self.assertIsInstance(
            mock_main.call_args.kwargs['upgrade_command'], status.Checks)
