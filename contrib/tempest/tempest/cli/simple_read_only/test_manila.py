# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 Mirantis Inc.
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

import re
import subprocess

from tempest.cli import manilaclient
from tempest import config_share as config

CONF = config.CONF


class SimpleReadOnlyManilaClientTest(manilaclient.ClientTestBase):
    """Basic, read-only tests for Manila CLI client.

    Checks return values and output of read-only commands.
    These tests do not presume any content, nor do they create
    their own. They only verify the structure of output if present.
    """

    @classmethod
    def setUpClass(cls):
        super(SimpleReadOnlyManilaClientTest, cls).setUpClass()
        if not CONF.service_available.manila:
            raise cls.skipException("Manila not available")

    def test_manila_fake_action(self):
        self.assertRaises(subprocess.CalledProcessError,
                          self.manila, 'this-does-not-exist')

    def test_manila_absolute_limit_list(self):
        roles = self.parser.listing(self.manila('absolute-limits'))
        self.assertTableStruct(roles, ['Name', 'Value'])

    def test_manila_shares_list(self):
        self.manila('list')

    def test_manila_shares_list_all_tenants(self):
        self.manila('list', params='--all-tenants')

    def test_manila_shares_list_filter_by_name(self):
        self.manila('list', params='--name name')

    def test_manila_shares_list_filter_by_status(self):
        self.manila('list', params='--status status')

    def test_manila_endpoints(self):
        self.manila('endpoints')

    def test_manila_quota_class_show(self):
        """This CLI can accept and string as param."""
        roles = self.parser.listing(self.manila('quota-class-show',
                                                params='abc'))
        self.assertTableStruct(roles, ['Property', 'Value'])

    def test_manila_quota_defaults(self):
        """This CLI can accept and string as param."""
        roles = self.parser.listing(self.manila('quota-defaults'))
        self.assertTableStruct(roles, ['Property', 'Value'])

    def test_manila_quota_show(self):
        """This CLI can accept and string as param."""
        roles = self.parser.listing(self.manila('quota-show'))
        self.assertTableStruct(roles, ['Property', 'Value'])

    def test_manila_rate_limits(self):
        self.manila('rate-limits')

    def test_manila_snapshot_list(self):
        self.manila('snapshot-list')

    def test_manila_snapshot_list_all_tenants(self):
        self.manila('snapshot-list', params='--all-tenants')

    def test_manila_snapshot_list_filter_by_name(self):
        self.manila('snapshot-list', params='--name name')

    def test_manila_snapshot_list_filter_by_status(self):
        self.manila('snapshot-list', params='--status status')

    def test_manila_snapshot_list_filter_by_share_id(self):
        self.manila('snapshot-list', params='--share-id share_id')

    def test_manila_credentials(self):
        self.manila('credentials')

    def test_manila_list_extensions(self):
        roles = self.parser.listing(self.manila('list-extensions'))
        self.assertTableStruct(roles, ['Name', 'Summary', 'Alias', 'Updated'])

    def test_manila_help(self):
        help_text = self.manila('help')
        lines = help_text.split('\n')
        self.assertFirstLineStartsWith(lines, 'usage: manila')

        commands = []
        cmds_start = lines.index('Positional arguments:')
        cmds_end = lines.index('Optional arguments:')
        command_pattern = re.compile('^ {4}([a-z0-9\-\_]+)')
        for line in lines[cmds_start:cmds_end]:
            match = command_pattern.match(line)
            if match:
                commands.append(match.group(1))
        commands = set(commands)
        wanted_commands = set(('absolute-limits', 'list', 'help',
                               'quota-show', 'access-list', 'snapshot-list',
                               'access-allow', 'access-deny'))
        self.assertFalse(wanted_commands - commands)

    # Optional arguments:

    def test_manila_version(self):
        self.manila('', flags='--version')

    def test_manila_debug_list(self):
        self.manila('list', flags='--debug')

    def test_manila_retries_list(self):
        self.manila('list', flags='--retries 3')

    def test_manila_region_list(self):
        self.manila('list', flags='--os-region-name ' + CONF.identity.region)
