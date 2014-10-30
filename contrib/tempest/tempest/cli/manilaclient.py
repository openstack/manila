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

from tempest_lib.cli import base  # noqa

from tempest import config_share as config
from tempest import test

CONF = config.CONF


class ClientTestBase(base.ClientTestBase, test.BaseTestCase):

    def manila(self, action, flags='', params='', fail_ok=False,
               endpoint_type='publicURL', merge_stderr=False):
        """Executes manila command for the given action."""
        flags += ' --endpoint-type %s' % endpoint_type
        return self.clients.cmd_with_auth(
            'manila', action, flags, params, fail_ok, merge_stderr)

    def _get_clients(self):
        clients = base.CLIClient(
            CONF.identity.admin_username,
            CONF.identity.admin_password,
            CONF.identity.admin_tenant_name,
            CONF.identity.uri,
            CONF.cli.cli_dir,
        )
        return clients
