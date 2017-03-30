# Copyright (c) Goutham Pacha Ravi.
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
"""Unit Tests for the interface methods in the manila/db/api.py."""

import re

from manila.db import api as db_interface
from manila.db.sqlalchemy import api as db_api
from manila import test


class DBInterfaceTestCase(test.TestCase):
    """Test cases for the DB Interface methods."""

    def test_interface_methods(self):
        """Ensure that implementation methods match interfaces.

        manila/db/api module is merely shim layer between the database
        implementation and the other methods using these implementations.
        Bugs are introduced when the shims go out of sync with the actual
        implementation. So this test ensures that method names and
        signatures match between the interface and the implementation.
        """
        members = dir(db_interface)
        # Ignore private methods for the file and any other members that
        # need not match.
        ignore_members = re.compile(r'^_|CONF|IMPL')
        interfaces = [i for i in members if not ignore_members.match(i)]
        for interface in interfaces:
            method = getattr(db_interface, interface)
            if callable(method):
                mock_method_call = self.mock_object(db_api, interface)
                # kwargs always specify defaults, ignore them in the signature.
                args = filter(
                    lambda x: x != 'kwargs', method.__code__.co_varnames)

                method(*args)

                self.assertTrue(mock_method_call.called)
