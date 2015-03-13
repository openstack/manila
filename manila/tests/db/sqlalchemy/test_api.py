# Copyright (c) 2015 Rushil Chugh
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

"""Testing of SQLAlchemy backend."""

from manila import context
from manila.db.sqlalchemy import api
from manila import test


class SQLAlchemyAPIShareTestCase(test.TestCase):

    def setUp(self):
        """Run before each test."""
        super(SQLAlchemyAPIShareTestCase, self).setUp()
        self.ctxt = context.get_admin_context()

    def test_share_filter_by_host_with_pools(self):
        shares = [[api.share_create(self.ctxt, {'host': value})
                   for value in ('foo', 'foo#pool0')]]

        api.share_create(self.ctxt, {'host': 'foobar'})
        self._assertEqualListsOfObjects(shares[0],
                                        api.share_get_all_by_host(
                                            self.ctxt, 'foo'),
                                        ignored_keys=['share_type',
                                                      'share_type_id',
                                                      'export_locations'])

    def test_share_filter_all_by_host_with_pools_multiple_hosts(self):
        shares = [[api.share_create(self.ctxt, {'host': value})
                   for value in ('foo', 'foo#pool0', 'foo', 'foo#pool1')]]

        api.share_create(self.ctxt, {'host': 'foobar'})
        self._assertEqualListsOfObjects(shares[0],
                                        api.share_get_all_by_host(
                                            self.ctxt, 'foo'),
                                        ignored_keys=['share_type',
                                                      'share_type_id',
                                                      'export_locations'])
