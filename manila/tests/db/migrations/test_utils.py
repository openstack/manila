# Copyright 2015 Mirantis Inc.
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

from manila.db.migrations import utils
from manila.db.sqlalchemy import api
from manila import test


class MigrationUtilsTestCase(test.TestCase):

    def test_load_table(self):
        connection = api.get_engine()
        table_name = 'shares'

        actual_result = utils.load_table(table_name, connection)

        self.assertIsNotNone(actual_result)
        self.assertEqual(table_name, actual_result.name)
