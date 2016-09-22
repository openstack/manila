# Copyright 2014 mirantis Inc.
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

from testtools import testcase as tc

from manila_tempest_tests.tests.api import base


class ExtensionsTest(base.BaseSharesTest):

    @tc.attr(base.TAG_POSITIVE, base.TAG_API)
    def test_extensions(self):

        # get extensions
        extensions = self.shares_client.list_extensions()

        # verify response
        keys = ["alias", "updated", "name", "description"]
        [self.assertIn(key, ext.keys()) for ext in extensions for key in keys]
