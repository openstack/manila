# Copyright (c) 2015 Clinton Knight.  All rights reserved.
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
"""
Mock unit tests for the NetApp driver protocols base class module.
"""

import ddt

from manila.common import constants
from manila.share.drivers.netapp.dataontap.protocols import nfs_cmode
from manila import test


@ddt.ddt
class NetAppNASHelperBaseTestCase(test.TestCase):

    def test_set_client(self):
        # The base class is abstract, so we'll use a subclass to test
        # base class functionality.
        helper = nfs_cmode.NetAppCmodeNFSHelper()
        self.assertIsNone(helper._client)

        helper.set_client('fake_client')
        self.assertEqual('fake_client', helper._client)

    @ddt.data(
        {'level': constants.ACCESS_LEVEL_RW, 'readonly': False},
        {'level': constants.ACCESS_LEVEL_RO, 'readonly': True})
    @ddt.unpack
    def test_is_readonly(self, level, readonly):

        helper = nfs_cmode.NetAppCmodeNFSHelper()

        result = helper._is_readonly(level)

        self.assertEqual(readonly, result)
