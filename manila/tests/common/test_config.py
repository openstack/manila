# Copyright 2015 Mirantis Inc.
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

import ddt

from manila.common import config
from manila.common import constants
from manila import exception
from manila import test
from manila.tests import utils as test_utils

VALID_CASES = [proto.lower() for proto in constants.SUPPORTED_SHARE_PROTOCOLS]
VALID_CASES.extend([proto.upper() for proto in VALID_CASES])
VALID_CASES.append(','.join(case for case in VALID_CASES))


@ddt.ddt
class VerifyConfigShareProtocolsTestCase(test.TestCase):

    @ddt.data(*VALID_CASES)
    def test_verify_share_protocols_valid_cases(self, proto):
        data = dict(DEFAULT=dict(enabled_share_protocols=proto))
        with test_utils.create_temp_config_with_opts(data):
            config.verify_share_protocols()

    @ddt.data(None, '', 'fake', [], ['fake'], [VALID_CASES[0] + 'fake'])
    def test_verify_share_protocols_invalid_cases(self, proto):
        data = dict(DEFAULT=dict(enabled_share_protocols=proto))
        with test_utils.create_temp_config_with_opts(data):
            self.assertRaises(
                exception.ManilaException, config.verify_share_protocols)
