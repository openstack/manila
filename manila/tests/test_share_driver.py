# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 NetApp
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
"""Unit tests for the Share driver module."""

import time

from manila import exception
from manila.share.configuration import Configuration
from manila.share import driver
from manila import test
from manila import utils


def fake_execute_with_raise(*cmd, **kwargs):
    raise exception.ProcessExecutionError


def fake_sleep(duration):
    pass


class ShareDriverTestCase(test.TestCase):
    def setUp(self):
        super(ShareDriverTestCase, self).setUp()
        self.utils = utils
        self.stubs.Set(self.utils, 'execute', fake_execute_with_raise)
        self.time = time
        self.stubs.Set(self.time, 'sleep', fake_sleep)

    def tearDown(self):
        super(ShareDriverTestCase, self).tearDown()

    def test__try_execute(self):
        execute_mixin = driver.ExecuteMixin(configuration=Configuration(None))
        self.assertRaises(exception.ProcessExecutionError,
                          execute_mixin._try_execute)
