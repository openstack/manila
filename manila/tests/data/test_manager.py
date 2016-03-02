# Copyright 2015, Hitachi Data Systems.
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
Tests For Data Manager
"""

from oslo_config import cfg

from manila import context
from manila.data import manager
from manila import test

CONF = cfg.CONF


class DataManagerTestCase(test.TestCase):
    """Test case for data manager."""

    manager_cls = manager.DataManager

    def setUp(self):
        super(DataManagerTestCase, self).setUp()
        self.manager = self.manager_cls()
        self.context = context.RequestContext('fake_user', 'fake_project')
        self.topic = 'fake_topic'

    def test_init(self):
        manager = self.manager
        self.assertIsNotNone(manager)
