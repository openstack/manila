# Copyright 2011 OpenStack Foundation.
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

"""
Tests For Scheduler Host Filters.
"""

from oslo_serialization import jsonutils

from manila.scheduler.filters import base_host
from manila import test


class TestFilter(test.TestCase):
    pass


class TestBogusFilter(object):
    """Class that doesn't inherit from BaseHostFilter."""
    pass


class HostFiltersTestCase(test.TestCase):
    """Test case for host filters."""

    def setUp(self):
        super(HostFiltersTestCase, self).setUp()
        self.json_query = jsonutils.dumps(
            ['and', ['>=', '$free_ram_mb', 1024],
             ['>=', '$free_disk_mb', 200 * 1024]])
        namespace = 'manila.scheduler.filters'
        filter_handler = base_host.HostFilterHandler(namespace)
        classes = filter_handler.get_all_classes()
        self.class_map = {}
        for cls in classes:
            self.class_map[cls.__name__] = cls

    def test_all_filters(self):
        # Double check at least a couple of known filters exist
        self.assertIn('JsonFilter', self.class_map)
        self.assertIn('CapabilitiesFilter', self.class_map)
        self.assertIn('AvailabilityZoneFilter', self.class_map)
