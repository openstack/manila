#    Copyright 2012 OpenStack Foundation
#    Copyright 2014 Mirantis Inc.
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

from oslo_log import log
import six

from manila.share import driver
from manila.tests import fake_service_instance

LOG = log.getLogger(__name__)


class FakeShareDriver(driver.ShareDriver):
    """Fake share driver.

    This fake driver can be also used as a test driver within a real
    running manila-share instance. To activate it use this in manila.conf::

        enabled_share_backends = fake

        [fake]
        driver_handles_share_servers = True
        share_backend_name = fake
        share_driver = manila.tests.fake_driver.FakeShareDriver

    With it you basically mocked all backend driver calls but e.g. networking
    will still be activated.
    """

    def __init__(self, *args, **kwargs):
        self._setup_service_instance_manager()
        super(FakeShareDriver, self).__init__([True, False], *args, **kwargs)

    def _setup_service_instance_manager(self):
        self.service_instance_manager = (
            fake_service_instance.FakeServiceInstanceManager())

    def manage_existing(self, share, driver_options):
        LOG.debug("Fake share driver: manage")
        LOG.debug("Fake share driver: driver options: %s",
                  six.text_type(driver_options))
        return {'size': 1}

    def unmanage(self, share):
        LOG.debug("Fake share driver: unmanage")

    @property
    def driver_handles_share_servers(self):
        if not isinstance(self.configuration.safe_get(
                'driver_handles_share_servers'), bool):
            return True

        return self.configuration.driver_handles_share_servers

    def create_snapshot(self, context, snapshot, share_server=None):
        pass

    def delete_snapshot(self, context, snapshot, share_server=None):
        pass

    def create_share(self, context, share, share_server=None):
        return ['/fake/path', '/fake/path2']

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        return ['/fake/path', '/fake/path2']

    def delete_share(self, context, share, share_server=None):
        pass

    def ensure_share(self, context, share, share_server=None):
        pass

    def allow_access(self, context, share, access, share_server=None):
        pass

    def deny_access(self, context, share, access, share_server=None):
        pass

    def get_share_stats(self, refresh=False):
        return None

    def do_setup(self, context):
        pass

    def setup_server(self, *args, **kwargs):
        pass

    def teardown_server(self, *args, **kwargs):
        pass

    def get_network_allocations_number(self):
        # NOTE(vponomaryov): Simulate drivers that use share servers and
        # do not use 'service_instance' module.
        return 2

    def _verify_share_server_handling(self, driver_handles_share_servers):
        return super(FakeShareDriver, self)._verify_share_server_handling(
            driver_handles_share_servers)

    def create_share_group(self, context, group_id, share_server=None):
        pass

    def delete_share_group(self, context, group_id, share_server=None):
        pass
