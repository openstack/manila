#    Copyright 2012 OpenStack LLC
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

from manila.openstack.common import log as logging
from manila.share.drivers import lvm

LOG = logging.getLogger(__name__)


class FakeShareDriver(lvm.LVMShareDriver):
    """Logs calls instead of executing."""
    def __init__(self, *args, **kwargs):
        super(FakeShareDriver, self).__init__(execute=self.fake_execute,
                                              *args, **kwargs)

    def check_for_setup_error(self):
        """No setup necessary in fake mode."""
        pass

    @staticmethod
    def fake_execute(cmd, *_args, **_kwargs):
        """Execute that simply logs the command."""
        LOG.debug("FAKE EXECUTE: %s", cmd)
        return (None, None)
