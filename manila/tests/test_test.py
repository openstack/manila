# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""Tests for the testing base code."""

from oslo_config import cfg
import oslo_messaging as messaging

from manila import rpc
from manila import test


class IsolationTestCase(test.TestCase):
    """Ensure that things are cleaned up after failed tests.

    These tests don't really do much here, but if isolation fails a bunch
    of other tests should fail.

    """
    def test_service_isolation(self):
        self.start_service('share')

    def test_rpc_consumer_isolation(self):
        class NeverCalled(object):

            def __getattribute__(self, name):
                if name == 'target':
                    # oslo.messaging 5.31.0 explicitly looks for 'target'
                    # on the endpoint and checks its type, so we can't avoid
                    # it here.  Just ignore it if that's the case.
                    return
                assert False, "I should never get called - name: %s" % name

        target = messaging.Target(topic='share', server=cfg.CONF.host)
        server = rpc.get_server(target=target, endpoints=[NeverCalled()])
        server.start()
