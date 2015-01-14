# Copyright 2012, Red Hat, Inc.
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
Client side of the scheduler manager RPC API.
"""

from oslo import messaging
from oslo_config import cfg
from oslo_serialization import jsonutils

from manila import rpc

CONF = cfg.CONF


class SchedulerAPI(object):
    '''Client side of the scheduler rpc API.

    API version history:

        1.0 - Initial version.
    '''

    RPC_API_VERSION = '1.0'

    def __init__(self):
        super(SchedulerAPI, self).__init__()
        target = messaging.Target(topic=CONF.scheduler_topic,
                                  version=self.RPC_API_VERSION)
        self.client = rpc.get_client(target, version_cap='1.0')

    def create_share(self, ctxt, topic, share_id, snapshot_id=None,
                     request_spec=None, filter_properties=None):
        request_spec_p = jsonutils.to_primitive(request_spec)
        cctxt = self.client.prepare(version='1.0')
        return cctxt.cast(
            ctxt,
            'create_share',
            topic=topic,
            share_id=share_id,
            snapshot_id=snapshot_id,
            request_spec=request_spec_p,
            filter_properties=filter_properties,
        )

    def update_service_capabilities(self, ctxt,
                                    service_name, host,
                                    capabilities):
        cctxt = self.client.prepare(fanout=True, version='1.0')
        cctxt.cast(
            ctxt,
            'update_service_capabilities',
            service_name=service_name,
            host=host,
            capabilities=capabilities,
        )
