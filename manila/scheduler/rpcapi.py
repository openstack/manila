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

from oslo_config import cfg
import oslo_messaging as messaging
from oslo_serialization import jsonutils

from manila import rpc

CONF = cfg.CONF


class SchedulerAPI(object):
    """Client side of the scheduler rpc API.

    API version history:

        1.0 - Initial version.
        1.1 - Add get_pools method
        1.2 - Introduce Share Instances:
            Replace create_share() - > create_share_instance()
        1.3 - Add create_consistency_group method
        1.4 - Add migrate_share_to_host method
        1.5 - Add create_share_replica
        1.6 - Add manage_share
    """

    RPC_API_VERSION = '1.6'

    def __init__(self):
        super(SchedulerAPI, self).__init__()
        target = messaging.Target(topic=CONF.scheduler_topic,
                                  version=self.RPC_API_VERSION)
        self.client = rpc.get_client(target, version_cap='1.6')

    def create_share_instance(self, context, request_spec=None,
                              filter_properties=None):
        request_spec_p = jsonutils.to_primitive(request_spec)
        call_context = self.client.prepare(version='1.2')
        return call_context.cast(context,
                                 'create_share_instance',
                                 request_spec=request_spec_p,
                                 filter_properties=filter_properties)

    def update_service_capabilities(self, context,
                                    service_name, host,
                                    capabilities):
        call_context = self.client.prepare(fanout=True, version='1.0')
        call_context.cast(context,
                          'update_service_capabilities',
                          service_name=service_name,
                          host=host,
                          capabilities=capabilities)

    def get_pools(self, context, filters=None):
        call_context = self.client.prepare(version='1.1')
        return call_context.call(context, 'get_pools', filters=filters)

    def create_consistency_group(self, context, cg_id, request_spec=None,
                                 filter_properties=None):
        request_spec_p = jsonutils.to_primitive(request_spec)
        call_context = self.client.prepare(version='1.3')
        return call_context.cast(context,
                                 'create_consistency_group',
                                 cg_id=cg_id,
                                 request_spec=request_spec_p,
                                 filter_properties=filter_properties)

    def migrate_share_to_host(self, context, share_id, host,
                              force_host_copy, notify, request_spec=None,
                              filter_properties=None):

        call_context = self.client.prepare(version='1.4')
        request_spec_p = jsonutils.to_primitive(request_spec)
        return call_context.call(context, 'migrate_share_to_host',
                                 share_id=share_id,
                                 host=host,
                                 force_host_copy=force_host_copy,
                                 notify=notify,
                                 request_spec=request_spec_p,
                                 filter_properties=filter_properties)

    def create_share_replica(self, context, request_spec=None,
                             filter_properties=None):
        request_spec_p = jsonutils.to_primitive(request_spec)
        call_context = self.client.prepare(version='1.5')
        return call_context.cast(context,
                                 'create_share_replica',
                                 request_spec=request_spec_p,
                                 filter_properties=filter_properties)

    def manage_share(self, context, share_id, driver_options,
                     request_spec=None, filter_properties=None):

        call_context = self.client.prepare(version='1.6')
        return call_context.call(context, 'manage_share',
                                 share_id=share_id,
                                 driver_options=driver_options,
                                 request_spec=request_spec,
                                 filter_properties=filter_properties)
