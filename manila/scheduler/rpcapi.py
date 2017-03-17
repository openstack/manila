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
        1.2 - Introduce Share Instances. Replace ``create_share()`` with
        ``create_share_instance()``
        1.3 - Add create_consistency_group method (renamed in 1.7)
        1.4 - Add migrate_share_to_host method
        1.5 - Add create_share_replica
        1.6 - Add manage_share
        1.7 - Updated migrate_share_to_host method with new parameters
        1.8 - Rename create_consistency_group -> create_share_group method
    """

    RPC_API_VERSION = '1.8'

    def __init__(self):
        super(SchedulerAPI, self).__init__()
        target = messaging.Target(topic=CONF.scheduler_topic,
                                  version=self.RPC_API_VERSION)
        self.client = rpc.get_client(target, version_cap=self.RPC_API_VERSION)

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

    def create_share_group(self, context, share_group_id, request_spec=None,
                           filter_properties=None):
        """Casts an rpc to the scheduler to create a share group.

        Example of 'request_spec' argument value::

            {

                'share_group_type_id': 'fake_share_group_type_id',
                'share_group_id': 'some_fake_uuid',
                'availability_zone_id': 'some_fake_az_uuid',
                'share_types': [models.ShareType],
                'resource_type': models.ShareGroup,

            }

        """
        request_spec_p = jsonutils.to_primitive(request_spec)
        call_context = self.client.prepare(version='1.8')
        return call_context.cast(context,
                                 'create_share_group',
                                 share_group_id=share_group_id,
                                 request_spec=request_spec_p,
                                 filter_properties=filter_properties)

    def migrate_share_to_host(
            self, context, share_id, host, force_host_assisted_migration,
            preserve_metadata, writable, nondisruptive, preserve_snapshots,
            new_share_network_id, new_share_type_id, request_spec=None,
            filter_properties=None):

        call_context = self.client.prepare(version='1.7')
        request_spec_p = jsonutils.to_primitive(request_spec)
        return call_context.cast(
            context, 'migrate_share_to_host',
            share_id=share_id,
            host=host,
            force_host_assisted_migration=force_host_assisted_migration,
            preserve_metadata=preserve_metadata,
            writable=writable,
            nondisruptive=nondisruptive,
            preserve_snapshots=preserve_snapshots,
            new_share_network_id=new_share_network_id,
            new_share_type_id=new_share_type_id,
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
        return call_context.cast(context, 'manage_share',
                                 share_id=share_id,
                                 driver_options=driver_options,
                                 request_spec=request_spec,
                                 filter_properties=filter_properties)
