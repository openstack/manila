# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Intel, Inc.
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
Client side of the share RPC API.
"""

from cinder import exception
from cinder import flags
from cinder.openstack.common import rpc
import cinder.openstack.common.rpc.proxy


FLAGS = flags.FLAGS


class ShareAPI(cinder.openstack.common.rpc.proxy.RpcProxy):
    '''Client side of the share rpc API.

    API version history:

        1.0 - Initial version.
        1.1 - Add snapshot support.
        1.2 - Add filter scheduler support
    '''

    BASE_RPC_API_VERSION = '1.1'

    def __init__(self, topic=None):
        super(ShareAPI, self).__init__(
            topic=topic or FLAGS.share_topic,
            default_version=self.BASE_RPC_API_VERSION)

    def create_share(self, ctxt, share, host,
                     request_spec, filter_properties,
                     snapshot_id=None):
        self.cast(ctxt,
                  self.make_msg('create_share',
                                share_id=share['id'],
                                request_spec=request_spec,
                                filter_properties=filter_properties,
                                snapshot_id=snapshot_id),
                  topic=rpc.queue_get_for(ctxt,
                                          self.topic,
                                          host))

    def delete_share(self, ctxt, share):
        self.cast(ctxt,
                  self.make_msg('delete_share',
                                share_id=share['id']),
                  topic=rpc.queue_get_for(ctxt, self.topic, share['host']))

    def create_snapshot(self, ctxt, share, snapshot):
        self.cast(ctxt,
                  self.make_msg('create_snapshot',
                                share_id=share['id'],
                                snapshot_id=snapshot['id']),
                  topic=rpc.queue_get_for(ctxt, self.topic, share['host']))

    def delete_snapshot(self, ctxt, snapshot, host):
        self.cast(ctxt,
                  self.make_msg('delete_snapshot',
                                snapshot_id=snapshot['id']),
                  topic=rpc.queue_get_for(ctxt, self.topic, host))

    def allow_access(self, ctxt, share, access):
        self.cast(ctxt, self.make_msg('allow_access', access_id=access['id']),
                  topic=rpc.queue_get_for(ctxt,
                                          self.topic,
                                          share['host']))

    def deny_access(self, ctxt, share, access):
        self.cast(ctxt, self.make_msg('deny_access', access_id=access['id']),
                  topic=rpc.queue_get_for(ctxt,
                                          self.topic,
                                          share['host']))

    def publish_service_capabilities(self, ctxt):
        self.fanout_cast(ctxt, self.make_msg('publish_service_capabilities'),
                         version='1.0')
