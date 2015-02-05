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

from oslo import messaging
from oslo_config import cfg
from oslo_serialization import jsonutils

from manila import rpc
from manila.share import utils

CONF = cfg.CONF


class ShareAPI(object):
    '''Client side of the share rpc API.

    API version history:

        1.0 - Initial version.
    '''

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic=None):
        super(ShareAPI, self).__init__()
        target = messaging.Target(topic=CONF.share_topic,
                                  version=self.BASE_RPC_API_VERSION)
        self.client = rpc.get_client(target, '1.0')

    def create_share(self, ctxt, share, host,
                     request_spec, filter_properties,
                     snapshot_id=None):
        new_host = utils.extract_host(host)
        cctxt = self.client.prepare(server=new_host, version='1.0')
        request_spec_p = jsonutils.to_primitive(request_spec)
        cctxt.cast(
            ctxt,
            'create_share',
            share_id=share['id'],
            request_spec=request_spec_p,
            filter_properties=filter_properties,
            snapshot_id=snapshot_id,
        )

    def delete_share(self, ctxt, share):
        host = utils.extract_host(share['host'])
        cctxt = self.client.prepare(server=host, version='1.0')
        cctxt.cast(ctxt, 'delete_share', share_id=share['id'])

    def delete_share_server(self, ctxt, share_server):
        host = utils.extract_host(share_server['host'])
        cctxt = self.client.prepare(server=host, version='1.0')
        cctxt.cast(ctxt, 'delete_share_server', share_server=share_server)

    def create_snapshot(self, ctxt, share, snapshot):
        host = utils.extract_host(share['host'])
        cctxt = self.client.prepare(server=host)
        cctxt.cast(
            ctxt,
            'create_snapshot',
            share_id=share['id'],
            snapshot_id=snapshot['id'],
        )

    def delete_snapshot(self, ctxt, snapshot, host):
        new_host = utils.extract_host(host)
        cctxt = self.client.prepare(server=new_host)
        cctxt.cast(ctxt, 'delete_snapshot', snapshot_id=snapshot['id'])

    def allow_access(self, ctxt, share, access):
        host = utils.extract_host(share['host'])
        cctxt = self.client.prepare(server=host, version='1.0')
        cctxt.cast(ctxt, 'allow_access', access_id=access['id'])

    def deny_access(self, ctxt, share, access):
        host = utils.extract_host(share['host'])
        cctxt = self.client.prepare(server=host, version='1.0')
        cctxt.cast(ctxt, 'deny_access', access_id=access['id'])

    def publish_service_capabilities(self, ctxt):
        cctxt = self.client.prepare(fanout=True, version='1.0')
        cctxt.cast(ctxt, 'publish_service_capabilities')
