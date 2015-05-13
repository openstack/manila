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

from oslo_config import cfg
import oslo_messaging as messaging
from oslo_serialization import jsonutils

from manila import rpc
from manila.share import utils

CONF = cfg.CONF


class ShareAPI(object):
    """Client side of the share rpc API.

    API version history:

        1.0 - Initial version.
        1.1 - Add manage_share() and unmanage_share() methods
        1.2 - Add extend_share() method
        1.3 - Add shrink_share() method
        1.4 - Introduce Share Instances:
            create_share() -> create_share_instance()
            delete_share() -> delete_share_instance()
            Add share_instance argument to allow_access() & deny_access()
        1.5 - Add create_consistency_group, delete_consistency_group
                create_cgsnapshot, and delete_cgsnapshot methods
        1.6 - Introduce Share migration:
            migrate_share()
            get_migration_info()
            get_driver_migration_info()
    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic=None):
        super(ShareAPI, self).__init__()
        target = messaging.Target(topic=CONF.share_topic,
                                  version=self.BASE_RPC_API_VERSION)
        self.client = rpc.get_client(target, version_cap='1.6')

    def create_share_instance(self, ctxt, share_instance, host,
                              request_spec, filter_properties,
                              snapshot_id=None):
        new_host = utils.extract_host(host)
        cctxt = self.client.prepare(server=new_host, version='1.4')
        request_spec_p = jsonutils.to_primitive(request_spec)
        cctxt.cast(
            ctxt,
            'create_share_instance',
            share_instance_id=share_instance['id'],
            request_spec=request_spec_p,
            filter_properties=filter_properties,
            snapshot_id=snapshot_id,
        )

    def manage_share(self, ctxt, share, driver_options=None):
        host = utils.extract_host(share['host'])
        cctxt = self.client.prepare(server=host, version='1.1')
        cctxt.cast(ctxt,
                   'manage_share',
                   share_id=share['id'],
                   driver_options=driver_options)

    def unmanage_share(self, ctxt, share):
        host = utils.extract_host(share['host'])
        cctxt = self.client.prepare(server=host, version='1.1')
        cctxt.cast(ctxt, 'unmanage_share', share_id=share['id'])

    def delete_share_instance(self, ctxt, share_instance):
        host = utils.extract_host(share_instance['host'])
        cctxt = self.client.prepare(server=host, version='1.4')
        cctxt.cast(ctxt, 'delete_share_instance',
                   share_instance_id=share_instance['id'])

    def migrate_share(self, ctxt, share, dest_host, force_host_copy):
        new_host = utils.extract_host(share['host'])
        cctxt = self.client.prepare(server=new_host, version='1.6')
        host_p = {'host': dest_host.host,
                  'capabilities': dest_host.capabilities}
        cctxt.cast(ctxt, 'migrate_share', share_id=share['id'],
                   host=host_p, force_host_copy=force_host_copy)

    def get_migration_info(self, ctxt, share_instance, share_server):
        new_host = utils.extract_host(share_instance['host'])
        cctxt = self.client.prepare(server=new_host, version='1.6')
        return cctxt.call(ctxt, 'get_migration_info',
                          share_instance_id=share_instance['id'],
                          share_server=share_server)

    def get_driver_migration_info(self, ctxt, share_instance, share_server):
        new_host = utils.extract_host(share_instance['host'])
        cctxt = self.client.prepare(server=new_host, version='1.6')
        return cctxt.call(ctxt, 'get_driver_migration_info',
                          share_instance_id=share_instance['id'],
                          share_server=share_server)

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

    def allow_access(self, ctxt, share_instance, access):
        host = utils.extract_host(share_instance['host'])
        cctxt = self.client.prepare(server=host, version='1.4')
        cctxt.cast(ctxt, 'allow_access',
                   share_instance_id=share_instance['id'],
                   access_id=access['id'])

    def deny_access(self, ctxt, share_instance, access):
        host = utils.extract_host(share_instance['host'])
        cctxt = self.client.prepare(server=host, version='1.4')
        cctxt.cast(ctxt, 'deny_access',
                   share_instance_id=share_instance['id'],
                   access_id=access['id'])

    def publish_service_capabilities(self, ctxt):
        cctxt = self.client.prepare(fanout=True, version='1.0')
        cctxt.cast(ctxt, 'publish_service_capabilities')

    def extend_share(self, ctxt, share, new_size, reservations):
        host = utils.extract_host(share['host'])
        cctxt = self.client.prepare(server=host, version='1.2')
        cctxt.cast(ctxt, 'extend_share', share_id=share['id'],
                   new_size=new_size, reservations=reservations)

    def shrink_share(self, ctxt, share, new_size):
        host = utils.extract_host(share['host'])
        cctxt = self.client.prepare(server=host, version='1.3')
        cctxt.cast(ctxt, 'shrink_share', share_id=share['id'],
                   new_size=new_size)

    def create_consistency_group(self, ctxt, cg, host):
        new_host = utils.extract_host(host)
        cctxt = self.client.prepare(server=new_host, version='1.5')
        cctxt.cast(
            ctxt,
            'create_consistency_group',
            cg_id=cg['id'])

    def delete_consistency_group(self, ctxt, cg):
        new_host = utils.extract_host(cg['host'])
        cctxt = self.client.prepare(server=new_host, version='1.5')
        cctxt.cast(
            ctxt,
            'delete_consistency_group',
            cg_id=cg['id'])

    def create_cgsnapshot(self, ctxt, cgsnapshot, host):
        new_host = utils.extract_host(host)
        cctxt = self.client.prepare(server=new_host, version='1.5')
        cctxt.cast(
            ctxt,
            'create_cgsnapshot',
            cgsnapshot_id=cgsnapshot['id'])

    def delete_cgsnapshot(self, ctxt, cgsnapshot, host):
        new_host = utils.extract_host(host)
        cctxt = self.client.prepare(server=new_host, version='1.5')
        cctxt.cast(
            ctxt,
            'delete_cgsnapshot',
            cgsnapshot_id=cgsnapshot['id'])
