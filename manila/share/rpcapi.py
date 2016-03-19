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

        1.0  - Initial version.
        1.1  - Add manage_share() and unmanage_share() methods
        1.2  - Add extend_share() method
        1.3  - Add shrink_share() method
        1.4  - Introduce Share Instances:
            create_share() -> create_share_instance()
            delete_share() -> delete_share_instance()
            Add share_instance argument to allow_access() & deny_access()
        1.5  - Add create_consistency_group, delete_consistency_group
                create_cgsnapshot, and delete_cgsnapshot methods
        1.6  - Introduce Share migration:
            migrate_share()
            get_migration_info()
            get_driver_migration_info()
        1.7  - Update target call API in allow/deny access methods
        1.8  - Introduce Share Replication:
            create_share_replica()
            delete_share_replica()
            promote_share_replica()
            update_share_replica()
        1.9  - Add manage_snapshot() and unmanage_snapshot() methods
        1.10 - Add migration_complete(), migration_cancel() and
            migration_get_progress(), rename migrate_share() to
            migration_start(), rename get_migration_info() to
            migration_get_info(), rename get_driver_migration_info() to
            migration_get_driver_info()
        1.11 - Add create_replicated_snapshot() and
            delete_replicated_snapshot() methods
    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic=None):
        super(ShareAPI, self).__init__()
        target = messaging.Target(topic=CONF.share_topic,
                                  version=self.BASE_RPC_API_VERSION)
        self.client = rpc.get_client(target, version_cap='1.11')

    def create_share_instance(self, context, share_instance, host,
                              request_spec, filter_properties,
                              snapshot_id=None):
        new_host = utils.extract_host(host)
        call_context = self.client.prepare(server=new_host, version='1.4')
        request_spec_p = jsonutils.to_primitive(request_spec)
        call_context.cast(context,
                          'create_share_instance',
                          share_instance_id=share_instance['id'],
                          request_spec=request_spec_p,
                          filter_properties=filter_properties,
                          snapshot_id=snapshot_id)

    def manage_share(self, context, share, driver_options=None):
        host = utils.extract_host(share['instance']['host'])
        call_context = self.client.prepare(server=host, version='1.1')
        call_context.cast(context,
                          'manage_share',
                          share_id=share['id'],
                          driver_options=driver_options)

    def unmanage_share(self, context, share):
        host = utils.extract_host(share['instance']['host'])
        call_context = self.client.prepare(server=host, version='1.1')
        call_context.cast(context, 'unmanage_share', share_id=share['id'])

    def manage_snapshot(self, context, snapshot, host,
                        driver_options=None):
        new_host = utils.extract_host(host)
        call_context = self.client.prepare(server=new_host, version='1.9')
        call_context.cast(context,
                          'manage_snapshot',
                          snapshot_id=snapshot['id'],
                          driver_options=driver_options)

    def unmanage_snapshot(self, context, snapshot, host):
        new_host = utils.extract_host(host)
        call_context = self.client.prepare(server=new_host, version='1.9')
        call_context.cast(context,
                          'unmanage_snapshot',
                          snapshot_id=snapshot['id'])

    def delete_share_instance(self, context, share_instance, force=False):
        host = utils.extract_host(share_instance['host'])
        call_context = self.client.prepare(server=host, version='1.4')
        call_context.cast(context,
                          'delete_share_instance',
                          share_instance_id=share_instance['id'],
                          force=force)

    def migration_start(self, context, share, dest_host, force_host_copy,
                        notify):
        new_host = utils.extract_host(share['instance']['host'])
        call_context = self.client.prepare(server=new_host, version='1.6')
        host_p = {'host': dest_host.host,
                  'capabilities': dest_host.capabilities}
        call_context.cast(context,
                          'migration_start',
                          share_id=share['id'],
                          host=host_p,
                          force_host_copy=force_host_copy,
                          notify=notify)

    def migration_get_info(self, context, share_instance):
        new_host = utils.extract_host(share_instance['host'])
        call_context = self.client.prepare(server=new_host, version='1.6')
        return call_context.call(context,
                                 'migration_get_info',
                                 share_instance_id=share_instance['id'])

    def migration_get_driver_info(self, context, share_instance):
        new_host = utils.extract_host(share_instance['host'])
        call_context = self.client.prepare(server=new_host, version='1.6')
        return call_context.call(context,
                                 'migration_get_driver_info',
                                 share_instance_id=share_instance['id'])

    def delete_share_server(self, context, share_server):
        host = utils.extract_host(share_server['host'])
        call_context = self.client.prepare(server=host, version='1.0')
        call_context.cast(context,
                          'delete_share_server',
                          share_server=share_server)

    def create_snapshot(self, context, share, snapshot):
        host = utils.extract_host(share['instance']['host'])
        call_context = self.client.prepare(server=host)
        call_context.cast(context,
                          'create_snapshot',
                          share_id=share['id'],
                          snapshot_id=snapshot['id'])

    def delete_snapshot(self, context, snapshot, host):
        new_host = utils.extract_host(host)
        call_context = self.client.prepare(server=new_host)
        call_context.cast(context,
                          'delete_snapshot',
                          snapshot_id=snapshot['id'])

    def create_replicated_snapshot(self, context, share, replicated_snapshot):
        host = utils.extract_host(share['instance']['host'])
        call_context = self.client.prepare(server=host, version='1.11')
        call_context.cast(context,
                          'create_replicated_snapshot',
                          snapshot_id=replicated_snapshot['id'],
                          share_id=share['id'])

    def delete_replicated_snapshot(self, context, replicated_snapshot, host,
                                   share_id=None, force=False):
        host = utils.extract_host(host)
        call_context = self.client.prepare(server=host, version='1.11')
        call_context.cast(context,
                          'delete_replicated_snapshot',
                          snapshot_id=replicated_snapshot['id'],
                          share_id=share_id,
                          force=force)

    @staticmethod
    def _get_access_rules(access):
        if isinstance(access, list):
            return [rule['id'] for rule in access]
        else:
            return [access['id']]

    def allow_access(self, context, share_instance, access):
        host = utils.extract_host(share_instance['host'])
        call_context = self.client.prepare(server=host, version='1.7')
        call_context.cast(context,
                          'allow_access',
                          share_instance_id=share_instance['id'],
                          access_rules=self._get_access_rules(access))

    def deny_access(self, context, share_instance, access):
        host = utils.extract_host(share_instance['host'])
        call_context = self.client.prepare(server=host, version='1.7')
        call_context.cast(context,
                          'deny_access',
                          share_instance_id=share_instance['id'],
                          access_rules=self._get_access_rules(access))

    def publish_service_capabilities(self, context):
        call_context = self.client.prepare(fanout=True, version='1.0')
        call_context.cast(context, 'publish_service_capabilities')

    def extend_share(self, context, share, new_size, reservations):
        host = utils.extract_host(share['instance']['host'])
        call_context = self.client.prepare(server=host, version='1.2')
        call_context.cast(context,
                          'extend_share',
                          share_id=share['id'],
                          new_size=new_size,
                          reservations=reservations)

    def shrink_share(self, context, share, new_size):
        host = utils.extract_host(share['instance']['host'])
        call_context = self.client.prepare(server=host, version='1.3')
        call_context.cast(context,
                          'shrink_share',
                          share_id=share['id'],
                          new_size=new_size)

    def create_consistency_group(self, context, cg, host):
        new_host = utils.extract_host(host)
        call_context = self.client.prepare(server=new_host, version='1.5')
        call_context.cast(context,
                          'create_consistency_group',
                          cg_id=cg['id'])

    def delete_consistency_group(self, context, cg):
        new_host = utils.extract_host(cg['host'])
        call_context = self.client.prepare(server=new_host, version='1.5')
        call_context.cast(context,
                          'delete_consistency_group',
                          cg_id=cg['id'])

    def create_cgsnapshot(self, context, cgsnapshot, host):
        new_host = utils.extract_host(host)
        call_context = self.client.prepare(server=new_host, version='1.5')
        call_context.cast(context,
                          'create_cgsnapshot',
                          cgsnapshot_id=cgsnapshot['id'])

    def delete_cgsnapshot(self, context, cgsnapshot, host):
        new_host = utils.extract_host(host)
        call_context = self.client.prepare(server=new_host, version='1.5')
        call_context.cast(context,
                          'delete_cgsnapshot',
                          cgsnapshot_id=cgsnapshot['id'])

    def create_share_replica(self, context, share_replica, host,
                             request_spec, filter_properties):
        new_host = utils.extract_host(host)
        call_context = self.client.prepare(server=new_host, version='1.8')
        request_spec_p = jsonutils.to_primitive(request_spec)
        call_context.cast(context,
                          'create_share_replica',
                          share_replica_id=share_replica['id'],
                          request_spec=request_spec_p,
                          filter_properties=filter_properties,
                          share_id=share_replica['share_id'])

    def delete_share_replica(self, context, share_replica, force=False):
        host = utils.extract_host(share_replica['host'])
        call_context = self.client.prepare(server=host, version='1.8')
        call_context.cast(context,
                          'delete_share_replica',
                          share_replica_id=share_replica['id'],
                          share_id=share_replica['share_id'],
                          force=force)

    def promote_share_replica(self, context, share_replica):
        host = utils.extract_host(share_replica['host'])
        call_context = self.client.prepare(server=host, version='1.8')
        call_context.cast(context,
                          'promote_share_replica',
                          share_replica_id=share_replica['id'],
                          share_id=share_replica['share_id'])

    def update_share_replica(self, context, share_replica):
        host = utils.extract_host(share_replica['host'])
        call_context = self.client.prepare(server=host, version='1.8')
        call_context.cast(context,
                          'update_share_replica',
                          share_replica_id=share_replica['id'],
                          share_id=share_replica['share_id'])

    def migration_complete(self, context, share, share_instance_id,
                           new_share_instance_id):
        new_host = utils.extract_host(share['host'])
        call_context = self.client.prepare(server=new_host, version='1.10')
        call_context.cast(context,
                          'migration_complete',
                          share_id=share['id'],
                          share_instance_id=share_instance_id,
                          new_share_instance_id=new_share_instance_id)

    def migration_cancel(self, context, share):
        new_host = utils.extract_host(share['host'])
        call_context = self.client.prepare(server=new_host, version='1.10')
        call_context.call(context, 'migration_cancel', share_id=share['id'])

    def migration_get_progress(self, context, share):
        new_host = utils.extract_host(share['host'])
        call_context = self.client.prepare(server=new_host, version='1.10')
        return call_context.call(context,
                                 'migration_get_progress',
                                 share_id=share['id'])
