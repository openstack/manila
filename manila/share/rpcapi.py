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
        1.7  - Update target call API in allow/deny access methods (Removed
            in 1.14)
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
        1.12 - Add provide_share_server(), create_share_server() and
            migration_driver_recovery(), remove migration_get_driver_info(),
            update migration_cancel(), migration_complete() and
            migration_get_progress method signature, rename
            migration_get_info() to connection_get_info()
        1.13 - Introduce share revert to snapshot: revert_to_snapshot()
        1.14 - Add update_access() and remove allow_access() and deny_access().
        1.15 - Updated migration_start() method with new parameter
            "preserve_snapshots"
        1.16  - Convert create_consistency_group, delete_consistency_group
                create_cgsnapshot, and delete_cgsnapshot methods to
                create_share_group, delete_share_group
                create_share_group_snapshot, and delete_share_group_snapshot
        1.17 - Add snapshot_update_access()
        1.18 - Remove unused "share_id" parameter from revert_to_snapshot()
    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic=None):
        super(ShareAPI, self).__init__()
        target = messaging.Target(topic=CONF.share_topic,
                                  version=self.BASE_RPC_API_VERSION)
        self.client = rpc.get_client(target, version_cap='1.18')

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

    def revert_to_snapshot(self, context, share, snapshot, host, reservations):
        host = utils.extract_host(host)
        call_context = self.client.prepare(server=host, version='1.18')
        call_context.cast(context,
                          'revert_to_snapshot',
                          snapshot_id=snapshot['id'],
                          reservations=reservations)

    def delete_share_instance(self, context, share_instance, force=False):
        host = utils.extract_host(share_instance['host'])
        call_context = self.client.prepare(server=host, version='1.4')
        call_context.cast(context,
                          'delete_share_instance',
                          share_instance_id=share_instance['id'],
                          force=force)

    def migration_start(self, context, share, dest_host,
                        force_host_assisted_migration, preserve_metadata,
                        writable, nondisruptive, preserve_snapshots,
                        new_share_network_id, new_share_type_id):
        new_host = utils.extract_host(share['instance']['host'])
        call_context = self.client.prepare(server=new_host, version='1.15')
        call_context.cast(
            context,
            'migration_start',
            share_id=share['id'],
            dest_host=dest_host,
            force_host_assisted_migration=force_host_assisted_migration,
            preserve_metadata=preserve_metadata,
            writable=writable,
            nondisruptive=nondisruptive,
            preserve_snapshots=preserve_snapshots,
            new_share_network_id=new_share_network_id,
            new_share_type_id=new_share_type_id)

    def connection_get_info(self, context, share_instance):
        new_host = utils.extract_host(share_instance['host'])
        call_context = self.client.prepare(server=new_host, version='1.12')
        return call_context.call(context,
                                 'connection_get_info',
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

    def delete_snapshot(self, context, snapshot, host, force=False):
        new_host = utils.extract_host(host)
        call_context = self.client.prepare(server=new_host)
        call_context.cast(context,
                          'delete_snapshot',
                          snapshot_id=snapshot['id'],
                          force=force)

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

    def update_access(self, context, share_instance):
        host = utils.extract_host(share_instance['host'])
        call_context = self.client.prepare(server=host, version='1.14')
        call_context.cast(context, 'update_access',
                          share_instance_id=share_instance['id'])

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

    def create_share_group(self, context, share_group, host):
        new_host = utils.extract_host(host)
        call_context = self.client.prepare(server=new_host, version='1.16')
        call_context.cast(
            context, 'create_share_group', share_group_id=share_group['id'])

    def delete_share_group(self, context, share_group):
        new_host = utils.extract_host(share_group['host'])
        call_context = self.client.prepare(server=new_host, version='1.16')
        call_context.cast(
            context, 'delete_share_group', share_group_id=share_group['id'])

    def create_share_group_snapshot(self, context, share_group_snapshot, host):
        new_host = utils.extract_host(host)
        call_context = self.client.prepare(server=new_host, version='1.16')
        call_context.cast(
            context, 'create_share_group_snapshot',
            share_group_snapshot_id=share_group_snapshot['id'])

    def delete_share_group_snapshot(self, context, share_group_snapshot, host):
        new_host = utils.extract_host(host)
        call_context = self.client.prepare(server=new_host, version='1.16')
        call_context.cast(
            context, 'delete_share_group_snapshot',
            share_group_snapshot_id=share_group_snapshot['id'])

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

    def migration_complete(self, context, src_share_instance,
                           dest_instance_id):
        new_host = utils.extract_host(src_share_instance['host'])
        call_context = self.client.prepare(server=new_host, version='1.12')
        call_context.cast(context,
                          'migration_complete',
                          src_instance_id=src_share_instance['id'],
                          dest_instance_id=dest_instance_id)

    def migration_cancel(self, context, src_share_instance, dest_instance_id):
        new_host = utils.extract_host(src_share_instance['host'])
        call_context = self.client.prepare(server=new_host, version='1.12')
        call_context.cast(context,
                          'migration_cancel',
                          src_instance_id=src_share_instance['id'],
                          dest_instance_id=dest_instance_id)

    def migration_get_progress(self, context, src_share_instance,
                               dest_instance_id):
        new_host = utils.extract_host(src_share_instance['host'])
        call_context = self.client.prepare(server=new_host, version='1.12')
        return call_context.call(context,
                                 'migration_get_progress',
                                 src_instance_id=src_share_instance['id'],
                                 dest_instance_id=dest_instance_id)

    def provide_share_server(self, context, share_instance, share_network_id,
                             snapshot_id=None):
        new_host = utils.extract_host(share_instance['host'])
        call_context = self.client.prepare(server=new_host, version='1.12')
        return call_context.call(context,
                                 'provide_share_server',
                                 share_instance_id=share_instance['id'],
                                 share_network_id=share_network_id,
                                 snapshot_id=snapshot_id)

    def create_share_server(self, context, share_instance, share_server_id):
        new_host = utils.extract_host(share_instance['host'])
        call_context = self.client.prepare(server=new_host, version='1.12')
        call_context.cast(context,
                          'create_share_server',
                          share_server_id=share_server_id)

    def snapshot_update_access(self, context, snapshot_instance):
        host = utils.extract_host(snapshot_instance['share_instance']['host'])
        call_context = self.client.prepare(server=host, version='1.17')
        call_context.cast(context,
                          'snapshot_update_access',
                          snapshot_instance_id=snapshot_instance['id'])
