# Copyright 2015, Hitachi Data Systems.
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
Client side of the data manager RPC API.
"""

from oslo_config import cfg
import oslo_messaging as messaging

from manila import rpc

CONF = cfg.CONF


class DataAPI(object):
    """Client side of the data RPC API.

    API version history:

        1.0 - Initial version,
              Add migration_start(),
              data_copy_cancel(),
              data_copy_get_progress()
    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self):
        super(DataAPI, self).__init__()
        target = messaging.Target(topic=CONF.data_topic,
                                  version=self.BASE_RPC_API_VERSION)
        self.client = rpc.get_client(target, version_cap='1.0')

    def migration_start(self, context, share_id, ignore_list,
                        share_instance_id, dest_share_instance_id,
                        migration_info_src, migration_info_dest, notify):
        call_context = self.client.prepare(version='1.0')
        call_context.cast(
            context,
            'migration_start',
            share_id=share_id,
            ignore_list=ignore_list,
            share_instance_id=share_instance_id,
            dest_share_instance_id=dest_share_instance_id,
            migration_info_src=migration_info_src,
            migration_info_dest=migration_info_dest,
            notify=notify)

    def data_copy_cancel(self, context, share_id):
        call_context = self.client.prepare(version='1.0')
        call_context.call(context, 'data_copy_cancel', share_id=share_id)

    def data_copy_get_progress(self, context, share_id):
        call_context = self.client.prepare(version='1.0')
        return call_context.call(context, 'data_copy_get_progress',
                                 share_id=share_id)
