# Copyright (c) 2016 Huawei Technologies Co., Ltd.
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

import oslo_messaging as messaging

from manila import rpc
from manila.share import utils


class HuaweiV3API(object):
    """Client side of the huawei V3 rpc API.

    API version history:

        1.0  - Initial version.
    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self):
        self.topic = 'huawei_v3'
        target = messaging.Target(topic=self.topic,
                                  version=self.BASE_RPC_API_VERSION)
        self.client = rpc.get_client(target, version_cap='1.0')

    def create_replica_pair(self, context, host, local_share_info,
                            remote_device_wwn, remote_fs_id):
        new_host = utils.extract_host(host)
        call_context = self.client.prepare(server=new_host, version='1.0')
        return call_context.call(
            context, 'create_replica_pair',
            local_share_info=local_share_info,
            remote_device_wwn=remote_device_wwn,
            remote_fs_id=remote_fs_id)
