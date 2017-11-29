# Copyright (c) 2017 Huawei Technologies Co., Ltd.
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


import itertools

from manila.policies import availability_zone
from manila.policies import base
from manila.policies import message
from manila.policies import quota_class_set
from manila.policies import quota_set
from manila.policies import scheduler_stats
from manila.policies import security_service
from manila.policies import service
from manila.policies import share_export_location
from manila.policies import share_group
from manila.policies import share_group_snapshot
from manila.policies import share_group_type
from manila.policies import share_group_types_spec
from manila.policies import share_instance
from manila.policies import share_instance_export_location
from manila.policies import share_network
from manila.policies import share_replica
from manila.policies import share_server
from manila.policies import share_snapshot
from manila.policies import share_snapshot_export_location
from manila.policies import share_snapshot_instance
from manila.policies import share_snapshot_instance_export_location
from manila.policies import share_type
from manila.policies import share_types_extra_spec
from manila.policies import shares


def list_rules():
    return itertools.chain(
        base.list_rules(),
        availability_zone.list_rules(),
        scheduler_stats.list_rules(),
        shares.list_rules(),
        share_instance_export_location.list_rules(),
        share_type.list_rules(),
        share_types_extra_spec.list_rules(),
        share_snapshot.list_rules(),
        share_snapshot_export_location.list_rules(),
        share_snapshot_instance.list_rules(),
        share_snapshot_instance_export_location.list_rules(),
        share_server.list_rules(),
        service.list_rules(),
        quota_set.list_rules(),
        quota_class_set.list_rules(),
        share_group_types_spec.list_rules(),
        share_group_type.list_rules(),
        share_group_snapshot.list_rules(),
        share_group.list_rules(),
        share_replica.list_rules(),
        share_network.list_rules(),
        security_service.list_rules(),
        share_export_location.list_rules(),
        share_instance.list_rules(),
        message.list_rules(),
    )
