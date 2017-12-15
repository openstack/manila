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

from manila.policies import base
from manila.policies import share_instance_export_location
from manila.policies import share_snapshot
from manila.policies import share_snapshot_export_location
from manila.policies import share_snapshot_instance
from manila.policies import share_snapshot_instance_export_location
from manila.policies import share_type
from manila.policies import shares


def list_rules():
    return itertools.chain(
        base.list_rules(),
        shares.list_rules(),
        share_instance_export_location.list_rules(),
        share_type.list_rules(),
        share_snapshot.list_rules(),
        share_snapshot_export_location.list_rules(),
        share_snapshot_instance.list_rules(),
        share_snapshot_instance_export_location.list_rules(),
    )
