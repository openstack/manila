# Copyright 2014 Mirantis Inc.
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

from tempest.exceptions import base


class ShareBuildErrorException(base.TempestException):
    message = "Share %(share_id)s failed to build and is in ERROR status"


class AccessRuleBuildErrorException(base.TempestException):
    message = "Share's rule with id %(rule_id) is in ERROR status"


class SnapshotBuildErrorException(base.TempestException):
    message = "Snapshot %(snapshot_id)s failed to build and is in ERROR status"


class ShareProtocolNotSpecified(base.TempestException):
    message = "Share can not be created, share protocol is not specified"


class ShareNetworkNotSpecified(base.TempestException):
    message = "Share can not be created, share network not specified"


class NoAvailableNetwork(base.TempestException):
    message = "No available network for service VM"
