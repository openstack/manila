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

from tempest_lib import exceptions


class ShareBuildErrorException(exceptions.TempestException):
    message = "Share %(share_id)s failed to build and is in ERROR status"


class AccessRuleBuildErrorException(exceptions.TempestException):
    message = "Share's rule with id %(rule_id)s is in ERROR status"


class SnapshotBuildErrorException(exceptions.TempestException):
    message = "Snapshot %(snapshot_id)s failed to build and is in ERROR status"


class ShareProtocolNotSpecified(exceptions.TempestException):
    message = "Share can not be created, share protocol is not specified"


class ShareNetworkNotSpecified(exceptions.TempestException):
    message = "Share can not be created, share network not specified"


class NoAvailableNetwork(exceptions.TempestException):
    message = "No available network for service VM"


class InvalidResource(exceptions.TempestException):
    message = "Provided invalid resource: %(message)s"


class ResourceReleaseFailed(exceptions.TempestException):
    message = "Failed to release resource '%(res_type)s' with id '%(res_id)s'."
