# Copyright 2010-2011 OpenStack LLC.
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

import datetime

from manila.api import common
from manila import utils


class ViewBuilder(common.ViewBuilder):
    """OpenStack API base limits view builder."""

    _collection_name = "limits"
    _detail_version_modifiers = [
        "add_share_replica_quotas",
        "add_share_group_quotas",
        "add_share_backup_quotas",
    ]

    def build(self, request, rate_limits, absolute_limits):
        rate_limits = self._build_rate_limits(rate_limits)
        absolute_limits = self._build_absolute_limits(request, absolute_limits)

        output = {
            "limits": {
                "rate": rate_limits,
                "absolute": absolute_limits,
            },
        }

        return output

    def _build_absolute_limits(self, request, absolute_limits):
        """Builder for absolute limits.

        absolute_limits should be given as a dict of limits.
        For example: {"limit": {"shares": 10, "gigabytes": 1024},
                      "in_use": {"shares": 8, "gigabytes": 256}}.
        """
        limit_names = {
            "limit": {
                "gigabytes": ["maxTotalShareGigabytes"],
                "snapshot_gigabytes": ["maxTotalSnapshotGigabytes"],
                "shares": ["maxTotalShares"],
                "snapshots": ["maxTotalShareSnapshots"],
                "share_networks": ["maxTotalShareNetworks"],
            },
            "in_use": {
                "shares": ["totalSharesUsed"],
                "snapshots": ["totalShareSnapshotsUsed"],
                "share_networks": ["totalShareNetworksUsed"],
                "gigabytes": ["totalShareGigabytesUsed"],
                "snapshot_gigabytes": ["totalSnapshotGigabytesUsed"],
            },
        }
        limits = {}
        self.update_versioned_resource_dict(request, limit_names,
                                            absolute_limits)
        for mapping_key in limit_names.keys():
            for k, v in absolute_limits.get(mapping_key, {}).items():
                if k in limit_names.get(mapping_key, []) and v is not None:
                    for name in limit_names[mapping_key][k]:
                        limits[name] = v
        return limits

    def _build_rate_limits(self, rate_limits):
        limits = []
        for rate_limit in rate_limits:
            _rate_limit_key = None
            _rate_limit = self._build_rate_limit(rate_limit)

            # check for existing key
            for limit in limits:
                if (limit["uri"] == rate_limit["URI"] and
                        limit["regex"] == rate_limit["regex"]):
                    _rate_limit_key = limit
                    break

            # ensure we have a key if we didn't find one
            if not _rate_limit_key:
                _rate_limit_key = {
                    "uri": rate_limit["URI"],
                    "regex": rate_limit["regex"],
                    "limit": [],
                }
                limits.append(_rate_limit_key)

            _rate_limit_key["limit"].append(_rate_limit)

        return limits

    def _build_rate_limit(self, rate_limit):
        _get_utc = datetime.datetime.utcfromtimestamp
        next_avail = _get_utc(rate_limit["resetTime"])
        return {
            "verb": rate_limit["verb"],
            "value": rate_limit["value"],
            "remaining": int(rate_limit["remaining"]),
            "unit": rate_limit["unit"],
            "next-available": utils.isotime(at=next_avail),
        }

    @common.ViewBuilder.versioned_method("2.58")
    def add_share_group_quotas(self, request, limit_names, absolute_limits):
        limit_names["limit"]["share_groups"] = ["maxTotalShareGroups"]
        limit_names["limit"]["share_group_snapshots"] = (
            ["maxTotalShareGroupSnapshots"])
        limit_names["in_use"]["share_groups"] = ["totalShareGroupsUsed"]
        limit_names["in_use"]["share_group_snapshots"] = (
            ["totalShareGroupSnapshotsUsed"])

    @common.ViewBuilder.versioned_method("2.53")
    def add_share_replica_quotas(self, request, limit_names, absolute_limits):
        limit_names["limit"]["share_replicas"] = ["maxTotalShareReplicas"]
        limit_names["limit"]["replica_gigabytes"] = (
            ["maxTotalReplicaGigabytes"])
        limit_names["in_use"]["share_replicas"] = ["totalShareReplicasUsed"]
        limit_names["in_use"]["replica_gigabytes"] = (
            ["totalReplicaGigabytesUsed"])

    @common.ViewBuilder.versioned_method("2.80")
    def add_share_backup_quotas(self, request, limit_names, absolute_limits):
        limit_names["limit"]["backups"] = ["maxTotalShareBackups"]
        limit_names["limit"]["backup_gigabytes"] = (
            ["maxTotalBackupGigabytes"])
        limit_names["in_use"]["backups"] = ["totalShareBackupsUsed"]
        limit_names["in_use"]["backup_gigabytes"] = (
            ["totalBackupGigabytesUsed"])
