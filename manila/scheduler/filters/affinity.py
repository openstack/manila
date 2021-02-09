# Copyright (c) 2021 SAP.
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

from oslo_log import log

from manila import exception
from manila.scheduler.filters import base_host
from manila.share import api

LOG = log.getLogger(__name__)

AFFINITY_FILTER = 'same_host'
ANTI_AFFINITY_FILTER = 'different_host'


class AffinityBaseFilter(base_host.BaseHostFilter):
    """Base class of affinity filters"""
    _filter_type = None

    def __init__(self):
        self.share_api = api.API()

    def filter_all(self, filter_obj_list, filter_properties):
        # _filter_type should be defined in subclass
        if self._filter_type is None:
            raise AffinityFilterTypeNotSetError

        try:
            filter_properties = self._validate(filter_properties)
        except SchedulerHintsNotSet:
            # AffinityFilter/AntiAffinityFilter is skipped if corresponding
            # hint is not set. If the "scheduler_hints" is not set, both
            # filters are skipped.
            return filter_obj_list
        except (exception.InvalidUUID,
                exception.ShareNotFound,
                exception.ShareInstanceNotFound) as e:
            # Stop scheduling share when above errors are caught
            LOG.error('%(filter_name)s: %(error)s', {
                'filter_name': self.__class__.__name__,
                'error': e})
            return None
        else:
            # Return list of hosts which pass the function host_passes()
            # overriden in AffinityFilter and AntiAffinityFilter.
            return [obj for obj in filter_obj_list
                    if self._filter_one(obj, filter_properties)]

    def _validate(self, filter_properties):
        context = filter_properties['context']
        hints = filter_properties.get('scheduler_hints')

        if hints is None:
            raise SchedulerHintsNotSet
        else:
            share_uuids = hints.get(self._filter_type)
            if share_uuids is None:
                raise SchedulerHintsNotSet

        share_uuids = share_uuids.split(",")

        filter_properties['scheduler_hints'][self._filter_type] = []

        filtered_hosts = []
        for uuid in share_uuids:
            try:
                share = self.share_api.get(context, uuid)
            except exception.NotFound:
                raise exception.ShareNotFound(uuid)
            instances = share.get('instances')
            if len(instances) == 0:
                raise exception.ShareInstanceNotFound(share_instance_id=uuid)
            filtered_hosts.append(
                [instance.get('host') for instance in instances])

        if self._filter_type == AFFINITY_FILTER:
            filter_properties['scheduler_hints'][self._filter_type] = list(
                set.intersection(*map(set, filtered_hosts)))
        else:
            filter_properties['scheduler_hints'][self._filter_type] = list(
                set.union(*map(set, filtered_hosts)))

        return filter_properties


class AffinityFilter(AffinityBaseFilter):
    _filter_type = AFFINITY_FILTER

    def host_passes(self, host_state, filter_properties):
        allowed_hosts = \
            filter_properties['scheduler_hints'][self._filter_type]
        return host_state.host in allowed_hosts


class AntiAffinityFilter(AffinityBaseFilter):
    _filter_type = ANTI_AFFINITY_FILTER

    def host_passes(self, host_state, filter_properties):
        forbidden_hosts = \
            filter_properties['scheduler_hints'][self._filter_type]
        return host_state.host not in forbidden_hosts


class SchedulerHintsNotSet(Exception):
    pass


class AffinityFilterTypeNotSetError(Exception):
    pass
