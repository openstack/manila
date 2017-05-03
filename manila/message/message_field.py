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

from manila import exception
from manila.i18n import _


class Resource(object):

    SHARE = 'SHARE'
    SHARE_GROUP = 'SHARE_GROUP'
    SHARE_REPLICA = 'SHARE_REPLICA'
    SHARE_SNAPSHOT = 'SHARE_SNAPSHOT'


class Action(object):

    ALLOCATE_HOST = ('001', _('allocate host'))
    CREATE = ('002', _('create'))
    DELETE_ACCESS_RULES = ('003', _('delete access rules'))
    PROMOTE = ('004', _('promote'))
    UPDATE = ('005', _('update'))
    REVERT_TO_SNAPSHOT = ('006', _('revert to snapshot'))
    DELETE = ('007', _('delete'))
    ALL = (ALLOCATE_HOST,
           CREATE,
           DELETE_ACCESS_RULES,
           PROMOTE,
           UPDATE,
           REVERT_TO_SNAPSHOT,
           DELETE)


class Detail(object):

    UNKNOWN_ERROR = ('001', _('An unknown error occurred.'))
    NO_VALID_HOST = (
        '002', _("No storage could be allocated for this share request. "
                 "Trying again with a different size or share type may "
                 "succeed."))
    UNEXPECTED_NETWORK = (
        '003', _("Driver does not expect share-network to be provided with "
                 "current configuration."))
    NO_SHARE_SERVER = (
        '004', _("Could not find an existing share server or allocate one on "
                 "the share network provided. You may use a different share "
                 "network, or verify the network details in the share network "
                 "and retry your request. If this doesn't work, contact your "
                 "administrator to troubleshoot issues with your network."))
    NO_ACTIVE_AVAILABLE_REPLICA = (
        '005', _("An 'active' replica must exist in 'available' state to "
                 "create a new replica for share."))
    NO_ACTIVE_REPLICA = (
        '006', _("Share has no replica with 'replica_state' set to 'active'."))

    FILTER_MSG = _("No storage could be allocated for this share request, "
                   "%s filter didn't succeed.")
    FILTER_AVAILABILITY = ('007', FILTER_MSG % 'AvailabilityZone')
    FILTER_CAPABILITIES = ('008', FILTER_MSG % 'Capabilities')
    FILTER_CAPACITY = ('009', FILTER_MSG % 'Capacity')
    FILTER_DRIVER = ('010', FILTER_MSG % 'Driver')
    FILTER_IGNORE = ('011', FILTER_MSG % 'IgnoreAttemptedHosts')
    FILTER_JSON = ('012', FILTER_MSG % 'Json')
    FILTER_RETRY = ('013', FILTER_MSG % 'Retry')
    FILTER_REPLICATION = ('014', FILTER_MSG % 'ShareReplication')

    ALL = (UNKNOWN_ERROR,
           NO_VALID_HOST,
           UNEXPECTED_NETWORK,
           NO_SHARE_SERVER,
           NO_ACTIVE_AVAILABLE_REPLICA,
           NO_ACTIVE_REPLICA,
           FILTER_AVAILABILITY,
           FILTER_CAPABILITIES,
           FILTER_CAPACITY,
           FILTER_DRIVER,
           FILTER_IGNORE,
           FILTER_JSON,
           FILTER_RETRY,
           FILTER_REPLICATION)

    # Exception and detail mappings
    EXCEPTION_DETAIL_MAPPINGS = {
        NO_VALID_HOST: ['NoValidHost'],
    }

    # Use special code for each filter rather then categorize all as
    # NO_VALID_HOST
    FILTER_DETAIL_MAPPINGS = {
        'AvailabilityZoneFilter': FILTER_AVAILABILITY,
        'CapabilitiesFilter': FILTER_CAPABILITIES,
        'CapacityFilter': FILTER_CAPACITY,
        'DriverFilter': FILTER_DRIVER,
        'IgnoreAttemptedHostsFilter': FILTER_IGNORE,
        'JsonFilter': FILTER_JSON,
        'RetryFilter': FILTER_RETRY,
        'ShareReplicationFilter': FILTER_REPLICATION,
    }


def translate_action(action_id):
    action_message = next((action[1] for action in Action.ALL
                           if action[0] == action_id), None)
    return action_message or 'unknown action'


def translate_detail(detail_id):
    detail_message = next((action[1] for action in Detail.ALL
                           if action[0] == detail_id), None)
    return detail_message or Detail.UNKNOWN_ERROR[1]


def translate_detail_id(excep, detail):
    if excep is not None:
        detail = _translate_exception_to_detail(excep)
    if detail in Detail.ALL:
        return detail[0]
    return Detail.UNKNOWN_ERROR[0]


def _translate_exception_to_detail(ex):
    if isinstance(ex, exception.NoValidHost):
        # if NoValidHost was raised because a filter failed (a filter
        # didn't return any hosts), use a filter-specific detail
        details = getattr(ex, 'detail_data', {})
        last_filter = details.get('last_filter')
        return Detail.FILTER_DETAIL_MAPPINGS.get(
            last_filter, Detail.NO_VALID_HOST)
    else:
        for key, value in Detail.EXCEPTION_DETAIL_MAPPINGS.items():
            if ex.__class__.__name__ in value:
                return key
