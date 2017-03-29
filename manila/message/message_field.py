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

    ALL = (UNKNOWN_ERROR,
           NO_VALID_HOST,
           UNEXPECTED_NETWORK,
           NO_SHARE_SERVER,
           NO_ACTIVE_AVAILABLE_REPLICA,
           NO_ACTIVE_REPLICA,)

    # Exception and detail mappings
    EXCEPTION_DETAIL_MAPPINGS = {
        NO_VALID_HOST: ['NoValidHost'],
    }


def translate_action(action_id):
    action_message = next((action[1] for action in Action.ALL
                           if action[0] == action_id), None)
    return action_message or 'unknown action'


def translate_detail(detail_id):
    detail_message = next((action[1] for action in Detail.ALL
                           if action[0] == detail_id), None)
    return detail_message or Detail.UNKNOWN_ERROR[1]


def translate_detail_id(exception, detail):
    if exception is not None and isinstance(exception, Exception):
        for key, value in Detail.EXCEPTION_DETAIL_MAPPINGS.items():
            if exception.__class__.__name__ in value:
                return key[0]
    if (detail in Detail.ALL and
            detail is not Detail.EXCEPTION_DETAIL_MAPPINGS):
        return detail[0]
    return Detail.UNKNOWN_ERROR[0]
