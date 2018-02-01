# Copyright (c) 2012 OpenStack Foundation
# Copyright (c) 2015 Rushil Chugh
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

"""Share-related Utilities and helpers."""

from oslo_config import cfg

from manila.common import constants
from manila.db import migration
from manila import rpc
from manila import utils

DEFAULT_POOL_NAME = '_pool0'
CONF = cfg.CONF


def extract_host(host, level='backend', use_default_pool_name=False):
    """Extract Host, Backend or Pool information from host string.

    :param host: String for host, which could include host@backend#pool info
    :param level: Indicate which level of information should be extracted
                  from host string. Level can be 'host', 'backend', 'pool',
                  or 'backend_name', default value is 'backend'
    :param use_default_pool_name: This flag specifies what to do
                              if level == 'pool' and there is no 'pool' info
                              encoded in host string.  default_pool_name=True
                              will return DEFAULT_POOL_NAME, otherwise it will
                              return None. Default value of this parameter
                              is False.
    :return: expected level of information

    For example:
        host = 'HostA@BackendB#PoolC'
        ret = extract_host(host, 'host')
        # ret is 'HostA'
        ret = extract_host(host, 'backend')
        # ret is 'HostA@BackendB'
        ret = extract_host(host, 'pool')
        # ret is 'PoolC'
        ret = extract_host(host, 'backend_name')
        # ret is 'BackendB'
        host = 'HostX@BackendY'
        ret = extract_host(host, 'pool')
        # ret is None
        ret = extract_host(host, 'pool', True)
        # ret is '_pool0'
    """
    if level == 'host':
        # Make sure pool is not included
        hst = host.split('#')[0]
        return hst.split('@')[0]
    if level == 'backend_name':
        hst = host.split('#')[0]
        return hst.split('@')[1]
    elif level == 'backend':
        return host.split('#')[0]
    elif level == 'pool':
        lst = host.split('#')
        if len(lst) == 2:
            return lst[1]
        elif use_default_pool_name is True:
            return DEFAULT_POOL_NAME
        else:
            return None


def append_host(host, pool):
    """Encode pool into host info."""
    if not host or not pool:
        return host

    new_host = "#".join([host, pool])
    return new_host


def get_active_replica(replica_list):
    """Returns the first 'active' replica in the list of replicas provided."""
    for replica in replica_list:
        if replica['replica_state'] == constants.REPLICA_STATE_ACTIVE:
            return replica


def change_rules_to_readonly(access_rules, add_rules, delete_rules):
    dict_access_rules = cast_access_object_to_dict_in_readonly(access_rules)
    dict_add_rules = cast_access_object_to_dict_in_readonly(add_rules)
    dict_delete_rules = cast_access_object_to_dict_in_readonly(delete_rules)
    return dict_access_rules, dict_add_rules, dict_delete_rules


def cast_access_object_to_dict_in_readonly(rules):
    dict_rules = []
    for rule in rules:
        dict_rules.append({
            'access_level': constants.ACCESS_LEVEL_RO,
            'access_type': rule['access_type'],
            'access_to': rule['access_to']
        })
    return dict_rules


@utils.if_notifications_enabled
def notify_about_share_usage(context, share, share_instance,
                             event_suffix, extra_usage_info=None, host=None):

    if not host:
        host = CONF.host

    if not extra_usage_info:
        extra_usage_info = {}

    usage_info = _usage_from_share(share, share_instance, **extra_usage_info)

    rpc.get_notifier("share", host).info(context, 'share.%s' % event_suffix,
                                         usage_info)


def _usage_from_share(share_ref, share_instance_ref, **extra_usage_info):

    usage_info = {
        'share_id': share_ref['id'],
        'user_id': share_ref['user_id'],
        'project_id': share_ref['project_id'],
        'snapshot_id': share_ref['snapshot_id'],
        'share_group_id': share_ref['share_group_id'],
        'size': share_ref['size'],
        'name': share_ref['display_name'],
        'description': share_ref['display_description'],
        'proto': share_ref['share_proto'],
        'is_public': share_ref['is_public'],
        'availability_zone': share_instance_ref['availability_zone'],
        'host': share_instance_ref['host'],
        'status': share_instance_ref['status'],
    }

    usage_info.update(extra_usage_info)

    return usage_info


def get_recent_db_migration_id():
    return migration.version()
