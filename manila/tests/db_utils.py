# Copyright 2015 Mirantis Inc.
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

import copy

from manila.common import constants
from manila import context
from manila import db
from manila.message import message_levels


def _create_db_row(method, default_values, custom_values):
    override_defaults = custom_values.pop('override_defaults', None)
    if override_defaults:
        default_values = custom_values
    else:
        default_values.update(copy.deepcopy(custom_values))
    return method(context.get_admin_context(), default_values)


def create_share_group(**kwargs):
    """Create a share group object."""
    share_group = {
        'share_network_id': None,
        'share_server_id': None,
        'user_id': 'fake',
        'project_id': 'fake',
        'status': constants.STATUS_CREATING,
        'host': 'fake_host'
    }
    return _create_db_row(db.share_group_create, share_group, kwargs)


def create_share_group_snapshot(share_group_id, **kwargs):
    """Create a share group snapshot object."""
    snapshot = {
        'share_group_id': share_group_id,
        'user_id': 'fake',
        'project_id': 'fake',
        'status': constants.STATUS_CREATING,
    }
    return _create_db_row(db.share_group_snapshot_create, snapshot, kwargs)


def create_share_group_snapshot_member(share_group_snapshot_id, **kwargs):
    """Create a share group snapshot member object."""
    member = {
        'share_proto': "NFS",
        'size': 0,
        'share_instance_id': None,
        'user_id': 'fake',
        'project_id': 'fake',
        'status': 'creating',
        'share_group_snapshot_id': share_group_snapshot_id,
    }
    return _create_db_row(
        db.share_group_snapshot_member_create, member, kwargs)


def create_share_access(**kwargs):
    share_access = {
        'id': 'fake_id',
        'access_type': 'ip',
        'access_to': 'fake_ip_address'
    }
    return _create_db_row(db.share_access_create, share_access, kwargs)


def create_share(**kwargs):
    """Create a share object."""
    share = {
        'share_proto': "NFS",
        'size': 0,
        'snapshot_id': None,
        'share_network_id': None,
        'share_server_id': None,
        'user_id': 'fake',
        'project_id': 'fake',
        'metadata': {'fake_key': 'fake_value'},
        'availability_zone': 'fake_availability_zone',
        'status': constants.STATUS_CREATING,
        'host': 'fake_host'
    }
    return _create_db_row(db.share_create, share, kwargs)


def create_share_without_instance(**kwargs):
    share = {
        'share_proto': "NFS",
        'size': 0,
        'snapshot_id': None,
        'share_network_id': None,
        'share_server_id': None,
        'user_id': 'fake',
        'project_id': 'fake',
        'metadata': {},
        'availability_zone': 'fake_availability_zone',
        'status': constants.STATUS_CREATING,
        'host': 'fake_host'
    }
    share.update(copy.deepcopy(kwargs))
    return db.share_create(context.get_admin_context(), share, False)


def create_share_instance(**kwargs):
    """Create a share instance object."""
    return db.share_instance_create(context.get_admin_context(),
                                    kwargs.pop('share_id'), kwargs)


def create_share_replica(**kwargs):
    """Create a share replica object."""

    if 'share_id' not in kwargs:
        share = create_share()
        kwargs['share_id'] = share['id']

    return db.share_instance_create(context.get_admin_context(),
                                    kwargs.pop('share_id'), kwargs)


def create_snapshot(**kwargs):
    """Create a snapshot object."""
    with_share = kwargs.pop('with_share', False)

    share = None
    if with_share:
        share = create_share(status=constants.STATUS_AVAILABLE,
                             size=kwargs.get('size', 0))

    snapshot = {
        'share_proto': "NFS",
        'size': 0,
        'share_id': share['id'] if with_share else None,
        'user_id': 'fake',
        'project_id': 'fake',
        'status': 'creating',
        'provider_location': 'fake',
    }
    snapshot.update(kwargs)
    return db.share_snapshot_create(context.get_admin_context(), snapshot)


def create_snapshot_instance(snapshot_id, **kwargs):
    """Create a share snapshot instance object."""

    snapshot_instance = {
        'provider_location': 'fake_provider_location',
        'progress': '0%',
        'status': constants.STATUS_CREATING,
    }

    snapshot_instance.update(kwargs)
    return db.share_snapshot_instance_create(
        context.get_admin_context(), snapshot_id, snapshot_instance)


def create_snapshot_instance_export_locations(snapshot_id, **kwargs):
    """Create a snapshot instance export location object."""
    export_location = {
        'share_snapshot_instance_id': snapshot_id,
    }

    export_location.update(kwargs)
    return db.share_snapshot_instance_export_location_create(
        context.get_admin_context(), export_location)


def create_access(**kwargs):
    """Create an access rule object."""
    state = kwargs.pop('state', constants.ACCESS_STATE_QUEUED_TO_APPLY)
    access = {
        'access_type': 'fake_type',
        'access_to': 'fake_IP',
        'share_id': kwargs.pop('share_id', None) or create_share()['id'],
    }
    access.update(kwargs)
    share_access_rule = _create_db_row(db.share_access_create, access, kwargs)

    for mapping in share_access_rule.instance_mappings:
        db.share_instance_access_update(
            context.get_admin_context(), share_access_rule['id'],
            mapping.share_instance_id, {'state': state})

    return share_access_rule


def create_snapshot_access(**kwargs):
    """Create a snapshot access rule object."""
    access = {
        'access_type': 'fake_type',
        'access_to': 'fake_IP',
        'share_snapshot_id': None,
    }
    return _create_db_row(db.share_snapshot_access_create, access, kwargs)


def create_share_server(**kwargs):
    """Create a share server object."""
    backend_details = kwargs.pop('backend_details', {})
    srv = {
        'host': 'host1',
        'share_network_id': 'fake_srv_id',
        'status': constants.STATUS_ACTIVE
    }
    share_srv = _create_db_row(db.share_server_create, srv, kwargs)
    if backend_details:
        db.share_server_backend_details_set(
            context.get_admin_context(), share_srv['id'], backend_details)
    return db.share_server_get(context.get_admin_context(),
                               share_srv['id'])


def create_share_type(**kwargs):
    """Create a share type object"""

    share_type = {
        'name': 'fake_type',
        'is_public': True,
    }

    return _create_db_row(db.share_type_create, share_type, kwargs)


def create_share_group_type(**kwargs):
    """Create a share group type object"""

    share_group_type = {
        'name': 'fake_group_type',
        'is_public': True,
    }

    return _create_db_row(db.share_group_type_create, share_group_type,
                          kwargs)


def create_share_network(**kwargs):
    """Create a share network object."""
    net = {
        'user_id': 'fake',
        'project_id': 'fake',
        'neutron_net_id': 'fake-neutron-net',
        'neutron_subnet_id': 'fake-neutron-subnet',
        'status': 'new',
        'network_type': 'vlan',
        'segmentation_id': 1000,
        'cidr': '10.0.0.0/24',
        'ip_version': 4,
        'name': 'whatever',
        'description': 'fake description',
    }
    return _create_db_row(db.share_network_create, net, kwargs)


def create_security_service(**kwargs):
    share_network_id = kwargs.pop('share_network_id', None)
    service = {
        'type': "FAKE",
        'project_id': 'fake-project-id',
    }
    service_ref = _create_db_row(db.security_service_create, service, kwargs)

    if share_network_id:
        db.share_network_add_security_service(context.get_admin_context(),
                                              share_network_id,
                                              service_ref['id'])
    return service_ref


def create_message(**kwargs):
    message_dict = {
        'action': 'fake_Action',
        'project_id': 'fake-project-id',
        'message_level': message_levels.ERROR,
    }
    return _create_db_row(db.message_create, message_dict, kwargs)
