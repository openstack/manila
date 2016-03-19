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


def _create_db_row(method, default_values, custom_values):
    override_defaults = custom_values.pop('override_defaults', None)
    if override_defaults:
        default_values = custom_values
    else:
        default_values.update(copy.deepcopy(custom_values))
    return method(context.get_admin_context(), default_values)


def create_consistency_group(**kwargs):
    """Create a consistency group object."""
    cg = {
        'share_network_id': None,
        'share_server_id': None,
        'user_id': 'fake',
        'project_id': 'fake',
        'status': constants.STATUS_CREATING,
        'host': 'fake_host'
    }
    return _create_db_row(db.consistency_group_create, cg, kwargs)


def create_cgsnapshot(cg_id, **kwargs):
    """Create a cgsnapshot object."""
    snapshot = {
        'consistency_group_id': cg_id,
        'user_id': 'fake',
        'project_id': 'fake',
        'status': constants.STATUS_CREATING,
    }
    return _create_db_row(db.cgsnapshot_create, snapshot, kwargs)


def create_cgsnapshot_member(cgsnapshot_id, **kwargs):
    """Create a cgsnapshot member object."""
    member = {
        'share_proto': "NFS",
        'size': 0,
        'share_id': None,
        'share_instance_id': None,
        'user_id': 'fake',
        'project_id': 'fake',
        'status': 'creating',
        'cgsnapshot_id': cgsnapshot_id,
    }
    return _create_db_row(db.cgsnapshot_member_create, member, kwargs)


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


def create_share_instance(**kwargs):
    """Create a share instance object."""
    instance = {
        'host': 'fake',
        'status': constants.STATUS_CREATING,
    }
    instance.update(kwargs)

    return db.share_instance_create(context.get_admin_context(),
                                    kwargs.pop('share_id'), kwargs)


def create_share_replica(**kwargs):
    """Create a share replica object."""
    replica = {
        'host': 'fake',
        'status': constants.STATUS_CREATING,
    }
    replica.update(kwargs)

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


def create_access(**kwargs):
    """Create a access rule object."""
    access = {
        'access_type': 'fake_type',
        'access_to': 'fake_IP',
        'share_id': None,
    }
    return _create_db_row(db.share_access_create, access, kwargs)


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
