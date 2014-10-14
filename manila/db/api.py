# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""Defines interface for DB access.

The underlying driver is loaded as a :class:`LazyPluggable`.

Functions in this module are imported into the manila.db namespace. Call these
functions from manila.db namespace, not the manila.db.api namespace.

All functions in this module return objects that implement a dictionary-like
interface. Currently, many of these objects are sqlalchemy objects that
implement a dictionary interface. However, a future goal is to have all of
these objects be simple dictionaries.


**Related Flags**

:backend:  string to lookup in the list of LazyPluggable backends.
           `sqlalchemy` is the only supported backend right now.

:connection:  string specifying the sqlalchemy connection to use, like:
              `sqlite:///var/lib/manila/manila.sqlite`.

:enable_new_services:  when adding a new service to the database, is it in the
                       pool of available hardware (Default: True)

"""
from oslo.config import cfg
from oslo.db import api as db_api


db_opts = [
    cfg.StrOpt('db_backend',
               default='sqlalchemy',
               help='The backend to use for database.'),
    cfg.BoolOpt('enable_new_services',
                default=True,
                help='Services to be added to the available pool on create.'),
    cfg.StrOpt('share_name_template',
               default='share-%s',
               help='Template string to be used to generate share names.'),
    cfg.StrOpt('share_snapshot_name_template',
               default='share-snapshot-%s',
               help='Template string to be used to generate share snapshot '
                    'names.'),
]

CONF = cfg.CONF
CONF.register_opts(db_opts)

_BACKEND_MAPPING = {'sqlalchemy': 'manila.db.sqlalchemy.api'}
IMPL = db_api.DBAPI.from_config(cfg.CONF, backend_mapping=_BACKEND_MAPPING,
                                lazy=True)


###################
def service_destroy(context, service_id):
    """Destroy the service or raise if it does not exist."""
    return IMPL.service_destroy(context, service_id)


def service_get(context, service_id):
    """Get a service or raise if it does not exist."""
    return IMPL.service_get(context, service_id)


def service_get_by_host_and_topic(context, host, topic):
    """Get a service by host it's on and topic it listens to."""
    return IMPL.service_get_by_host_and_topic(context, host, topic)


def service_get_all(context, disabled=None):
    """Get all services."""
    return IMPL.service_get_all(context, disabled)


def service_get_all_by_topic(context, topic):
    """Get all services for a given topic."""
    return IMPL.service_get_all_by_topic(context, topic)


def service_get_all_by_host(context, host):
    """Get all services for a given host."""
    return IMPL.service_get_all_by_host(context, host)


def service_get_all_share_sorted(context):
    """Get all share services sorted by share count.

    :returns: a list of (Service, share_count) tuples.

    """
    return IMPL.service_get_all_share_sorted(context)


def service_get_by_args(context, host, binary):
    """Get the state of an service by node name and binary."""
    return IMPL.service_get_by_args(context, host, binary)


def service_create(context, values):
    """Create a service from the values dictionary."""
    return IMPL.service_create(context, values)


def service_update(context, service_id, values):
    """Set the given properties on an service and update it.

    Raises NotFound if service does not exist.

    """
    return IMPL.service_update(context, service_id, values)


####################


def quota_create(context, project_id, resource, limit, user_id=None):
    """Create a quota for the given project and resource."""
    return IMPL.quota_create(context, project_id, resource, limit,
                             user_id=user_id)


def quota_get(context, project_id, resource, user_id=None):
    """Retrieve a quota or raise if it does not exist."""
    return IMPL.quota_get(context, project_id, resource, user_id=user_id)


def quota_get_all_by_project_and_user(context, project_id, user_id):
    """Retrieve all quotas associated with a given project and user."""
    return IMPL.quota_get_all_by_project_and_user(context, project_id, user_id)


def quota_get_all_by_project(context, project_id):
    """Retrieve all quotas associated with a given project."""
    return IMPL.quota_get_all_by_project(context, project_id)


def quota_get_all(context, project_id):
    """Retrieve all user quotas associated with a given project."""
    return IMPL.quota_get_all(context, project_id)


def quota_update(context, project_id, resource, limit, user_id=None):
    """Update a quota or raise if it does not exist."""
    return IMPL.quota_update(context, project_id, resource, limit,
                             user_id=user_id)


###################


def quota_class_create(context, class_name, resource, limit):
    """Create a quota class for the given name and resource."""
    return IMPL.quota_class_create(context, class_name, resource, limit)


def quota_class_get(context, class_name, resource):
    """Retrieve a quota class or raise if it does not exist."""
    return IMPL.quota_class_get(context, class_name, resource)


def quota_class_get_default(context):
    """Retrieve all default quotas."""
    return IMPL.quota_class_get_default(context)


def quota_class_get_all_by_name(context, class_name):
    """Retrieve all quotas associated with a given quota class."""
    return IMPL.quota_class_get_all_by_name(context, class_name)


def quota_class_update(context, class_name, resource, limit):
    """Update a quota class or raise if it does not exist."""
    return IMPL.quota_class_update(context, class_name, resource, limit)


###################


def quota_usage_get(context, project_id, resource, user_id=None):
    """Retrieve a quota usage or raise if it does not exist."""
    return IMPL.quota_usage_get(context, project_id, resource, user_id=user_id)


def quota_usage_get_all_by_project_and_user(context, project_id, user_id):
    """Retrieve all usage associated with a given resource."""
    return IMPL.quota_usage_get_all_by_project_and_user(context,
                                                        project_id, user_id)


def quota_usage_get_all_by_project(context, project_id):
    """Retrieve all usage associated with a given resource."""
    return IMPL.quota_usage_get_all_by_project(context, project_id)


def quota_usage_update(context, project_id, user_id, resource, **kwargs):
    """Update a quota usage or raise if it does not exist."""
    return IMPL.quota_usage_update(context, project_id, user_id, resource,
                                   **kwargs)


###################


def reservation_create(context, uuid, usage, project_id, user_id, resource,
                       delta, expire):
    """Create a reservation for the given project and resource."""
    return IMPL.reservation_create(context, uuid, usage, project_id,
                                   user_id, resource, delta, expire)


def reservation_get(context, uuid):
    """Retrieve a reservation or raise if it does not exist."""
    return IMPL.reservation_get(context, uuid)


###################


def quota_reserve(context, resources, quotas, user_quotas, deltas, expire,
                  until_refresh, max_age, project_id=None, user_id=None):
    """Check quotas and create appropriate reservations."""
    return IMPL.quota_reserve(context, resources, quotas, user_quotas, deltas,
                              expire, until_refresh, max_age,
                              project_id=project_id, user_id=user_id)


def reservation_commit(context, reservations, project_id=None, user_id=None):
    """Commit quota reservations."""
    return IMPL.reservation_commit(context, reservations,
                                   project_id=project_id,
                                   user_id=user_id)


def reservation_rollback(context, reservations, project_id=None, user_id=None):
    """Roll back quota reservations."""
    return IMPL.reservation_rollback(context, reservations,
                                     project_id=project_id,
                                     user_id=user_id)


def quota_destroy_all_by_project_and_user(context, project_id, user_id):
    """Destroy all quotas associated with a given project and user."""
    return IMPL.quota_destroy_all_by_project_and_user(context,
                                                      project_id, user_id)


def quota_destroy_all_by_project(context, project_id):
    """Destroy all quotas associated with a given project."""
    return IMPL.quota_destroy_all_by_project(context, project_id)


def reservation_expire(context):
    """Roll back any expired reservations."""
    return IMPL.reservation_expire(context)


###################


def share_create(context, values):
    """Create new share."""
    return IMPL.share_create(context, values)


def share_data_get_for_project(context, project_id, session=None):
    """Get (share_count, gigabytes) for project."""
    return IMPL.share_data_get_for_project(context, project_id)


def share_update(context, share_id, values):
    """Update share fields."""
    return IMPL.share_update(context, share_id, values)


def share_get(context, share_id):
    """Get share by id."""
    return IMPL.share_get(context, share_id)


def share_get_all(context, filters=None, sort_key=None, sort_dir=None):
    """Get all shares."""
    return IMPL.share_get_all(
        context, filters=filters, sort_key=sort_key, sort_dir=sort_dir,
    )


def share_get_all_by_host(context, host, filters=None, sort_key=None,
                          sort_dir=None):
    """Returns all shares with given host."""
    return IMPL.share_get_all_by_host(
        context, host, filters=filters, sort_key=sort_key, sort_dir=sort_dir,
    )


def share_get_all_by_project(context, project_id, filters=None, sort_key=None,
                             sort_dir=None):
    """Returns all shares with given project ID."""
    return IMPL.share_get_all_by_project(
        context, project_id, filters=filters, sort_key=sort_key,
        sort_dir=sort_dir,
    )


def share_get_all_by_share_server(context, share_server_id, filters=None,
                                  sort_key=None, sort_dir=None):
    """Returns all shares with given share server ID."""
    return IMPL.share_get_all_by_share_server(
        context, share_server_id, filters=filters, sort_key=sort_key,
        sort_dir=sort_dir,
    )


def share_delete(context, share_id):
    """Delete share."""
    return IMPL.share_delete(context, share_id)


###################


def share_access_create(context, values):
    """Allow access to share."""
    return IMPL.share_access_create(context, values)


def share_access_get(context, access_id):
    """Allow access to share."""
    return IMPL.share_access_get(context, access_id)


def share_access_get_all_for_share(context, share_id):
    """Allow access to share."""
    return IMPL.share_access_get_all_for_share(context, share_id)


def share_access_get_all_by_type_and_access(context, share_id, access_type,
                                            access):
    """Returns share access by given type and access."""
    return IMPL.share_access_get_all_by_type_and_access(
        context, share_id, access_type, access)


def share_access_delete(context, access_id):
    """Deny access to share."""
    return IMPL.share_access_delete(context, access_id)


def share_access_update(context, access_id, values):
    """Update access record."""
    return IMPL.share_access_update(context, access_id, values)


####################


def share_snapshot_create(context, values):
    """Create a snapshot from the values dictionary."""
    return IMPL.share_snapshot_create(context, values)


def snapshot_data_get_for_project(context, project_id, session=None):
    """Get (snapshot_count, gigabytes) for project."""
    return IMPL.snapshot_data_get_for_project(context, project_id)


def share_snapshot_destroy(context, snapshot_id):
    """Destroy the snapshot or raise if it does not exist."""
    return IMPL.share_snapshot_destroy(context, snapshot_id)


def share_snapshot_get(context, snapshot_id):
    """Get a snapshot or raise if it does not exist."""
    return IMPL.share_snapshot_get(context, snapshot_id)


def share_snapshot_get_all(context):
    """Get all snapshots."""
    return IMPL.share_snapshot_get_all(context)


def share_snapshot_get_all_by_project(context, project_id):
    """Get all snapshots belonging to a project."""
    return IMPL.share_snapshot_get_all_by_project(context, project_id)


def share_snapshot_get_all_for_share(context, share_id):
    """Get all snapshots for a share."""
    return IMPL.share_snapshot_get_all_for_share(context, share_id)


def share_snapshot_update(context, snapshot_id, values):
    """Set the given properties on an snapshot and update it.

    Raises NotFound if snapshot does not exist.
    """
    return IMPL.share_snapshot_update(context, snapshot_id, values)


def share_snapshot_data_get_for_project(context, project_id, session=None):
    """Get count and gigabytes used for snapshots for specified project."""
    return IMPL.share_snapshot_data_get_for_project(context,
                                                    project_id,
                                                    session=None)


###################
def security_service_create(context, values):
    """Create security service DB record."""
    return IMPL.security_service_create(context, values)


def security_service_delete(context, id):
    """Delete security service DB record."""
    return IMPL.security_service_delete(context, id)


def security_service_update(context, id, values):
    """Update security service DB record."""
    return IMPL.security_service_update(context, id, values)


def security_service_get(context, id):
    """Get security service DB record."""
    return IMPL.security_service_get(context, id)


def security_service_get_all(context):
    """Get all security service DB records."""
    return IMPL.security_service_get_all(context)


def security_service_get_all_by_project(context, project_id):
    """Get all security service DB records for the given project."""
    return IMPL.security_service_get_all_by_project(context, project_id)


####################


def share_metadata_get(context, share_id):
    """Get all metadata for a share."""
    return IMPL.share_metadata_get(context, share_id)


def share_metadata_delete(context, share_id, key):
    """Delete the given metadata item."""
    IMPL.share_metadata_delete(context, share_id, key)


def share_metadata_update(context, share, metadata, delete):
    """Update metadata if it exists, otherwise create it."""
    IMPL.share_metadata_update(context, share, metadata, delete)


###################
def share_network_create(context, values):
    """Create a share network DB record."""
    return IMPL.share_network_create(context, values)


def share_network_delete(context, id):
    """Delete a share network DB record."""
    return IMPL.share_network_delete(context, id)


def share_network_update(context, id, values):
    """Update a share network DB record."""
    return IMPL.share_network_update(context, id, values)


def share_network_get(context, id):
    """Get requested share network DB record."""
    return IMPL.share_network_get(context, id)


def share_network_get_all(context):
    """Get all share network DB records."""
    return IMPL.share_network_get_all(context)


def share_network_get_all_by_project(context, project_id):
    """Get all share network DB records for the given project."""
    return IMPL.share_network_get_all_by_project(context, project_id)


def share_network_get_all_by_security_service(context, share_network_id):
    """Get all share network DB records for the given project."""
    return IMPL.share_network_get_all_by_security_service(
        context, share_network_id)


def share_network_add_security_service(context, id, security_service_id):
    return IMPL.share_network_add_security_service(context,
                                                   id,
                                                   security_service_id)


def share_network_remove_security_service(context, id, security_service_id):
    return IMPL.share_network_remove_security_service(context,
                                                      id,
                                                      security_service_id)


def network_allocation_create(context, values):
    """Create a network allocation DB record."""
    return IMPL.network_allocation_create(context, values)


def network_allocation_delete(context, id):
    """Delete a network allocation DB record."""
    return IMPL.network_allocation_delete(context, id)


def network_allocation_update(context, id, values):
    """Update a network allocation DB record."""
    return IMPL.network_allocation_update(context, id, values)


def network_allocations_get_for_share_server(context, share_server_id,
                                             session=None):
    """Get network allocation for share server."""
    return IMPL.network_allocations_get_for_share_server(context,
                                                         share_server_id,
                                                         session=session)


##################


def share_server_create(context, values):
    """Create share server DB record."""
    return IMPL.share_server_create(context, values)


def share_server_delete(context, id):
    """Delete share server DB record."""
    return IMPL.share_server_delete(context, id)


def share_server_update(context, id, values):
    """Update share server DB record."""
    return IMPL.share_server_update(context, id, values)


def share_server_get(context, id, session=None):
    """Get share server DB record by ID."""
    return IMPL.share_server_get(context, id, session=session)


def share_server_get_by_host(context, host, share_net_id, session=None):
    """Get share server DB records by host."""
    return IMPL.share_server_get_by_host(context, host, share_net_id,
                                         session=session)


def share_server_get_by_host_and_share_net(context, host, share_net_id,
                                           session=None):
    """Get share server DB records by host and share net."""
    return IMPL.share_server_get_by_host_and_share_net(context, host,
                                                       share_net_id,
                                                       session=session)


def share_server_get_by_host_and_share_net_valid(context, host,
                                                 share_net_id,
                                                 session=None):
    """Get share server DB records by host and share net not error."""
    return IMPL.share_server_get_by_host_and_share_net_valid(context,
                                                             host,
                                                             share_net_id,
                                                             session=session)


def share_server_get_all(context):
    """Get all share server DB records."""
    return IMPL.share_server_get_all(context)


def share_server_backend_details_set(context, share_server_id, server_details):
    """Create DB record with backend details."""
    return IMPL.share_server_backend_details_set(context, share_server_id,
                                                 server_details)


def share_server_backend_details_get(context, share_server_id):
    """Get all backend details records for share server."""
    return IMPL.share_server_backend_details_get(context, share_server_id)


##################


def volume_type_create(context, values):
    """Create a new volume type."""
    return IMPL.volume_type_create(context, values)


def volume_type_get_all(context, inactive=False):
    """Get all volume types."""
    return IMPL.volume_type_get_all(context, inactive)


def volume_type_get(context, id, inactive=False):
    """Get volume type by id."""
    return IMPL.volume_type_get(context, id, inactive)


def volume_type_get_by_name(context, name):
    """Get volume type by name."""
    return IMPL.volume_type_get_by_name(context, name)


def volume_type_qos_specs_get(context, type_id):
    """Get all qos specs for given volume type."""
    return IMPL.volume_type_qos_specs_get(context, type_id)


def volume_type_destroy(context, id):
    """Delete a volume type."""
    return IMPL.volume_type_destroy(context, id)


def volume_get_active_by_window(context, begin, end=None, project_id=None):
    """Get all the volumes inside the window.

    Specifying a project_id will filter for a certain project.
    """
    return IMPL.volume_get_active_by_window(context, begin, end, project_id)


####################


def volume_type_extra_specs_get(context, volume_type_id):
    """Get all extra specs for a volume type."""
    return IMPL.volume_type_extra_specs_get(context, volume_type_id)


def volume_type_extra_specs_delete(context, volume_type_id, key):
    """Delete the given extra specs item."""
    return IMPL.volume_type_extra_specs_delete(context, volume_type_id, key)


def volume_type_extra_specs_update_or_create(context,
                                             volume_type_id,
                                             extra_specs):
    """Create or update volume type extra specs.

    This adds or modifies the key/value pairs specified in the extra
    specs dict argument.
    """
    return IMPL.volume_type_extra_specs_update_or_create(context,
                                                         volume_type_id,
                                                         extra_specs)
