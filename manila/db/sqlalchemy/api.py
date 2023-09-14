# Copyright (c) 2011 X.commerce, a business unit of eBay Inc.
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright (c) 2014 Mirantis, Inc.
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

"""Implementation of SQLAlchemy backend."""

import copy
import datetime
from functools import wraps
import ipaddress
import sys
import warnings

# NOTE(uglide): Required to override default oslo_db Query class
import manila.db.sqlalchemy.query  # noqa

from oslo_config import cfg
from oslo_db import api as oslo_db_api
from oslo_db import exception as db_exc
from oslo_db import exception as db_exception
from oslo_db import options as db_options
from oslo_db.sqlalchemy import enginefacade
from oslo_db.sqlalchemy import utils as db_utils
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import strutils
from oslo_utils import timeutils
from oslo_utils import uuidutils
from sqlalchemy import and_
from sqlalchemy import MetaData
from sqlalchemy import or_
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import subqueryload
from sqlalchemy.sql.expression import false
from sqlalchemy.sql.expression import literal
from sqlalchemy.sql.expression import true
from sqlalchemy.sql import func

from manila.common import constants
from manila.db.sqlalchemy import models
from manila.db.sqlalchemy import utils
from manila import exception
from manila.i18n import _
from manila import quota

osprofiler_sqlalchemy = importutils.try_import('osprofiler.sqlalchemy')

CONF = cfg.CONF
CONF.import_group("profiler", "manila.service")

LOG = log.getLogger(__name__)
QUOTAS = quota.QUOTAS

_DEFAULT_QUOTA_NAME = 'default'
PER_PROJECT_QUOTAS = []

_DEFAULT_SQL_CONNECTION = 'sqlite://'
db_options.set_defaults(cfg.CONF,
                        connection=_DEFAULT_SQL_CONNECTION)

context_manager = enginefacade.transaction_context()

# FIXME(stephenfin): we need to remove reliance on autocommit semantics ASAP
# since it's not compatible with SQLAlchemy 2.0
context_manager.configure(__autocommit=True)


def get_engine():
    return context_manager._factory.get_legacy_facade().get_engine()


def get_session(**kwargs):
    return context_manager._factory.get_legacy_facade().get_session(**kwargs)


def get_backend():
    """The backend is this module itself."""

    return sys.modules[__name__]


def is_admin_context(context):
    """Indicates if the request context is an administrator."""
    if not context:
        warnings.warn(_('Use of empty request context is deprecated'),
                      DeprecationWarning)
        raise Exception('die')
    return context.is_admin


def is_user_context(context):
    """Indicates if the request context is a normal user."""
    if not context:
        return False
    if context.is_admin:
        return False
    if not context.user_id or not context.project_id:
        return False
    return True


def authorize_project_context(context, project_id):
    """Ensures a request has permission to access the given project."""
    if is_user_context(context):
        if not context.project_id:
            raise exception.NotAuthorized()
        elif context.project_id != project_id:
            raise exception.NotAuthorized()


def authorize_user_context(context, user_id):
    """Ensures a request has permission to access the given user."""
    if is_user_context(context):
        if not context.user_id:
            raise exception.NotAuthorized()
        elif context.user_id != user_id:
            raise exception.NotAuthorized()


def authorize_quota_class_context(context, class_name):
    """Ensures a request has permission to access the given quota class."""
    if is_user_context(context):
        if not context.quota_class:
            raise exception.NotAuthorized()
        elif context.quota_class != class_name:
            raise exception.NotAuthorized()


def require_admin_context(f):
    """Decorator to require admin request context.

    The first argument to the wrapped function must be the context.

    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_admin_context(args[0]):
            raise exception.AdminRequired()
        return f(*args, **kwargs)
    return wrapper


def require_context(f):
    """Decorator to require *any* user or admin context.

    This does no authorization for user or project access matching, see
    :py:func:`authorize_project_context` and
    :py:func:`authorize_user_context`.

    The first argument to the wrapped function must be the context.

    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_admin_context(args[0]) and not is_user_context(args[0]):
            raise exception.NotAuthorized()
        return f(*args, **kwargs)
    return wrapper


def require_share_exists(f):
    """Decorator to require the specified share to exist.

    Requires the wrapped function to use context and share_id as
    their first two arguments.
    """
    @wraps(f)
    def wrapper(context, share_id, *args, **kwargs):
        share_get(context, share_id)
        return f(context, share_id, *args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


def require_share_snapshot_exists(f):
    """Decorator to require the specified share snapshot to exist.

    Requires the wrapped function to use context and share_snapshot_id as
    their first two arguments.
    """
    @wraps(f)
    def wrapper(context, share_snapshot_id, *args, **kwargs):
        share_snapshot_get(context, share_snapshot_id)
        return f(context, share_snapshot_id, *args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


def require_share_network_subnet_exists(f):
    """Decorator to require the specified share network subnet to exist.

    Requires the wrapped function to use context and share_network_subnet_id
    as their first two arguments.
    """
    @wraps(f)
    def wrapper(context, share_network_subnet_id, *args, **kwargs):
        share_network_subnet_get(context, share_network_subnet_id)
        return f(context, share_network_subnet_id, *args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


def require_share_instance_exists(f):
    """Decorator to require the specified share instance to exist.

    Requires the wrapped function to use context and share_instance_id as
    their first two arguments.
    """
    @wraps(f)
    def wrapper(context, share_instance_id, *args, **kwargs):
        share_instance_get(context, share_instance_id)
        return f(context, share_instance_id, *args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


def apply_sorting(model, query, sort_key, sort_dir):
    if sort_dir.lower() not in ('desc', 'asc'):
        msg = _("Wrong sorting data provided: sort key is '%(sort_key)s' "
                "and sort direction is '%(sort_dir)s'.") % {
                    "sort_key": sort_key, "sort_dir": sort_dir}
        raise exception.InvalidInput(reason=msg)

    # NOTE(maaoyu): We add the additional sort by ID in this case to
    # get deterministic results. Without the ordering by ID this could
    # lead to flapping return lists.
    sort_keys = [sort_key]
    if sort_key != 'id':
        sort_keys.append('id')

    for sort_key in sort_keys:
        sort_attr = getattr(model, sort_key)
        sort_method = getattr(sort_attr, sort_dir.lower())
        query = query.order_by(sort_method())

    return query


def handle_db_data_error(f):
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except db_exc.DBDataError:
            msg = _('Error writing field to database.')
            LOG.exception(msg)
            raise exception.Invalid(msg)

    return wrapper


def model_query(context, model, *args, **kwargs):
    """Query helper that accounts for context's `read_deleted` field.

    :param context: context to query under
    :param model: model to query. Must be a subclass of ModelBase.
    :param session: if present, the session to use
    :param read_deleted: if present, overrides context's read_deleted field.
    :param project_only: if present and context is user-type, then restrict
            query to match the context's project_id.
    """
    session = kwargs.get('session')

    if hasattr(context, 'session') and context.session:
        session = context.session

    if not session:
        session = get_session()

    read_deleted = kwargs.get('read_deleted') or context.read_deleted
    project_only = kwargs.get('project_only')
    kwargs = dict()

    if project_only and not context.is_admin:
        kwargs['project_id'] = context.project_id
    if read_deleted in ('no', 'n', False):
        kwargs['deleted'] = False
    elif read_deleted == 'only':
        kwargs['deleted'] = True
    elif read_deleted in ('yes', 'y', True):
        pass

    return db_utils.model_query(
        model=model,
        session=session,
        args=args,
        **kwargs,
    )


def _process_model_like_filter(model, query, filters):
    """Applies regex expression filtering to a query.

    :param model: model to apply filters to
    :param query: query to apply filters to
    :param filters: dictionary of filters with regex values
    :returns: the updated query.
    """
    if query is None:
        return query

    if filters:
        for key in sorted(filters):
            column_attr = getattr(model, key)
            if 'property' == type(column_attr).__name__:
                continue
            value = filters[key]
            if not (isinstance(value, (str, int))):
                continue
            query = query.filter(
                column_attr.op('LIKE')(u'%%%s%%' % value))
    return query


def apply_like_filters(process_exact_filters):
    def _decorator(query, model, filters, legal_keys):
        exact_filters = filters.copy()
        regex_filters = {}
        for key, value in filters.items():
            if key not in legal_keys:
                # Skip ones we're not filtering on
                continue
            # NOTE(haixin): For inexact match, the filter keys
            # are in the format of 'key~=value'
            if key.endswith('~'):
                exact_filters.pop(key)
                regex_filters[key.rstrip('~')] = value
        query = process_exact_filters(query, model, exact_filters,
                                      legal_keys)
        return _process_model_like_filter(model, query, regex_filters)
    return _decorator


@apply_like_filters
def exact_filter(query, model, filters, legal_keys,
                 created_at_key='created_at'):
    """Applies exact match filtering to a query.

    Returns the updated query.  Modifies filters argument to remove
    filters consumed.

    :param query: query to apply filters to
    :param model: model object the query applies to, for IN-style
                  filtering
    :param filters: dictionary of filters; values that are lists,
                    tuples, sets, or frozensets cause an 'IN' test to
                    be performed, while exact matching ('==' operator)
                    is used for other values
    :param legal_keys: list of keys to apply exact filtering to
    """

    filter_dict = {}
    created_at_attr = getattr(model, created_at_key, None)
    # Walk through all the keys
    for key in legal_keys:
        # Skip ones we're not filtering on
        if key not in filters:
            continue

        # OK, filtering on this key; what value do we search for?
        value = filters.pop(key)

        if key == 'created_since' and created_at_attr:
            # This is a reserved query parameter to indicate resources created
            # after a particular datetime
            value = timeutils.normalize_time(value)
            query = query.filter(created_at_attr.op('>=')(value))
        elif key == 'created_before' and created_at_attr:
            # This is a reserved query parameter to indicate resources created
            # before a particular datetime
            value = timeutils.normalize_time(value)
            query = query.filter(created_at_attr.op('<=')(value))
        elif isinstance(value, (list, tuple, set, frozenset)):
            # Looking for values in a list; apply to query directly
            column_attr = getattr(model, key)
            query = query.filter(column_attr.in_(value))
        else:
            # OK, simple exact match; save for later
            filter_dict[key] = value

    # Apply simple exact matches
    if filter_dict:
        query = query.filter_by(**filter_dict)

    return query


def ensure_model_dict_has_id(model_dict):
    if not model_dict.get('id'):
        model_dict['id'] = uuidutils.generate_uuid()
    return model_dict


def _sync_shares(context, project_id, user_id, share_type_id=None):
    shares, _ = _share_data_get_for_project(
        context, project_id, user_id, share_type_id=share_type_id,
    )
    return {'shares': shares}


def _sync_snapshots(context, project_id, user_id, share_type_id=None):
    snapshots, _ = _snapshot_data_get_for_project(
        context, project_id, user_id, share_type_id=share_type_id,
    )
    return {'snapshots': snapshots}


def _sync_gigabytes(context, project_id, user_id, share_type_id=None):
    _, share_gigs = _share_data_get_for_project(
        context, project_id, user_id, share_type_id=share_type_id,
    )
    return {'gigabytes': share_gigs}


def _sync_snapshot_gigabytes(context, project_id, user_id, share_type_id=None):
    _, snapshot_gigs = _snapshot_data_get_for_project(
        context, project_id, user_id, share_type_id=share_type_id,
    )
    return {'snapshot_gigabytes': snapshot_gigs}


def _sync_share_networks(context, project_id, user_id, share_type_id=None):
    share_networks_count = _count_share_networks(
        context, project_id, user_id, share_type_id=share_type_id,
    )
    return {'share_networks': share_networks_count}


def _sync_share_groups(context, project_id, user_id, share_type_id=None):
    share_groups_count = _count_share_groups(
        context, project_id, user_id, share_type_id=share_type_id,
    )
    return {'share_groups': share_groups_count}


def _sync_backups(context, project_id, user_id, share_type_id=None):
    backups, _ = _backup_data_get_for_project(context, project_id, user_id)
    return {'backups': backups}


def _sync_backup_gigabytes(context, project_id, user_id, share_type_id=None):
    _, backup_gigs = _backup_data_get_for_project(context, project_id, user_id)
    return {'backup_gigabytes': backup_gigs}


def _sync_share_group_snapshots(
    context, project_id, user_id, share_type_id=None,
):
    share_group_snapshots_count = _count_share_group_snapshots(
        context, project_id, user_id, share_type_id=share_type_id,
    )
    return {'share_group_snapshots': share_group_snapshots_count}


def _sync_share_replicas(context, project_id, user_id, share_type_id=None):
    share_replicas_count, _ = _share_replica_data_get_for_project(
        context, project_id, user_id, share_type_id=share_type_id,
    )
    return {'share_replicas': share_replicas_count}


def _sync_replica_gigabytes(context, project_id, user_id, share_type_id=None):
    _, replica_gigs = _share_replica_data_get_for_project(
        context, project_id, user_id, share_type_id=share_type_id,
    )
    return {'replica_gigabytes': replica_gigs}


QUOTA_SYNC_FUNCTIONS = {
    '_sync_shares': _sync_shares,
    '_sync_snapshots': _sync_snapshots,
    '_sync_gigabytes': _sync_gigabytes,
    '_sync_snapshot_gigabytes': _sync_snapshot_gigabytes,
    '_sync_share_networks': _sync_share_networks,
    '_sync_share_groups': _sync_share_groups,
    '_sync_share_group_snapshots': _sync_share_group_snapshots,
    '_sync_share_replicas': _sync_share_replicas,
    '_sync_replica_gigabytes': _sync_replica_gigabytes,
    '_sync_backups': _sync_backups,
    '_sync_backup_gigabytes': _sync_backup_gigabytes,
}


###################

@require_admin_context
@context_manager.writer
def share_resources_host_update(context, current_host, new_host):
    """Updates the 'host' attribute of resources"""

    resources = {
        'instances': models.ShareInstance,
        'servers': models.ShareServer,
        'groups': models.ShareGroup,
    }
    result = {}

    for res_name, res_model in resources.items():
        host_field = res_model.host
        query = model_query(
            context, res_model, read_deleted="no",
        ).filter(host_field.like('{}%'.format(current_host)))
        count = query.update(
            {host_field: func.replace(host_field, current_host, new_host)},
            synchronize_session=False,
        )
        result.update({res_name: count})
    return result


###################


@require_admin_context
@context_manager.writer
def service_destroy(context, service_id):
    service_ref = _service_get(context, service_id)
    service_ref.soft_delete(context.session)


@require_admin_context
def _service_get(context, service_id):
    result = (
        model_query(
            context,
            models.Service,
        ).filter_by(
            id=service_id,
        ).first()
    )
    if not result:
        raise exception.ServiceNotFound(service_id=service_id)

    return result


@require_admin_context
@context_manager.reader
def service_get(context, service_id):
    return _service_get(context, service_id)


@require_admin_context
@context_manager.reader
def service_get_all(context, disabled=None):
    query = model_query(context, models.Service)

    if disabled is not None:
        query = query.filter_by(disabled=disabled)

    return query.all()


@require_admin_context
@context_manager.reader
def service_get_all_by_topic(context, topic):
    return (model_query(
        context, models.Service, read_deleted="no").
        filter_by(disabled=False).
        filter_by(topic=topic).
        all())


@require_admin_context
@context_manager.reader
def service_get_by_host_and_topic(context, host, topic):
    result = (model_query(
        context, models.Service, read_deleted="no").
        filter_by(disabled=False).
        filter_by(host=host).
        filter_by(topic=topic).
        first())
    if not result:
        raise exception.ServiceNotFound(service_id=host)
    return result


@require_admin_context
def _service_get_all_topic_subquery(context, topic, subq, label):
    sort_value = getattr(subq.c, label)
    return (
        model_query(
            context, models.Service,
            func.coalesce(sort_value, 0),
            read_deleted="no",
        ).filter_by(
            topic=topic,
        ).filter_by(
            disabled=False,
        ).outerjoin(
            (subq, models.Service.host == subq.c.host)
        ).order_by(
            sort_value
        ).all()
    )


@require_admin_context
@context_manager.reader
def service_get_all_share_sorted(context):
    topic = CONF.share_topic
    label = 'share_gigabytes'
    subq = (
        model_query(
            context,
            models.Share,
            func.sum(models.Share.size).label(label),
            read_deleted="no",
        ).join(
            models.ShareInstance,
            models.ShareInstance.share_id == models.Share.id,
        ).group_by(
            models.ShareInstance.host
        ).subquery()
    )
    return _service_get_all_topic_subquery(
        context,
        topic,
        subq,
        label,
    )


@require_admin_context
@context_manager.reader
def service_get_by_args(context, host, binary):
    result = (model_query(context, models.Service).
              filter_by(host=host).
              filter_by(binary=binary).
              first())

    if not result:
        raise exception.HostBinaryNotFound(host=host, binary=binary)

    return result


@require_admin_context
@context_manager.writer
def service_create(context, values):
    _ensure_availability_zone_exists(context, values)

    service_ref = models.Service()
    service_ref.update(values)
    if not CONF.enable_new_services:
        service_ref.disabled = True

    service_ref.save(context.session)
    return service_ref


@require_admin_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
@context_manager.writer
def service_update(context, service_id, values):
    _ensure_availability_zone_exists(context, values, strict=False)

    service_ref = _service_get(context, service_id)
    service_ref.update(values)
    service_ref.save(context.session)


###################


@require_context
@context_manager.reader
def quota_get_all_by_project_and_user(context, project_id, user_id):
    authorize_project_context(context, project_id)
    user_quotas = model_query(
        context, models.ProjectUserQuota,
        models.ProjectUserQuota.resource,
        models.ProjectUserQuota.hard_limit,
    ).filter_by(
        project_id=project_id,
    ).filter_by(
        user_id=user_id,
    ).all()

    result = {'project_id': project_id, 'user_id': user_id}
    for u_quota in user_quotas:
        result[u_quota.resource] = u_quota.hard_limit
    return result


@require_context
@context_manager.reader
def quota_get_all_by_project_and_share_type(
    context, project_id, share_type_id,
):
    authorize_project_context(context, project_id)
    share_type_quotas = model_query(
        context, models.ProjectShareTypeQuota,
        models.ProjectShareTypeQuota.resource,
        models.ProjectShareTypeQuota.hard_limit,
    ).filter_by(
        project_id=project_id,
    ).filter_by(
        share_type_id=share_type_id,
    ).all()

    result = {
        'project_id': project_id,
        'share_type_id': share_type_id,
    }
    for st_quota in share_type_quotas:
        result[st_quota.resource] = st_quota.hard_limit
    return result


@require_context
@context_manager.reader
def quota_get_all_by_project(context, project_id):
    authorize_project_context(context, project_id)
    project_quotas = model_query(
        context, models.Quota, read_deleted="no",
    ).filter_by(
        project_id=project_id,
    ).all()

    result = {'project_id': project_id}
    for p_quota in project_quotas:
        result[p_quota.resource] = p_quota.hard_limit
    return result


@require_context
@context_manager.reader
def quota_get_all(context, project_id):
    authorize_project_context(context, project_id)

    result = (model_query(context, models.ProjectUserQuota).
              filter_by(project_id=project_id).
              all())

    return result


@require_admin_context
@context_manager.writer
def quota_create(
    context,
    project_id,
    resource,
    limit,
    user_id=None,
    share_type_id=None,
):
    per_user = user_id and resource not in PER_PROJECT_QUOTAS

    if per_user:
        check = model_query(context, models.ProjectUserQuota).filter(
            models.ProjectUserQuota.project_id == project_id,
            models.ProjectUserQuota.user_id == user_id,
            models.ProjectUserQuota.resource == resource,
        ).all()
        quota_ref = models.ProjectUserQuota()
        quota_ref.user_id = user_id
    elif share_type_id:
        check = model_query(context, models.ProjectShareTypeQuota).filter(
            models.ProjectShareTypeQuota.project_id == project_id,
            models.ProjectShareTypeQuota.share_type_id == share_type_id,
            models.ProjectShareTypeQuota.resource == resource,
        ).all()
        quota_ref = models.ProjectShareTypeQuota()
        quota_ref.share_type_id = share_type_id
    else:
        check = model_query(context, models.Quota).filter(
            models.Quota.project_id == project_id,
            models.Quota.resource == resource,
        ).all()
        quota_ref = models.Quota()
    if check:
        raise exception.QuotaExists(project_id=project_id, resource=resource)

    quota_ref.project_id = project_id
    quota_ref.resource = resource
    quota_ref.hard_limit = limit
    try:
        quota_ref.save(context.session)
    except Exception as e:
        if "out of range" in str(e).lower():
            msg = _("Quota limit should not exceed 2147483647")
            raise exception.InvalidInput(reason=msg)
        raise
    return quota_ref


@require_admin_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
@context_manager.writer
def quota_update(
    context,
    project_id,
    resource,
    limit,
    user_id=None,
    share_type_id=None,
):
    per_user = user_id and resource not in PER_PROJECT_QUOTAS
    if per_user:
        query = model_query(context, models.ProjectUserQuota).filter(
            models.ProjectUserQuota.project_id == project_id,
            models.ProjectUserQuota.user_id == user_id,
            models.ProjectUserQuota.resource == resource,
        )
    elif share_type_id:
        query = model_query(context, models.ProjectShareTypeQuota).filter(
            models.ProjectShareTypeQuota.project_id == project_id,
            models.ProjectShareTypeQuota.share_type_id == share_type_id,
            models.ProjectShareTypeQuota.resource == resource,
        )
    else:
        query = model_query(context, models.Quota).filter(
            models.Quota.project_id == project_id,
            models.Quota.resource == resource,
        )

    result = query.update({'hard_limit': limit})
    if not result:
        if per_user:
            raise exception.ProjectUserQuotaNotFound(
                project_id=project_id, user_id=user_id)
        elif share_type_id:
            raise exception.ProjectShareTypeQuotaNotFound(
                project_id=project_id, share_type=share_type_id)
        raise exception.ProjectQuotaNotFound(project_id=project_id)


###################


@require_context
@context_manager.reader
def quota_class_get(context, class_name, resource):
    result = (
        model_query(
            context,
            models.QuotaClass,
            read_deleted="no",
        ).filter_by(
            class_name=class_name
        ).filter_by(
            resource=resource
        ).first()
    )

    if not result:
        raise exception.QuotaClassNotFound(class_name=class_name)

    return result


@require_context
@context_manager.reader
def quota_class_get_default(context):
    rows = (model_query(context, models.QuotaClass, read_deleted="no").
            filter_by(class_name=_DEFAULT_QUOTA_NAME).
            all())

    result = {'class_name': _DEFAULT_QUOTA_NAME}
    for row in rows:
        result[row.resource] = row.hard_limit

    return result


@require_context
@context_manager.reader
def quota_class_get_all_by_name(context, class_name):
    authorize_quota_class_context(context, class_name)

    rows = (model_query(context, models.QuotaClass, read_deleted="no").
            filter_by(class_name=class_name).
            all())

    result = {'class_name': class_name}
    for row in rows:
        result[row.resource] = row.hard_limit

    return result


@require_admin_context
@context_manager.writer
def quota_class_create(context, class_name, resource, limit):
    quota_class_ref = models.QuotaClass()
    quota_class_ref.class_name = class_name
    quota_class_ref.resource = resource
    quota_class_ref.hard_limit = limit
    quota_class_ref.save(context.session)
    return quota_class_ref


@require_admin_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
@context_manager.writer
def quota_class_update(context, class_name, resource, limit):
    result = (model_query(context, models.QuotaClass, read_deleted="no").
              filter_by(class_name=class_name).
              filter_by(resource=resource).
              update({'hard_limit': limit}))

    if not result:
        raise exception.QuotaClassNotFound(class_name=class_name)


###################


@require_context
@context_manager.reader
def quota_usage_get(context, project_id, resource, user_id=None,
                    share_type_id=None):
    query = (model_query(context, models.QuotaUsage, read_deleted="no").
             filter_by(project_id=project_id).
             filter_by(resource=resource))
    if user_id:
        if resource not in PER_PROJECT_QUOTAS:
            result = query.filter_by(user_id=user_id).first()
        else:
            result = query.filter_by(user_id=None).first()
    elif share_type_id:
        result = query.filter_by(queryshare_type_id=share_type_id).first()
    else:
        result = query.first()

    if not result:
        raise exception.QuotaUsageNotFound(project_id=project_id)

    return result


def _quota_usage_get_all(context, project_id, user_id=None,
                         share_type_id=None):
    authorize_project_context(context, project_id)
    query = (model_query(context, models.QuotaUsage, read_deleted="no").
             filter_by(project_id=project_id))
    result = {'project_id': project_id}
    if user_id:
        query = query.filter(or_(models.QuotaUsage.user_id == user_id,
                                 models.QuotaUsage.user_id is None))
        result['user_id'] = user_id
    elif share_type_id:
        query = query.filter_by(share_type_id=share_type_id)
        result['share_type_id'] = share_type_id
    else:
        query = query.filter_by(share_type_id=None)

    rows = query.all()
    for row in rows:
        if row.resource in result:
            result[row.resource]['in_use'] += row.in_use
            result[row.resource]['reserved'] += row.reserved
        else:
            result[row.resource] = dict(in_use=row.in_use,
                                        reserved=row.reserved)

    return result


@require_context
@context_manager.reader
def quota_usage_get_all_by_project(context, project_id):
    return _quota_usage_get_all(context, project_id)


@require_context
@context_manager.reader
def quota_usage_get_all_by_project_and_user(context, project_id, user_id):
    return _quota_usage_get_all(context, project_id, user_id=user_id)


@require_context
@context_manager.reader
def quota_usage_get_all_by_project_and_share_type(context, project_id,
                                                  share_type_id):
    return _quota_usage_get_all(
        context, project_id, share_type_id=share_type_id)


def _quota_usage_create(context, project_id, user_id, resource, in_use,
                        reserved, until_refresh, share_type_id=None):
    quota_usage_ref = models.QuotaUsage()
    if share_type_id:
        quota_usage_ref.share_type_id = share_type_id
    else:
        quota_usage_ref.user_id = user_id
    quota_usage_ref.project_id = project_id
    quota_usage_ref.resource = resource
    quota_usage_ref.in_use = in_use
    quota_usage_ref.reserved = reserved
    quota_usage_ref.until_refresh = until_refresh
    # updated_at is needed for judgement of max_age
    quota_usage_ref.updated_at = timeutils.utcnow()

    quota_usage_ref.save(session=context.session)

    return quota_usage_ref


@require_admin_context
@context_manager.writer
def quota_usage_create(context, project_id, user_id, resource, in_use,
                       reserved, until_refresh, share_type_id=None):
    return _quota_usage_create(
        context,
        project_id,
        user_id,
        resource,
        in_use,
        reserved,
        until_refresh,
        share_type_id=share_type_id,
    )


@require_admin_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
@context_manager.writer
def quota_usage_update(context, project_id, user_id, resource,
                       share_type_id=None, **kwargs):
    updates = {}
    for key in ('in_use', 'reserved', 'until_refresh'):
        if key in kwargs:
            updates[key] = kwargs[key]

    query = model_query(
        context, models.QuotaUsage, read_deleted="no",
    ).filter_by(project_id=project_id).filter_by(resource=resource)
    if share_type_id:
        query = query.filter_by(share_type_id=share_type_id)
    else:
        query = query.filter(or_(models.QuotaUsage.user_id == user_id,
                                 models.QuotaUsage.user_id is None))
    result = query.update(updates)

    if not result:
        raise exception.QuotaUsageNotFound(project_id=project_id)


###################


def _reservation_create(context, uuid, usage, project_id, user_id, resource,
                        delta, expire, share_type_id=None):
    reservation_ref = models.Reservation()
    reservation_ref.uuid = uuid
    reservation_ref.usage_id = usage['id']
    reservation_ref.project_id = project_id
    if share_type_id:
        reservation_ref.share_type_id = share_type_id
    else:
        reservation_ref.user_id = user_id
    reservation_ref.resource = resource
    reservation_ref.delta = delta
    reservation_ref.expire = expire
    reservation_ref.save(session=context.session)
    return reservation_ref


###################


# NOTE(johannes): The quota code uses SQL locking to ensure races don't
# cause under or over counting of resources. To avoid deadlocks, this
# code always acquires the lock on quota_usages before acquiring the lock
# on reservations.

def _get_share_type_quota_usages(context, project_id, share_type_id):
    rows = model_query(
        context, models.QuotaUsage, read_deleted="no",
    ).filter(
        models.QuotaUsage.project_id == project_id,
        models.QuotaUsage.share_type_id == share_type_id,
    ).with_for_update().all()
    return {row.resource: row for row in rows}


def _get_user_quota_usages(context, project_id, user_id):
    # Broken out for testability
    rows = model_query(
        context, models.QuotaUsage, read_deleted="no",
    ).filter_by(
        project_id=project_id,
    ).filter(
        or_(
            models.QuotaUsage.user_id == user_id,
            models.QuotaUsage.user_id is None,
        )
    ).with_for_update().all()
    return {row.resource: row for row in rows}


def _get_project_quota_usages(context, project_id):
    rows = model_query(
        context, models.QuotaUsage, read_deleted="no",
    ).filter_by(
        project_id=project_id,
    ).filter(
        models.QuotaUsage.share_type_id is None,
    ).with_for_update().all()
    result = dict()
    # Get the total count of in_use,reserved
    for row in rows:
        if row.resource in result:
            result[row.resource]['in_use'] += row.in_use
            result[row.resource]['reserved'] += row.reserved
            result[row.resource]['total'] += (row.in_use + row.reserved)
        else:
            result[row.resource] = dict(
                in_use=row.in_use,
                reserved=row.reserved,
                total=row.in_use + row.reserved,
            )
    return result


# NOTE(stephenfin): We intentionally don't wrap the outer function here since
# we call the innter function multiple times and want each call to be in a
# separate transaction
@require_context
def quota_reserve(context, resources, project_quotas, user_quotas,
                  share_type_quotas, deltas, expire, until_refresh,
                  max_age, project_id=None, user_id=None, share_type_id=None,
                  overquota_allowed=False):
    user_reservations = _quota_reserve(
        context, resources, project_quotas, user_quotas,
        deltas, expire, until_refresh, max_age, project_id, user_id=user_id,
        overquota_allowed=overquota_allowed)
    if share_type_id:
        try:
            st_reservations = _quota_reserve(
                context, resources, project_quotas, share_type_quotas,
                deltas, expire, until_refresh, max_age, project_id,
                share_type_id=share_type_id,
                overquota_allowed=overquota_allowed)
        except exception.OverQuota:
            # rollback previous reservations
            with excutils.save_and_reraise_exception():
                # We call a public method since we haven't wrapped this, the
                # caller, and we want to run in a different transaction
                reservation_rollback(
                    context, user_reservations,
                    project_id=project_id, user_id=user_id)
        return user_reservations + st_reservations
    return user_reservations


# NOTE(stephenfin): Per above, we wrap the inner method here
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
@context_manager.writer
def _quota_reserve(context, resources, project_quotas, user_or_st_quotas,
                   deltas, expire, until_refresh,
                   max_age, project_id=None, user_id=None, share_type_id=None,
                   overquota_allowed=False):
    elevated = context.elevated()

    if project_id is None:
        project_id = context.project_id
    if share_type_id:
        user_or_st_usages = _get_share_type_quota_usages(
            context, project_id, share_type_id,
        )
    else:
        user_id = user_id if user_id else context.user_id
        user_or_st_usages = _get_user_quota_usages(
            context, project_id, user_id,
        )

    # Get the current usages
    project_usages = _get_project_quota_usages(context, project_id)

    # Handle usage refresh
    work = set(deltas.keys())
    while work:
        resource = work.pop()

        # Do we need to refresh the usage?
        refresh = False
        if ((resource not in PER_PROJECT_QUOTAS) and
                (resource not in user_or_st_usages)):
            user_or_st_usages[resource] = _quota_usage_create(
                elevated,
                project_id,
                user_id,
                resource,
                0, 0,
                until_refresh or None,
                share_type_id=share_type_id,
            )
            refresh = True
        elif ((resource in PER_PROJECT_QUOTAS) and
                (resource not in user_or_st_usages)):
            user_or_st_usages[resource] = _quota_usage_create(
                elevated,
                project_id,
                None,
                resource,
                0, 0,
                until_refresh or None,
                share_type_id=share_type_id,
            )
            refresh = True
        elif user_or_st_usages[resource].in_use < 0:
            # Negative in_use count indicates a desync, so try to
            # heal from that...
            refresh = True
        elif user_or_st_usages[resource].until_refresh is not None:
            user_or_st_usages[resource].until_refresh -= 1
            if user_or_st_usages[resource].until_refresh <= 0:
                refresh = True
        elif max_age and (user_or_st_usages[resource].updated_at -
                          timeutils.utcnow()).seconds >= max_age:
            refresh = True

        # OK, refresh the usage
        if refresh:
            # Grab the sync routine
            sync = QUOTA_SYNC_FUNCTIONS[resources[resource].sync]

            updates = sync(
                elevated,
                project_id,
                user_id,
                share_type_id=share_type_id,
            )
            for res, in_use in updates.items():
                # Make sure we have a destination for the usage!
                if ((res not in PER_PROJECT_QUOTAS) and
                        (res not in user_or_st_usages)):
                    user_or_st_usages[res] = _quota_usage_create(
                        elevated,
                        project_id,
                        user_id,
                        res,
                        0, 0,
                        until_refresh or None,
                        share_type_id=share_type_id,
                    )
                if ((res in PER_PROJECT_QUOTAS) and
                        (res not in user_or_st_usages)):
                    user_or_st_usages[res] = _quota_usage_create(
                        elevated,
                        project_id,
                        None,
                        res,
                        0, 0,
                        until_refresh or None,
                        share_type_id=share_type_id,
                    )

                if user_or_st_usages[res].in_use != in_use:
                    LOG.debug(
                        'quota_usages out of sync, updating. '
                        'project_id: %(project_id)s, '
                        'user_id: %(user_id)s, '
                        'share_type_id: %(share_type_id)s, '
                        'resource: %(res)s, '
                        'tracked usage: %(tracked_use)s, '
                        'actual usage: %(in_use)s',
                        {'project_id': project_id,
                         'user_id': user_id,
                         'share_type_id': share_type_id,
                         'res': res,
                         'tracked_use': user_or_st_usages[res].in_use,
                         'in_use': in_use})

                # Update the usage
                user_or_st_usages[res].in_use = in_use
                user_or_st_usages[res].until_refresh = (
                    until_refresh or None)

                # Because more than one resource may be refreshed
                # by the call to the sync routine, and we don't
                # want to double-sync, we make sure all refreshed
                # resources are dropped from the work set.
                work.discard(res)

                # NOTE(Vek): We make the assumption that the sync
                #            routine actually refreshes the
                #            resources that it is the sync routine
                #            for.  We don't check, because this is
                #            a best-effort mechanism.

    # Check for deltas that would go negative
    unders = [res for res, delta in deltas.items()
              if delta < 0 and
              delta + user_or_st_usages[res].in_use < 0]

    # Now, let's check the quotas
    # NOTE(Vek): We're only concerned about positive increments.
    #            If a project has gone over quota, we want them to
    #            be able to reduce their usage without any
    #            problems.
    for key, value in user_or_st_usages.items():
        if key not in project_usages:
            project_usages[key] = value
    overs = [res for res, delta in deltas.items()
             if user_or_st_quotas[res] >= 0 and delta >= 0 and
             (0 <= project_quotas[res] < delta +
              project_usages[res]['total'] or
              user_or_st_quotas[res] < delta +
              user_or_st_usages[res].total)]

    # NOTE(carloss): If OverQuota is allowed, there is no problem to exceed
    # the quotas, so we reset the overs list and LOG it.
    if overs and overquota_allowed:
        msg = _("The service has identified one or more exceeded "
                "quotas. Please check the quotas for project "
                "%(project_id)s, user %(user_id)s and share type "
                "%(share_type_id)s, and adjust them if "
                "necessary.") % {
            "project_id": project_id,
            "user_id": user_id,
            "share_type_id": share_type_id
        }
        LOG.warning(msg)
        overs = []

    # NOTE(Vek): The quota check needs to be in the transaction,
    #            but the transaction doesn't fail just because
    #            we're over quota, so the OverQuota raise is
    #            outside the transaction.  If we did the raise
    #            here, our usage updates would be discarded, but
    #            they're not invalidated by being over-quota.

    # Create the reservations
    if not overs:
        reservations = []
        for res, delta in deltas.items():
            reservation = _reservation_create(
                elevated,
                uuidutils.generate_uuid(),
                user_or_st_usages[res],
                project_id,
                user_id,
                res, delta, expire,
                share_type_id=share_type_id,
            )
            reservations.append(reservation.uuid)

            # Also update the reserved quantity
            # NOTE(Vek): Again, we are only concerned here about
            #            positive increments.  Here, though, we're
            #            worried about the following scenario:
            #
            #            1) User initiates resize down.
            #            2) User allocates a new instance.
            #            3) Resize down fails or is reverted.
            #            4) User is now over quota.
            #
            #            To prevent this, we only update the
            #            reserved value if the delta is positive.
            if delta > 0:
                user_or_st_usages[res].reserved += delta

    # Apply updates to the usages table
    for usage_ref in user_or_st_usages.values():
        context.session.add(usage_ref)

    # NOTE(stephenfin): commit changes before we raise any exceptions

    context.session.commit()
    context.session.begin()

    if unders:
        LOG.warning("Change will make usage less than 0 for the following "
                    "resources: %s", unders)
    if overs:
        if project_quotas == user_or_st_quotas:
            usages = project_usages
        else:
            usages = user_or_st_usages
        usages = {k: dict(in_use=v['in_use'], reserved=v['reserved'])
                  for k, v in usages.items()}
        raise exception.OverQuota(
            overs=sorted(overs), quotas=user_or_st_quotas, usages=usages)

    return reservations


def _quota_reservations_query(context, reservations):
    """Return the relevant reservations."""
    return model_query(
        context, models.Reservation,
        read_deleted="no",
    ).filter(
        models.Reservation.uuid.in_(reservations),
    ).with_for_update()


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
@context_manager.writer
def reservation_commit(context, reservations, project_id=None, user_id=None,
                       share_type_id=None):
    if share_type_id:
        st_usages = _get_share_type_quota_usages(
            context, project_id, share_type_id,
        )
    else:
        st_usages = {}
    user_usages = _get_user_quota_usages(context, project_id, user_id)

    reservation_query = _quota_reservations_query(context, reservations)
    for reservation in reservation_query.all():
        if reservation['share_type_id']:
            usages = st_usages
        else:
            usages = user_usages
        usage = usages[reservation.resource]
        if reservation.delta >= 0:
            usage.reserved -= reservation.delta
        usage.in_use += reservation.delta
    reservation_query.soft_delete(synchronize_session=False)


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
@context_manager.writer
def reservation_rollback(context, reservations, project_id=None, user_id=None,
                         share_type_id=None):
    if share_type_id:
        st_usages = _get_share_type_quota_usages(
            context, project_id, share_type_id,
        )
    else:
        st_usages = {}
    user_usages = _get_user_quota_usages(context, project_id, user_id)

    reservation_query = _quota_reservations_query(context, reservations)
    for reservation in reservation_query.all():
        if reservation['share_type_id']:
            usages = st_usages
        else:
            usages = user_usages
        usage = usages[reservation.resource]
        if reservation.delta >= 0:
            usage.reserved -= reservation.delta
    reservation_query.soft_delete(synchronize_session=False)


@require_admin_context
@context_manager.writer
def quota_destroy_all_by_project_and_user(context, project_id, user_id):
    model_query(
        context, models.ProjectUserQuota, read_deleted="no",
    ).filter_by(
        project_id=project_id,
    ).filter_by(user_id=user_id).soft_delete(synchronize_session=False)

    model_query(
        context, models.QuotaUsage, read_deleted="no",
    ).filter_by(
        project_id=project_id,
    ).filter_by(user_id=user_id).soft_delete(synchronize_session=False)

    model_query(
        context, models.Reservation, read_deleted="no",
    ).filter_by(
        project_id=project_id,
    ).filter_by(user_id=user_id).soft_delete(synchronize_session=False)


@require_admin_context
@context_manager.writer
def quota_destroy_all_by_share_type(context, share_type_id, project_id=None):
    return _quota_destroy_all_by_share_type(
        context, share_type_id, project_id=project_id,
    )


@require_admin_context
def _quota_destroy_all_by_share_type(context, share_type_id, project_id=None):
    """Soft deletes all quotas, usages and reservations.

    :param context: request context for queries, updates and logging
    :param share_type_id: ID of the share type to filter the quotas, usages
        and reservations under.
    :param project_id: ID of the project to filter the quotas, usages and
        reservations under. If not provided, share type quotas for all
        projects will be acted upon.
    """
    share_type_quotas = model_query(
        context, models.ProjectShareTypeQuota,
        read_deleted="no",
    ).filter_by(share_type_id=share_type_id)

    share_type_quota_usages = model_query(
        context, models.QuotaUsage, read_deleted="no",
    ).filter_by(share_type_id=share_type_id)

    share_type_quota_reservations = model_query(
        context, models.Reservation, read_deleted="no",
    ).filter_by(share_type_id=share_type_id)

    if project_id is not None:
        share_type_quotas = share_type_quotas.filter_by(
            project_id=project_id,
        )
        share_type_quota_usages = share_type_quota_usages.filter_by(
            project_id=project_id,
        )
        share_type_quota_reservations = (
            share_type_quota_reservations.filter_by(project_id=project_id)
        )

    share_type_quotas.soft_delete(synchronize_session=False)
    share_type_quota_usages.soft_delete(synchronize_session=False)
    share_type_quota_reservations.soft_delete(synchronize_session=False)


@require_admin_context
@context_manager.writer
def quota_destroy_all_by_project(context, project_id):
    model_query(
        context, models.Quota, read_deleted="no",
    ).filter_by(
        project_id=project_id,
    ).soft_delete(synchronize_session=False)

    model_query(
        context, models.ProjectUserQuota, read_deleted="no",
    ).filter_by(
        project_id=project_id,
    ).soft_delete(synchronize_session=False)

    model_query(
        context, models.QuotaUsage, read_deleted="no",
    ).filter_by(
        project_id=project_id,
    ).soft_delete(synchronize_session=False)

    model_query(
        context, models.Reservation, read_deleted="no",
    ).filter_by(
        project_id=project_id,
    ).soft_delete(synchronize_session=False)


@require_admin_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
@context_manager.writer
def reservation_expire(context):
    current_time = timeutils.utcnow()
    reservation_query = model_query(
        context, models.Reservation,
        read_deleted="no"
    ).filter(models.Reservation.expire < current_time)

    for reservation in reservation_query.all():
        if reservation.delta >= 0:
            quota_usage = model_query(
                context, models.QuotaUsage, read_deleted="no",
            ).filter(
                models.QuotaUsage.id == reservation.usage_id,
            ).first()
            quota_usage.reserved -= reservation.delta
            context.session.add(quota_usage)

    reservation_query.soft_delete(synchronize_session=False)


################

def _extract_subdict_by_fields(source_dict, fields):
    dict_to_extract_from = copy.deepcopy(source_dict)
    sub_dict = {}
    for field in fields:
        field_value = dict_to_extract_from.pop(field, None)
        if field_value:
            sub_dict.update({field: field_value})

    return sub_dict, dict_to_extract_from


def _extract_share_instance_values(values):
    share_instance_model_fields = [
        'status', 'host', 'scheduled_at', 'launched_at', 'terminated_at',
        'share_server_id', 'share_network_id', 'availability_zone',
        'replica_state', 'share_type_id', 'share_type', 'access_rules_status',
    ]
    share_instance_values, share_values = (
        _extract_subdict_by_fields(values, share_instance_model_fields)
    )
    return share_instance_values, share_values


def _change_size_to_instance_size(snap_instance_values):
    if 'size' in snap_instance_values:
        snap_instance_values['instance_size'] = snap_instance_values['size']
        snap_instance_values.pop('size')


def _extract_snapshot_instance_values(values):
    fields = ['status', 'progress', 'provider_location']
    snapshot_instance_values, snapshot_values = (
        _extract_subdict_by_fields(values, fields)
    )
    return snapshot_instance_values, snapshot_values


################


@require_context
def share_instance_create(context, share_id, values):
    session = get_session()
    with session.begin():
        return _share_instance_create(context, share_id, values, session)


def _share_instance_create(context, share_id, values, session):
    if not values.get('id'):
        values['id'] = uuidutils.generate_uuid()
    values.update({'share_id': share_id})

    share_instance_ref = models.ShareInstance()
    share_instance_ref.update(values)
    share_instance_ref.save(session=session)

    return share_instance_get(context, share_instance_ref['id'],
                              session=session)


@require_context
def share_instance_update(context, share_instance_id, values,
                          with_share_data=False):
    session = get_session()
    _ensure_availability_zone_exists(context, values, session, strict=False)
    with session.begin():
        instance_ref = _share_instance_update(
            context, share_instance_id, values, session
        )
        if with_share_data:
            parent_share = share_get(context, instance_ref['share_id'],
                                     session=session)
            instance_ref.set_share_data(parent_share)
        return instance_ref


def share_and_snapshot_instances_status_update(
        context, values, share_instance_ids=None, snapshot_instance_ids=None,
        current_expected_status=None):
    updated_share_instances = None
    updated_snapshot_instances = None
    session = get_session()
    with session.begin():
        if current_expected_status and share_instance_ids:
            filters = {'instance_ids': share_instance_ids}
            share_instances = share_instances_get_all(
                context, filters=filters, session=session)
            all_instances_are_compliant = all(
                instance['status'] == current_expected_status
                for instance in share_instances)

            if not all_instances_are_compliant:
                msg = _('At least one of the shares is not in the %(status)s '
                        'status.') % {
                    'status': current_expected_status
                }
                raise exception.InvalidShareInstance(reason=msg)

        if current_expected_status and snapshot_instance_ids:
            filters = {'instance_ids': snapshot_instance_ids}
            snapshot_instances = share_snapshot_instance_get_all_with_filters(
                context, filters, session=session)
            all_snap_instances_are_compliant = all(
                snap_instance['status'] == current_expected_status
                for snap_instance in snapshot_instances)
            if not all_snap_instances_are_compliant:
                msg = _('At least one of the snapshots is not in the '
                        '%(status)s status.') % {
                    'status': current_expected_status
                }
                raise exception.InvalidShareSnapshotInstance(reason=msg)

        if share_instance_ids:
            updated_share_instances = share_instances_status_update(
                context, share_instance_ids, values, session=session)

        if snapshot_instance_ids:
            updated_snapshot_instances = (
                share_snapshot_instances_status_update(
                    context, snapshot_instance_ids, values, session=session))

    return updated_share_instances, updated_snapshot_instances


@require_context
def share_instances_status_update(
        context, share_instance_ids, values, session=None):
    session = session or get_session()

    result = (
        model_query(
            context, models.ShareInstance, read_deleted="no",
            session=session).filter(
            models.ShareInstance.id.in_(share_instance_ids)).update(
            values, synchronize_session=False))
    return result


def _share_instance_update(context, share_instance_id, values, session):
    share_instance_ref = share_instance_get(context, share_instance_id,
                                            session=session)
    share_instance_ref.update(values)
    share_instance_ref.save(session=session)
    return share_instance_ref


@require_context
def share_instance_get(context, share_instance_id, session=None,
                       with_share_data=False):
    if session is None:
        session = get_session()
    result = model_query(
        context, models.ShareInstance, session=session,
    ).filter_by(
        id=share_instance_id,
    ).options(
        joinedload('export_locations').joinedload('_el_metadata_bare'),
        joinedload('share_type'),
    ).first()
    if result is None:
        raise exception.NotFound()

    if with_share_data:
        parent_share = share_get(context, result['share_id'], session=session)
        result.set_share_data(parent_share)

    return result


@require_admin_context
def share_instances_get_all(context, filters=None, session=None):
    session = session or get_session()
    query = model_query(
        context, models.ShareInstance, session=session, read_deleted="no",
    ).options(
        joinedload('export_locations'),
    )

    filters = filters or {}

    export_location_id = filters.get('export_location_id')
    export_location_path = filters.get('export_location_path')
    if export_location_id or export_location_path:
        query = query.join(
            models.ShareInstanceExportLocations,
            models.ShareInstanceExportLocations.share_instance_id ==
            models.ShareInstance.id)
        if export_location_path:
            query = query.filter(
                models.ShareInstanceExportLocations.path ==
                export_location_path)
        if export_location_id:
            query = query.filter(
                models.ShareInstanceExportLocations.uuid ==
                export_location_id)

    query = query.join(
        models.Share,
        models.Share.id ==
        models.ShareInstance.share_id)
    is_soft_deleted = filters.get('is_soft_deleted')
    if is_soft_deleted:
        query = query.filter(models.Share.is_soft_deleted == true())
    else:
        query = query.filter(models.Share.is_soft_deleted == false())

    instance_ids = filters.get('instance_ids')
    if instance_ids:
        query = query.filter(models.ShareInstance.id.in_(instance_ids))

    # TODO(gouthamr): This DB API method needs to be generalized for all
    # share instance fields.
    host = filters.get('host')
    if host:
        query = query.filter(
            or_(models.ShareInstance.host == host,
                models.ShareInstance.host.like("{0}#%".format(host)))
        )
    share_server_id = filters.get('share_server_id')
    if share_server_id:
        query = query.filter(
            models.ShareInstance.share_server_id == share_server_id)

    # Returns list of share instances that satisfy filters.
    query = query.all()
    return query


@require_context
def _update_share_instance_usages(context, share, instance_ref,
                                  is_replica=False):
    deltas = {}
    no_instances_remain = len(share.instances) == 0
    share_usages_to_release = {"shares": -1, "gigabytes": -share['size']}
    replica_usages_to_release = {"share_replicas": -1,
                                 "replica_gigabytes": -share['size']}

    if is_replica and no_instances_remain:
        # A share that had a replication_type is being deleted, so there's
        # need to update the share replica quotas and the share quotas
        deltas.update(replica_usages_to_release)
        deltas.update(share_usages_to_release)
    elif is_replica:
        # The user is deleting a share replica
        deltas.update(replica_usages_to_release)
    else:
        # A share with no replication_type is being deleted
        deltas.update(share_usages_to_release)

    reservations = None
    try:
        # we give the user_id of the share, to update
        # the quota usage for the user, who created the share
        reservations = QUOTAS.reserve(
            context,
            project_id=share['project_id'],
            user_id=share['user_id'],
            share_type_id=instance_ref['share_type_id'],
            **deltas)
        QUOTAS.commit(
            context, reservations, project_id=share['project_id'],
            user_id=share['user_id'],
            share_type_id=instance_ref['share_type_id'])
    except Exception:
        resource_name = (
            'share replica' if is_replica else 'share')
        resource_id = instance_ref['id'] if is_replica else share['id']
        msg = (_("Failed to update usages deleting %(resource_name)s "
                 "'%(id)s'.") % {'id': resource_id,
                                 "resource_name": resource_name})
        LOG.exception(msg)
        if reservations:
            QUOTAS.rollback(
                context, reservations,
                share_type_id=instance_ref['share_type_id'])


@require_context
def share_instance_delete(context, instance_id, session=None,
                          need_to_update_usages=False):
    if session is None:
        session = get_session()

    with session.begin():
        share_export_locations_update(context, instance_id, [], delete=True)
        instance_ref = share_instance_get(context, instance_id,
                                          session=session)
        is_replica = instance_ref['replica_state'] is not None
        instance_ref.soft_delete(session=session, update_status=True)
        share = share_get(context, instance_ref['share_id'], session=session)
        if len(share.instances) == 0:
            share_access_delete_all_by_share(context, share['id'])
            session.query(models.ShareMetadata).filter_by(
                share_id=share['id']).soft_delete()
            share.soft_delete(session=session)

        if need_to_update_usages:
            _update_share_instance_usages(context, share, instance_ref,
                                          is_replica=is_replica)


def _set_instances_share_data(context, instances, session):
    if instances and not isinstance(instances, list):
        instances = [instances]

    instances_with_share_data = []
    for instance in instances:
        try:
            parent_share = share_get(context, instance['share_id'],
                                     session=session)
        except exception.NotFound:
            continue
        instance.set_share_data(parent_share)
        instances_with_share_data.append(instance)
    return instances_with_share_data


@require_admin_context
def share_instances_get_all_by_host(context, host, with_share_data=False,
                                    status=None, session=None):
    """Retrieves all share instances hosted on a host."""
    session = session or get_session()
    instances = (
        model_query(context, models.ShareInstance).filter(
            or_(
                models.ShareInstance.host == host,
                models.ShareInstance.host.like("{0}#%".format(host))
            )
        )
    )
    if status is not None:
        instances = instances.filter(models.ShareInstance.status == status)
    # Returns list of all instances that satisfy filters.
    instances = instances.all()

    if with_share_data:
        instances = _set_instances_share_data(context, instances, session)
    return instances


@require_context
def share_instances_get_all_by_share_network(context, share_network_id):
    """Returns list of share instances that belong to given share network."""
    result = (
        model_query(context, models.ShareInstance).filter(
            models.ShareInstance.share_network_id == share_network_id,
        ).all()
    )
    return result


@require_context
def share_instances_get_all_by_share_server(context, share_server_id,
                                            with_share_data=False):
    """Returns list of share instance with given share server."""
    session = get_session()
    result = (
        model_query(context, models.ShareInstance).filter(
            models.ShareInstance.share_server_id == share_server_id,
        ).all()
    )

    if with_share_data:
        result = _set_instances_share_data(context, result, session)

    return result


@require_context
def share_instances_get_all_by_share(context, share_id):
    """Returns list of share instances that belong to given share."""
    result = (
        model_query(context, models.ShareInstance).filter(
            models.ShareInstance.share_id == share_id,
        ).all()
    )
    return result


@require_context
def share_instances_get_all_by_share_group_id(context, share_group_id):
    """Returns list of share instances that belong to given share group."""
    result = (
        model_query(context, models.Share).filter(
            models.Share.share_group_id == share_group_id,
        ).all()
    )
    instances = []
    for share in result:
        instance = share.instance
        instance.set_share_data(share)
        instances.append(instance)

    return instances


################

def _share_replica_get_with_filters(context, share_id=None, replica_id=None,
                                    replica_state=None, status=None,
                                    with_share_server=True, session=None):

    query = model_query(context, models.ShareInstance, session=session,
                        read_deleted="no")

    if not context.is_admin:
        query = query.join(
            models.Share,
            models.ShareInstance.share_id == models.Share.id).filter(
            models.Share.project_id == context.project_id)

    if share_id is not None:
        query = query.filter(models.ShareInstance.share_id == share_id)

    if replica_id is not None:
        query = query.filter(models.ShareInstance.id == replica_id)

    if replica_state is not None:
        query = query.filter(
            models.ShareInstance.replica_state == replica_state)
    else:
        query = query.filter(models.ShareInstance.replica_state.isnot(None))

    if status is not None:
        query = query.filter(models.ShareInstance.status == status)

    if with_share_server:
        query = query.options(joinedload('share_server'))

    return query


@require_context
def share_replicas_get_all(context, with_share_data=False,
                           with_share_server=True, session=None):
    """Returns replica instances for all available replicated shares."""
    session = session or get_session()

    result = _share_replica_get_with_filters(
        context, with_share_server=with_share_server, session=session).all()

    if with_share_data:
        result = _set_instances_share_data(context, result, session)

    return result


@require_context
def share_replicas_get_all_by_share(context, share_id,
                                    with_share_data=False,
                                    with_share_server=False, session=None):
    """Returns replica instances for a given share."""
    session = session or get_session()

    result = _share_replica_get_with_filters(
        context, with_share_server=with_share_server,
        share_id=share_id, session=session).all()

    if with_share_data:
        result = _set_instances_share_data(context, result, session)

    return result


@require_context
def share_replicas_get_available_active_replica(context, share_id,
                                                with_share_data=False,
                                                with_share_server=False,
                                                session=None):
    """Returns an 'active' replica instance that is 'available'."""
    session = session or get_session()

    result = _share_replica_get_with_filters(
        context, with_share_server=with_share_server, share_id=share_id,
        replica_state=constants.REPLICA_STATE_ACTIVE,
        status=constants.STATUS_AVAILABLE, session=session).first()

    if result and with_share_data:
        result = _set_instances_share_data(context, result, session)[0]

    return result


@require_context
def share_replica_get(context, replica_id, with_share_data=False,
                      with_share_server=False, session=None):
    """Returns summary of requested replica if available."""
    session = session or get_session()

    result = _share_replica_get_with_filters(
        context, with_share_server=with_share_server,
        replica_id=replica_id, session=session).first()

    if result is None:
        raise exception.ShareReplicaNotFound(replica_id=replica_id)

    if with_share_data:
        result = _set_instances_share_data(context, result, session)[0]

    return result


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_replica_update(context, share_replica_id, values,
                         with_share_data=False, session=None):
    """Updates a share replica with specified values."""
    session = session or get_session()

    with session.begin():
        _ensure_availability_zone_exists(context, values, session,
                                         strict=False)
        updated_share_replica = _share_instance_update(
            context, share_replica_id, values, session=session)

        if with_share_data:
            updated_share_replica = _set_instances_share_data(
                context, updated_share_replica, session)[0]

    return updated_share_replica


@require_context
def share_replica_delete(context, share_replica_id, session=None,
                         need_to_update_usages=True):
    """Deletes a share replica."""
    session = session or get_session()

    share_instance_delete(context, share_replica_id, session=session,
                          need_to_update_usages=need_to_update_usages)


################


@require_context
def _share_get_query(context, session=None, **kwargs):
    if session is None:
        session = get_session()
    return (model_query(context, models.Share, session=session, **kwargs).
            options(joinedload('share_metadata')))


def _process_share_filters(query, filters, project_id=None, is_public=False):
    if filters is None:
        filters = {}

    share_filter_keys = ['share_group_id', 'snapshot_id',
                         'is_soft_deleted', 'source_backup_id']
    instance_filter_keys = ['share_server_id', 'status', 'share_type_id',
                            'host', 'share_network_id']
    share_filters = {}
    instance_filters = {}

    for k, v in filters.items():
        share_filters.update({k: v}) if k in share_filter_keys else None
        instance_filters.update({k: v}) if k in instance_filter_keys else None

    no_key = 'key_is_absent'

    def _filter_data(query, model, desired_filters):
        for key, value in desired_filters.items():
            filter_attr = getattr(model, key, no_key)
            if filter_attr == no_key:
                pass
            query = query.filter(filter_attr == value)
        return query

    if share_filters:
        query = _filter_data(query, models.Share, share_filters)
    if instance_filters:
        query = _filter_data(query, models.ShareInstance, instance_filters)

    if project_id:
        if is_public:
            query = query.filter(or_(models.Share.project_id == project_id,
                                     models.Share.is_public))
        else:
            query = query.filter(models.Share.project_id == project_id)

    display_name = filters.get('display_name')
    if display_name:
        query = query.filter(
            models.Share.display_name == display_name)
    else:
        display_name = filters.get('display_name~')
        if display_name:
            query = query.filter(models.Share.display_name.op('LIKE')(
                u'%' + display_name + u'%'))

    display_description = filters.get('display_description')
    if display_description:
        query = query.filter(
            models.Share.display_description == display_description)
    else:
        display_description = filters.get('display_description~')
        if display_description:
            query = query.filter(models.Share.display_description.op('LIKE')(
                u'%' + display_description + u'%'))

    export_location_id = filters.pop('export_location_id', None)
    export_location_path = filters.pop('export_location_path', None)
    if export_location_id or export_location_path:
        query = query.join(
            models.ShareInstanceExportLocations,
            models.ShareInstanceExportLocations.share_instance_id ==
            models.ShareInstance.id)
        if export_location_path:
            query = query.filter(
                models.ShareInstanceExportLocations.path ==
                export_location_path)
        if export_location_id:
            query = query.filter(
                models.ShareInstanceExportLocations.uuid ==
                export_location_id)

    if 'metadata' in filters:
        for k, v in filters['metadata'].items():
            # pylint: disable=no-member
            query = query.filter(
                or_(models.Share.share_metadata.any(
                    key=k, value=v)))
    if 'extra_specs' in filters:
        query = query.join(
            models.ShareTypeExtraSpecs,
            models.ShareTypeExtraSpecs.share_type_id ==
            models.ShareInstance.share_type_id)
        for k, v in filters['extra_specs'].items():
            query = query.filter(and_(models.ShareTypeExtraSpecs.key == k,
                                 models.ShareTypeExtraSpecs.value == v))

    return query


def _metadata_refs(metadata_dict, meta_class):
    metadata_refs = []
    if metadata_dict:
        for k, v in metadata_dict.items():
            value = str(v) if isinstance(v, bool) else v

            metadata_ref = meta_class()
            metadata_ref['key'] = k
            metadata_ref['value'] = value
            metadata_refs.append(metadata_ref)
    return metadata_refs


@require_context
def share_create(context, share_values, create_share_instance=True):
    values = copy.deepcopy(share_values)
    values = ensure_model_dict_has_id(values)
    values['share_metadata'] = _metadata_refs(values.get('metadata'),
                                              models.ShareMetadata)
    session = get_session()
    share_ref = models.Share()
    share_instance_values, share_values = _extract_share_instance_values(
        values)
    _ensure_availability_zone_exists(context, share_instance_values, session,
                                     strict=False)
    share_ref.update(share_values)

    with session.begin():
        share_ref.save(session=session)

        if create_share_instance:
            _share_instance_create(context, share_ref['id'],
                                   share_instance_values, session=session)

        # NOTE(u_glide): Do so to prevent errors with relationships
        return share_get(context, share_ref['id'], session=session)


@require_admin_context
def _share_data_get_for_project(
    context, project_id, user_id, share_type_id=None,
):
    query = model_query(
        context, models.Share,
        func.count(models.Share.id),
        func.sum(models.Share.size),
        read_deleted="no",
    ).filter_by(project_id=project_id)
    if share_type_id:
        query = query.join("instances").filter_by(share_type_id=share_type_id)
    elif user_id:
        query = query.filter_by(user_id=user_id)
    result = query.first()
    return (result[0] or 0, result[1] or 0)


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_update(context, share_id, update_values):
    session = get_session()
    values = copy.deepcopy(update_values)

    share_instance_values, share_values = _extract_share_instance_values(
        values)
    _ensure_availability_zone_exists(context, share_instance_values, session,
                                     strict=False)

    with session.begin():
        share_ref = share_get(context, share_id, session=session)

        _share_instance_update(context, share_ref.instance['id'],
                               share_instance_values, session=session)

        share_ref.update(share_values)
        share_ref.save(session=session)
        return share_ref


@require_context
def share_get(context, share_id, session=None, **kwargs):
    result = _share_get_query(context, session, **kwargs).filter_by(
        id=share_id).first()

    if result is None:
        raise exception.NotFound()

    return result


def _share_get_all_with_filters(context, project_id=None, share_server_id=None,
                                share_group_id=None, filters=None,
                                is_public=False, sort_key=None,
                                sort_dir=None, show_count=False):
    """Returns sorted list of shares that satisfies filters.

    :param context: context to query under
    :param project_id: project id that owns shares
    :param share_server_id: share server that hosts shares
    :param filters: dict of filters to specify share selection
    :param is_public: public shares from other projects will be added
                      to result if True
    :param sort_key: key of models.Share to be used for sorting
    :param sort_dir: desired direction of sorting, can be 'asc' and 'desc'
    :returns: list -- models.Share
    :raises: exception.InvalidInput
    """
    if filters is None:
        filters = {}

    if not sort_key:
        sort_key = 'created_at'
    if not sort_dir:
        sort_dir = 'desc'
    query = (
        _share_get_query(context).join(
            models.ShareInstance,
            models.ShareInstance.share_id == models.Share.id
        )
    )

    if share_group_id:
        filters['share_group_id'] = share_group_id
    if share_server_id:
        filters['share_server_id'] = share_server_id

    # if not specified is_soft_deleted filter, default is False, to get
    # shares not in recycle bin.
    if 'is_soft_deleted' not in filters:
        filters['is_soft_deleted'] = False

    query = _process_share_filters(
        query, filters, project_id, is_public=is_public)

    try:
        query = apply_sorting(models.Share, query, sort_key, sort_dir)
    except AttributeError:
        try:
            query = apply_sorting(
                models.ShareInstance, query, sort_key, sort_dir)
        except AttributeError:
            msg = _("Wrong sorting key provided - '%s'.") % sort_key
            raise exception.InvalidInput(reason=msg)

    count = None
    # NOTE(carloss): Count must be calculated before limit and offset are
    # applied into the query.
    if show_count:
        count = query.count()

    if 'limit' in filters:
        offset = filters.get('offset', 0)
        query = query.limit(filters['limit']).offset(offset)

    # Returns list of shares that satisfy filters.
    query = query.all()

    if show_count:
        return count, query

    return query


@require_admin_context
def get_all_expired_shares(context):
    query = (
        _share_get_query(context).join(
            models.ShareInstance,
            models.ShareInstance.share_id == models.Share.id
        )
    )
    filters = {"is_soft_deleted": True}
    query = _process_share_filters(query, filters=filters)
    scheduled_deleted_attr = getattr(models.Share,
                                     'scheduled_to_be_deleted_at', None)
    now_time = timeutils.utcnow()
    query = query.filter(scheduled_deleted_attr.op('<=')(now_time))
    result = query.all()

    return result


@require_admin_context
def share_get_all(context, filters=None, sort_key=None, sort_dir=None):
    project_id = filters.pop('project_id', None) if filters else None
    query = _share_get_all_with_filters(
        context,
        project_id=project_id,
        filters=filters, sort_key=sort_key, sort_dir=sort_dir)

    return query


@require_admin_context
def share_get_all_with_count(context, filters=None, sort_key=None,
                             sort_dir=None):
    count, query = _share_get_all_with_filters(
        context,
        filters=filters, sort_key=sort_key, sort_dir=sort_dir,
        show_count=True)
    return count, query


@require_context
def share_get_all_by_project(context, project_id, filters=None,
                             is_public=False, sort_key=None, sort_dir=None):
    """Returns list of shares with given project ID."""
    query = _share_get_all_with_filters(
        context, project_id=project_id, filters=filters, is_public=is_public,
        sort_key=sort_key, sort_dir=sort_dir)
    return query


@require_context
def share_get_all_by_project_with_count(
        context, project_id, filters=None, is_public=False, sort_key=None,
        sort_dir=None):
    """Returns list of shares with given project ID."""
    count, query = _share_get_all_with_filters(
        context, project_id=project_id, filters=filters, is_public=is_public,
        sort_key=sort_key, sort_dir=sort_dir, show_count=True)
    return count, query


@require_context
def share_get_all_by_share_group_id(context, share_group_id,
                                    filters=None, sort_key=None,
                                    sort_dir=None):
    """Returns list of shares with given group ID."""
    query = _share_get_all_with_filters(
        context, share_group_id=share_group_id,
        filters=filters, sort_key=sort_key, sort_dir=sort_dir)
    return query


@require_context
def share_get_all_by_share_group_id_with_count(context, share_group_id,
                                               filters=None, sort_key=None,
                                               sort_dir=None):
    """Returns list of shares with given share group ID."""
    count, query = _share_get_all_with_filters(
        context, share_group_id=share_group_id,
        filters=filters, sort_key=sort_key, sort_dir=sort_dir, show_count=True)
    return count, query


@require_context
def share_get_all_by_share_server(context, share_server_id, filters=None,
                                  sort_key=None, sort_dir=None):
    """Returns list of shares with given share server."""
    query = _share_get_all_with_filters(
        context, share_server_id=share_server_id, filters=filters,
        sort_key=sort_key, sort_dir=sort_dir)
    return query


@require_context
def get_shares_in_recycle_bin_by_share_server(
        context, share_server_id, filters=None, sort_key=None, sort_dir=None):
    """Returns list of shares in recycle bin with given share server."""
    if filters is None:
        filters = {}
    filters["is_soft_deleted"] = True
    query = _share_get_all_with_filters(
        context, share_server_id=share_server_id, filters=filters,
        sort_key=sort_key, sort_dir=sort_dir)
    return query


@require_context
def share_get_all_by_share_server_with_count(
        context, share_server_id, filters=None, sort_key=None, sort_dir=None):
    """Returns list of shares with given share server."""
    count, query = _share_get_all_with_filters(
        context, share_server_id=share_server_id, filters=filters,
        sort_key=sort_key, sort_dir=sort_dir, show_count=True)
    return count, query


@require_context
def get_shares_in_recycle_bin_by_network(
        context, share_network_id, filters=None, sort_key=None, sort_dir=None):
    """Returns list of shares in recycle bin with given share network."""
    if filters is None:
        filters = {}
    filters["share_network_id"] = share_network_id
    filters["is_soft_deleted"] = True
    query = _share_get_all_with_filters(context, filters=filters,
                                        sort_key=sort_key, sort_dir=sort_dir)
    return query


@require_context
def share_delete(context, share_id):
    session = get_session()

    with session.begin():
        share_ref = share_get(context, share_id, session)

        if len(share_ref.instances) > 0:
            msg = _("Share %(id)s has %(count)s share instances.") % {
                'id': share_id, 'count': len(share_ref.instances)}
            raise exception.InvalidShare(msg)

        share_ref.soft_delete(session=session)

        (session.query(models.ShareMetadata).
            filter_by(share_id=share_id).soft_delete())


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_soft_delete(context, share_id):
    session = get_session()
    now_time = timeutils.utcnow()
    time_delta = datetime.timedelta(
        seconds=CONF.soft_deleted_share_retention_time)
    scheduled_to_be_deleted_at = now_time + time_delta
    update_values = {
        'is_soft_deleted': True,
        'scheduled_to_be_deleted_at': scheduled_to_be_deleted_at
    }

    with session.begin():
        share_ref = share_get(context, share_id, session=session)
        share_ref.update(update_values)
        share_ref.save(session=session)


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_restore(context, share_id):
    session = get_session()
    update_values = {
        'is_soft_deleted': False,
        'scheduled_to_be_deleted_at': None
    }

    with session.begin():
        share_ref = share_get(context, share_id, session=session)
        share_ref.update(update_values)
        share_ref.save(session=session)


###################


@context_manager.reader
def _transfer_get(context, transfer_id, resource_type='share',
                  session=None, read_deleted=False):
    """resource_type can be share or network(TODO network transfer)"""
    query = model_query(context, models.Transfer,
                        session=session,
                        read_deleted=read_deleted).filter_by(id=transfer_id)

    if not is_admin_context(context):
        if resource_type == 'share':
            share = models.Share
            query = query.filter(models.Transfer.resource_id == share.id,
                                 share.project_id == context.project_id)

    result = query.first()
    if not result:
        raise exception.TransferNotFound(transfer_id=transfer_id)

    return result


@context_manager.reader
def share_transfer_get(context, transfer_id, read_deleted=False):
    return _transfer_get(context, transfer_id, read_deleted=read_deleted)


def _transfer_get_all(context, limit=None, sort_key=None,
                      sort_dir=None, filters=None, offset=None):
    session = get_session()
    sort_key = sort_key or 'created_at'
    sort_dir = sort_dir or 'desc'
    with session.begin():
        query = model_query(context, models.Transfer, session=session)

        if filters:
            legal_filter_keys = ('display_name', 'display_name~',
                                 'id', 'resource_type', 'resource_id',
                                 'source_project_id', 'destination_project_id')
            query = exact_filter(query, models.Transfer,
                                 filters, legal_filter_keys)
            query = utils.paginate_query(query, models.Transfer, limit,
                                         sort_key=sort_key,
                                         sort_dir=sort_dir,
                                         offset=offset)
        return query.all()


@require_admin_context
def transfer_get_all(context, limit=None, sort_key=None,
                     sort_dir=None, filters=None, offset=None):
    return _transfer_get_all(context, limit=limit,
                             sort_key=sort_key, sort_dir=sort_dir,
                             filters=filters, offset=offset)


@require_context
def transfer_get_all_by_project(context, project_id,
                                limit=None, sort_key=None,
                                sort_dir=None, filters=None, offset=None):
    filters = filters.copy() if filters else {}
    filters['source_project_id'] = project_id
    return _transfer_get_all(context, limit=limit,
                             sort_key=sort_key, sort_dir=sort_dir,
                             filters=filters, offset=offset)


@require_context
@handle_db_data_error
def transfer_create(context, values):
    if not values.get('id'):
        values['id'] = uuidutils.generate_uuid()

    resource_id = values['resource_id']
    now_time = timeutils.utcnow()
    time_delta = datetime.timedelta(
        seconds=CONF.transfer_retention_time)
    transfer_timeout = now_time + time_delta
    values['expires_at'] = transfer_timeout

    session = get_session()
    with session.begin():
        transfer = models.Transfer()
        transfer.update(values)
        transfer.save(session=session)
        update = {'status': constants.STATUS_AWAITING_TRANSFER}
        if values['resource_type'] == 'share':
            share_update(context, resource_id, update)
        return transfer


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def transfer_destroy(context, transfer_id,
                     update_share_status=True):
    session = get_session()
    with session.begin():
        update = {'status': constants.STATUS_AVAILABLE}
        transfer = share_transfer_get(context, transfer_id)
        if transfer['resource_type'] == 'share':
            if update_share_status:
                share_update(context, transfer['resource_id'], update)
        transfer_query = model_query(context, models.Transfer,
                                     session=session).filter_by(id=transfer_id)

        transfer_query.soft_delete()


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def transfer_accept(context, transfer_id, user_id, project_id,
                    accept_snapshots=False):
    session = get_session()
    with session.begin():
        share_id = share_transfer_get(context, transfer_id)['resource_id']
        update = {'status': constants.STATUS_AVAILABLE,
                  'user_id': user_id,
                  'project_id': project_id,
                  'updated_at': timeutils.utcnow()}
        share_update(context, share_id, update)

        # Update snapshots for transfer snapshots with share.
        if accept_snapshots:
            snapshots = share_snapshot_get_all_for_share(context, share_id)
            for snapshot in snapshots:
                LOG.debug('Begin to transfer snapshot: %s', snapshot['id'])
                update = {'user_id': user_id,
                          'project_id': project_id,
                          'updated_at': timeutils.utcnow()}
                share_snapshot_update(context, snapshot['id'], update)
        query = session.query(models.Transfer).filter_by(id=transfer_id)
        query.update({'deleted': True,
                      'deleted_at': timeutils.utcnow(),
                      'updated_at': timeutils.utcnow(),
                      'destination_project_id': project_id,
                      'accepted': True})


@require_context
def transfer_accept_rollback(context, transfer_id, user_id,
                             project_id, rollback_snap=False):
    session = get_session()
    with session.begin():
        share_id = share_transfer_get(
            context, transfer_id, read_deleted=True)['resource_id']
        update = {'status': constants.STATUS_AWAITING_TRANSFER,
                  'user_id': user_id,
                  'project_id': project_id,
                  'updated_at': timeutils.utcnow()}
        share_update(context, share_id, update)

        # rollback snapshots for transfer snapshots with share.
        if rollback_snap:
            snapshots = share_snapshot_get_all_for_share(context, share_id)
            for snapshot in snapshots:
                LOG.debug('Begin to rollback snapshot: %s', snapshot['id'])
                update = {'user_id': user_id,
                          'project_id': project_id,
                          'updated_at': timeutils.utcnow()}
                share_snapshot_update(context, snapshot['id'], update)

        query = session.query(models.Transfer).filter_by(id=transfer_id)
        query.update({'deleted': 'False',
                      'deleted_at': None,
                      'updated_at': timeutils.utcnow(),
                      'destination_project_id': None,
                      'accepted': 0})


@require_admin_context
def get_all_expired_transfers(context):
    session = get_session()
    with session.begin():
        query = model_query(context, models.Transfer, session=session)
        expires_at_attr = getattr(models.Transfer, 'expires_at', None)
        now_time = timeutils.utcnow()
        query = query.filter(expires_at_attr.op('<=')(now_time))
        result = query.all()

        return result

###################


def _share_access_get_query(context, session, values, read_deleted='no'):
    """Get access record."""
    query = (model_query(
        context, models.ShareAccessMapping, session=session,
        read_deleted=read_deleted).options(
            joinedload('share_access_rules_metadata')))
    return query.filter_by(**values)


def _share_instance_access_query(context, session, access_id=None,
                                 instance_id=None):
    filters = {'deleted': 'False'}

    if access_id is not None:
        filters.update({'access_id': access_id})

    if instance_id is not None:
        filters.update({'share_instance_id': instance_id})

    return model_query(context, models.ShareInstanceAccessMapping,
                       session=session).filter_by(**filters)


def _share_access_metadata_get_item(context, access_id, key, session=None):
    result = (_share_access_metadata_get_query(
        context, access_id, session=session).filter_by(key=key).first())
    if not result:
        raise exception.ShareAccessMetadataNotFound(
            metadata_key=key, access_id=access_id)
    return result


def _share_access_metadata_get_query(context, access_id, session=None):
    return (model_query(
        context, models.ShareAccessRulesMetadata, session=session,
        read_deleted="no").
        filter_by(access_id=access_id).
        options(joinedload('access')))


@require_context
def share_access_metadata_update(context, access_id, metadata):
    session = get_session()

    with session.begin():
        # Now update all existing items with new values, or create new meta
        # objects
        for meta_key, meta_value in metadata.items():

            # update the value whether it exists or not
            item = {"value": meta_value}
            try:
                meta_ref = _share_access_metadata_get_item(
                    context, access_id, meta_key, session=session)
            except exception.ShareAccessMetadataNotFound:
                meta_ref = models.ShareAccessRulesMetadata()
                item.update({"key": meta_key, "access_id": access_id})

            meta_ref.update(item)
            meta_ref.save(session=session)

        return metadata


@require_context
def share_access_metadata_delete(context, access_id, key):
    session = get_session()
    with session.begin():
        metadata = _share_access_metadata_get_item(
            context, access_id, key, session=session)

        metadata.soft_delete(session)


@require_context
def share_access_create(context, values):
    values = ensure_model_dict_has_id(values)
    session = get_session()
    with session.begin():
        values['share_access_rules_metadata'] = (
            _metadata_refs(values.get('metadata'),
                           models.ShareAccessRulesMetadata))

        access_ref = models.ShareAccessMapping()
        access_ref.update(values)
        access_ref.save(session=session)

        parent_share = share_get(context, values['share_id'], session=session)

        for instance in parent_share.instances:
            vals = {
                'share_instance_id': instance['id'],
                'access_id': access_ref['id'],
            }

            _share_instance_access_create(vals, session)

    return share_access_get(context, access_ref['id'])


@require_context
def share_instance_access_create(context, values, share_instance_id):
    values = ensure_model_dict_has_id(values)
    session = get_session()
    with session.begin():
        access_list = _share_access_get_query(
            context, session, {
                'share_id': values['share_id'],
                'access_type': values['access_type'],
                'access_to': values['access_to'],
            }).all()
        if len(access_list) > 0:
            access_ref = access_list[0]
        else:
            access_ref = models.ShareAccessMapping()
        access_ref.update(values)
        access_ref.save(session=session)

        vals = {
            'share_instance_id': share_instance_id,
            'access_id': access_ref['id'],
        }

        _share_instance_access_create(vals, session)

    return share_access_get(context, access_ref['id'])


@require_context
def share_instance_access_copy(context, share_id, instance_id, session=None):
    """Copy access rules from share to share instance."""
    session = session or get_session()

    share_access_rules = _share_access_get_query(
        context, session, {'share_id': share_id}).all()

    for access_rule in share_access_rules:
        values = {
            'share_instance_id': instance_id,
            'access_id': access_rule['id'],
        }

        _share_instance_access_create(values, session)

    return share_access_rules


def _share_instance_access_create(values, session):
    access_ref = models.ShareInstanceAccessMapping()
    access_ref.update(ensure_model_dict_has_id(values))
    access_ref.save(session=session)
    return access_ref


@require_context
def share_access_get(context, access_id, session=None):
    """Get access record."""
    session = session or get_session()

    access = _share_access_get_query(
        context, session, {'id': access_id}).first()
    if access:
        return access
    else:
        raise exception.NotFound()


@require_context
def share_access_get_with_context(context, access_id, session=None):
    """Get access record."""
    session = session or get_session()

    access = _share_access_get_query(
        context, session,
        {'id': access_id}).options(joinedload('share')).first()
    if access:
        access['project_id'] = access['share']['project_id']
        return access
    else:
        raise exception.NotFound()


@require_context
def share_instance_access_get(context, access_id, instance_id,
                              with_share_access_data=True):
    """Get access record."""
    session = get_session()

    access = _share_instance_access_query(context, session, access_id,
                                          instance_id).first()
    if access is None:
        raise exception.NotFound()

    if with_share_access_data:
        access = _set_instances_share_access_data(context, access, session)[0]

    return access


@require_context
def share_access_get_all_for_share(context, share_id, filters=None,
                                   session=None):
    filters = filters or {}
    session = session or get_session()
    share_access_mapping = models.ShareAccessMapping
    query = (_share_access_get_query(
        context, session, {'share_id': share_id}).filter(
        models.ShareAccessMapping.instance_mappings.any()))

    legal_filter_keys = ('id', 'access_type', 'access_key',
                         'access_to', 'access_level')

    if 'metadata' in filters:
        for k, v in filters['metadata'].items():
            query = query.filter(
                or_(models.ShareAccessMapping.
                    share_access_rules_metadata.any(key=k, value=v)))

    query = exact_filter(
        query, share_access_mapping, filters, legal_filter_keys)

    return query.all()


@require_context
def share_access_get_all_for_instance(context, instance_id, filters=None,
                                      with_share_access_data=True,
                                      session=None):
    """Get all access rules related to a certain share instance."""
    session = session or get_session()
    filters = copy.deepcopy(filters) if filters else {}
    filters.update({'share_instance_id': instance_id})
    legal_filter_keys = ('id', 'share_instance_id', 'access_id', 'state')
    query = _share_instance_access_query(context, session)

    query = exact_filter(
        query, models.ShareInstanceAccessMapping, filters, legal_filter_keys)

    instance_accesses = query.all()

    if with_share_access_data:
        instance_accesses = _set_instances_share_access_data(
            context, instance_accesses, session)

    return instance_accesses


def _set_instances_share_access_data(context, instance_accesses, session):
    if instance_accesses and not isinstance(instance_accesses, list):
        instance_accesses = [instance_accesses]

    for instance_access in instance_accesses:
        share_access = share_access_get(
            context, instance_access['access_id'], session=session)
        instance_access.set_share_access_data(share_access)

    return instance_accesses


def _set_instances_snapshot_access_data(context, instance_accesses, session):
    if instance_accesses and not isinstance(instance_accesses, list):
        instance_accesses = [instance_accesses]

    for instance_access in instance_accesses:
        snapshot_access = share_snapshot_access_get(
            context, instance_access['access_id'], session=session)
        instance_access.set_snapshot_access_data(snapshot_access)

    return instance_accesses


@require_context
def share_access_get_all_by_type_and_access(context, share_id, access_type,
                                            access):
    session = get_session()
    return _share_access_get_query(context, session,
                                   {'share_id': share_id,
                                    'access_type': access_type,
                                    'access_to': access}).all()


@require_context
def share_access_check_for_existing_access(context, share_id, access_type,
                                           access_to):
    return _check_for_existing_access(
        context, 'share', share_id, access_type, access_to)


def _check_for_existing_access(context, resource, resource_id, access_type,
                               access_to):

    session = get_session()
    if resource == 'share':
        query_method = _share_access_get_query
        access_to_field = models.ShareAccessMapping.access_to
    else:
        query_method = _share_snapshot_access_get_query
        access_to_field = models.ShareSnapshotAccessMapping.access_to

    with session.begin():
        if access_type == 'ip':
            rules = query_method(
                context, session, {'%s_id' % resource: resource_id,
                                   'access_type': access_type}).filter(
                access_to_field.startswith(access_to.split('/')[0])).all()

            matching_rules = [
                rule for rule in rules if
                ipaddress.ip_network(str(access_to)) ==
                ipaddress.ip_network(str(rule['access_to']))
            ]
            return len(matching_rules) > 0
        else:
            return query_method(
                context, session, {'%s_id' % resource: resource_id,
                                   'access_type': access_type,
                                   'access_to': access_to}).count() > 0


@require_context
def share_access_delete_all_by_share(context, share_id):
    session = get_session()
    with session.begin():
        (session.query(models.ShareAccessMapping).
            filter_by(share_id=share_id).soft_delete())


@require_context
def share_instance_access_delete(context, mapping_id):
    session = get_session()
    with session.begin():

        mapping = (session.query(models.ShareInstanceAccessMapping).
                   filter_by(id=mapping_id).first())

        if not mapping:
            exception.NotFound()

        filters = {
            'resource_id': mapping['access_id'],
            'all_projects': True
        }
        locks, __ = resource_lock_get_all(
            context.elevated(), filters=filters
        )
        if locks:
            for lock in locks:
                resource_lock_delete(
                    context.elevated(), lock['id']
                )

        mapping.soft_delete(session, update_status=True,
                            status_field_name='state')

        other_mappings = _share_instance_access_query(
            context, session, mapping['access_id']).all()

        # NOTE(u_glide): Remove access rule if all mappings were removed.
        if len(other_mappings) == 0:
            (session.query(models.ShareAccessRulesMetadata).filter_by(
                access_id=mapping['access_id']).soft_delete())

            (session.query(models.ShareAccessMapping).filter_by(
                id=mapping['access_id']).soft_delete())


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_instance_access_update(context, access_id, instance_id, updates):
    session = get_session()
    share_access_fields = ('access_type', 'access_to', 'access_key',
                           'access_level')

    share_access_map_updates, share_instance_access_map_updates = (
        _extract_subdict_by_fields(updates, share_access_fields)
    )
    updated_at = timeutils.utcnow()
    share_access_map_updates['updated_at'] = updated_at
    share_instance_access_map_updates['updated_at'] = updated_at

    with session.begin():
        share_access = _share_access_get_query(
            context, session, {'id': access_id}).first()
        share_access.update(share_access_map_updates)
        share_access.save(session=session)

        access = _share_instance_access_query(
            context, session, access_id, instance_id).first()
        access.update(share_instance_access_map_updates)
        access.save(session=session)

        return access

###################


@require_context
def share_snapshot_instance_create(context, snapshot_id, values, session=None):
    session = session or get_session()
    values = copy.deepcopy(values)
    values['share_snapshot_metadata'] = _metadata_refs(
        values.get('metadata'), models.ShareSnapshotMetadata)

    _change_size_to_instance_size(values)

    if not values.get('id'):
        values['id'] = uuidutils.generate_uuid()
    values.update({'snapshot_id': snapshot_id})

    instance_ref = models.ShareSnapshotInstance()
    instance_ref.update(values)
    instance_ref.save(session=session)

    return share_snapshot_instance_get(context, instance_ref['id'],
                                       session=session)


@require_context
def share_snapshot_instance_update(context, instance_id, values):
    session = get_session()
    instance_ref = share_snapshot_instance_get(context, instance_id,
                                               session=session)
    _change_size_to_instance_size(values)

    # NOTE(u_glide): Ignore updates to custom properties
    for extra_key in models.ShareSnapshotInstance._extra_keys:
        if extra_key in values:
            values.pop(extra_key)

    instance_ref.update(values)
    instance_ref.save(session=session)
    return instance_ref


@require_context
def share_snapshot_instance_delete(context, snapshot_instance_id,
                                   session=None):
    session = session or get_session()

    with session.begin():

        snapshot_instance_ref = share_snapshot_instance_get(
            context, snapshot_instance_id, session=session)

        access_rules = share_snapshot_access_get_all_for_snapshot_instance(
            context, snapshot_instance_id, session=session)
        for rule in access_rules:
            share_snapshot_instance_access_delete(
                context, rule['access_id'], snapshot_instance_id)

        for el in snapshot_instance_ref.export_locations:
            share_snapshot_instance_export_location_delete(context, el['id'])

        snapshot_instance_ref.soft_delete(
            session=session, update_status=True)
        snapshot = share_snapshot_get(
            context, snapshot_instance_ref['snapshot_id'], session=session)
        if len(snapshot.instances) == 0:
            session.query(models.ShareSnapshotMetadata).filter_by(
                share_snapshot_id=snapshot['id']).soft_delete()
            snapshot.soft_delete(session=session)


@require_context
def share_snapshot_instance_get(context, snapshot_instance_id, session=None,
                                with_share_data=False):

    session = session or get_session()

    result = _share_snapshot_instance_get_with_filters(
        context, instance_ids=[snapshot_instance_id], session=session).first()

    if result is None:
        raise exception.ShareSnapshotInstanceNotFound(
            instance_id=snapshot_instance_id)

    if with_share_data:
        result = _set_share_snapshot_instance_data(context, result, session)[0]

    return result


@require_context
def share_snapshot_instance_get_all_with_filters(context, search_filters,
                                                 with_share_data=False,
                                                 session=None):
    """Get snapshot instances filtered by known attrs, ignore unknown attrs.

    All filters accept list/tuples to filter on, along with simple values.
    """
    def listify(values):
        if values:
            if not isinstance(values, (list, tuple, set)):
                return values,
            else:
                return values

    session = session or get_session()
    _known_filters = ('instance_ids', 'snapshot_ids', 'share_instance_ids',
                      'statuses')

    filters = {k: listify(search_filters.get(k)) for k in _known_filters}

    result = _share_snapshot_instance_get_with_filters(
        context, session=session, **filters).all()

    if with_share_data:
        result = _set_share_snapshot_instance_data(context, result, session)

    return result


def _share_snapshot_instance_get_with_filters(context, instance_ids=None,
                                              snapshot_ids=None, statuses=None,
                                              share_instance_ids=None,
                                              session=None):

    query = model_query(context, models.ShareSnapshotInstance, session=session,
                        read_deleted="no")

    if instance_ids is not None:
        query = query.filter(
            models.ShareSnapshotInstance.id.in_(instance_ids))

    if snapshot_ids is not None:
        query = query.filter(
            models.ShareSnapshotInstance.snapshot_id.in_(snapshot_ids))

    if share_instance_ids is not None:
        query = query.filter(models.ShareSnapshotInstance.share_instance_id
                             .in_(share_instance_ids))

    if statuses is not None:
        query = query.filter(models.ShareSnapshotInstance.status.in_(statuses))

    query = query.options(joinedload('share_group_snapshot'))
    return query


def _set_share_snapshot_instance_data(context, snapshot_instances, session):
    if snapshot_instances and not isinstance(snapshot_instances, list):
        snapshot_instances = [snapshot_instances]

    for snapshot_instance in snapshot_instances:
        share_instance = share_instance_get(
            context, snapshot_instance['share_instance_id'], session=session,
            with_share_data=True)
        snapshot_instance['share'] = share_instance

    return snapshot_instances


###################


@require_context
def share_snapshot_create(context, create_values,
                          create_snapshot_instance=True):
    values = copy.deepcopy(create_values)
    values = ensure_model_dict_has_id(values)
    values['share_snapshot_metadata'] = _metadata_refs(
        values.pop('metadata', {}), models.ShareSnapshotMetadata)

    snapshot_ref = models.ShareSnapshot()
    snapshot_instance_values, snapshot_values = (
        _extract_snapshot_instance_values(values)
    )
    share_ref = share_get(context, snapshot_values.get('share_id'))
    snapshot_instance_values.update(
        {'share_instance_id': share_ref.instance.id}
    )

    snapshot_ref.update(snapshot_values)
    session = get_session()
    with session.begin():
        snapshot_ref.save(session=session)

        if create_snapshot_instance:
            share_snapshot_instance_create(
                context,
                snapshot_ref['id'],
                snapshot_instance_values,
                session=session
            )
        return share_snapshot_get(
            context, snapshot_values['id'], session=session)


@require_admin_context
def _snapshot_data_get_for_project(
    context, project_id, user_id, share_type_id=None,
):
    query = model_query(
        context, models.ShareSnapshot,
        func.count(models.ShareSnapshot.id),
        func.sum(models.ShareSnapshot.size),
        read_deleted="no",
    ).filter_by(project_id=project_id)
    if share_type_id:
        query = query.join(
            models.ShareInstance,
            models.ShareInstance.share_id == models.ShareSnapshot.share_id,
        ).filter_by(share_type_id=share_type_id)
    elif user_id:
        query = query.filter_by(user_id=user_id)
    result = query.first()

    return result[0] or 0, result[1] or 0


@require_context
def share_snapshot_get(context, snapshot_id, project_only=True, session=None):
    result = (model_query(context, models.ShareSnapshot, session=session,
                          project_only=project_only).
              filter_by(id=snapshot_id).
              options(joinedload('share')).
              options(joinedload('instances')).
              options(joinedload('share_snapshot_metadata')).
              first())

    if not result:
        raise exception.ShareSnapshotNotFound(snapshot_id=snapshot_id)

    return result


def _share_snapshot_get_all_with_filters(context, project_id=None,
                                         share_id=None, filters=None,
                                         limit=None, offset=None,
                                         sort_key=None, sort_dir=None,
                                         show_count=False):
    """Retrieves all snapshots.

    If no sorting parameters are specified then returned snapshots are sorted
    by the 'created_at' key and desc order.

    :param context: context to query under
    :param filters: dictionary of filters
    :param limit: maximum number of items to return
    :param sort_key: attribute by which results should be sorted,default is
                     created_at
    :param sort_dir: direction in which results should be sorted
    :returns: list of matching snapshots
    """
    # Init data
    sort_key = sort_key or 'created_at'
    sort_dir = sort_dir or 'desc'
    filters = copy.deepcopy(filters) if filters else {}
    query = model_query(context, models.ShareSnapshot)

    if project_id:
        query = query.filter_by(project_id=project_id)
    if share_id:
        query = query.filter_by(share_id=share_id)
    query = (query.options(joinedload('share'))
             .options(joinedload('instances'))
             .options(joinedload('share_snapshot_metadata'))
             )

    # Snapshots with no instances are filtered out.
    query = query.filter(
        models.ShareSnapshot.id == models.ShareSnapshotInstance.snapshot_id)

    # Apply filters
    if 'usage' in filters:
        usage_filter_keys = ['any', 'used', 'unused']
        if filters['usage'] == 'any':
            pass
        elif filters['usage'] == 'used':
            query = query.filter(models.Share.snapshot_id == (
                models.ShareSnapshot.id))
        elif filters['usage'] == 'unused':
            query = query.filter(models.Share.snapshot_id != (
                models.ShareSnapshot.id))
        else:
            msg = _("Wrong 'usage' key provided - '%(key)s'. "
                    "Expected keys are '%(ek)s'.") % {
                        'key': filters['usage'],
                        'ek': usage_filter_keys}
            raise exception.InvalidInput(reason=msg)
        filters.pop('usage')
    if 'status' in filters:
        query = query.filter(models.ShareSnapshotInstance.status == (
            filters['status']))
        filters.pop('status')
    if 'metadata' in filters:
        for k, v in filters['metadata'].items():
            # pylint: disable=no-member
            query = query.filter(
                or_(models.ShareSnapshot.share_snapshot_metadata.any(
                    key=k, value=v)))
        filters.pop('metadata')

    legal_filter_keys = ('display_name', 'display_name~',
                         'display_description', 'display_description~',
                         'id', 'user_id', 'project_id', 'share_id',
                         'share_proto', 'size', 'share_size')
    query = exact_filter(query, models.ShareSnapshot,
                         filters, legal_filter_keys)

    query = apply_sorting(models.ShareSnapshot, query, sort_key, sort_dir)

    count = None
    if show_count:
        count = query.count()

    if limit is not None:
        query = query.limit(limit)

    if offset:
        query = query.offset(offset)

    # Returns list of share snapshots that satisfy filters
    query = query.all()

    if show_count:
        return count, query

    return query


@require_admin_context
def share_snapshot_get_all(context, filters=None, limit=None, offset=None,
                           sort_key=None, sort_dir=None):
    return _share_snapshot_get_all_with_filters(
        context, filters=filters, limit=limit,
        offset=offset, sort_key=sort_key, sort_dir=sort_dir)


@require_admin_context
def share_snapshot_get_all_with_count(context, filters=None, limit=None,
                                      offset=None, sort_key=None,
                                      sort_dir=None):
    count, query = _share_snapshot_get_all_with_filters(
        context, filters=filters, limit=limit,
        offset=offset, sort_key=sort_key, sort_dir=sort_dir,
        show_count=True)
    return count, query


@require_context
def share_snapshot_get_all_by_project(context, project_id, filters=None,
                                      limit=None, offset=None,
                                      sort_key=None, sort_dir=None):
    authorize_project_context(context, project_id)
    return _share_snapshot_get_all_with_filters(
        context, project_id=project_id, filters=filters, limit=limit,
        offset=offset, sort_key=sort_key, sort_dir=sort_dir)


@require_context
def share_snapshot_get_all_by_project_with_count(context, project_id,
                                                 filters=None, limit=None,
                                                 offset=None, sort_key=None,
                                                 sort_dir=None):
    authorize_project_context(context, project_id)
    count, query = _share_snapshot_get_all_with_filters(
        context, project_id=project_id, filters=filters, limit=limit,
        offset=offset, sort_key=sort_key, sort_dir=sort_dir,
        show_count=True)
    return count, query


@require_context
def share_snapshot_get_all_for_share(context, share_id, filters=None,
                                     sort_key=None, sort_dir=None):
    return _share_snapshot_get_all_with_filters(
        context, share_id=share_id,
        filters=filters, sort_key=sort_key, sort_dir=sort_dir,
    )


@require_context
def share_snapshot_get_latest_for_share(context, share_id):

    snapshots = _share_snapshot_get_all_with_filters(
        context, share_id=share_id, sort_key='created_at', sort_dir='desc')
    return snapshots[0] if snapshots else None


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_snapshot_update(context, snapshot_id, values):
    session = get_session()
    with session.begin():
        snapshot_ref = share_snapshot_get(context, snapshot_id,
                                          session=session)

        instance_values, snapshot_values = (
            _extract_snapshot_instance_values(values)
        )

        if snapshot_values:
            snapshot_ref.update(snapshot_values)
            snapshot_ref.save(session=session)

        if instance_values:
            snapshot_ref.instance.update(instance_values)
            snapshot_ref.instance.save(session=session)

        return snapshot_ref


@require_context
def share_snapshot_instances_status_update(
        context, snapshot_instance_ids, values, session=None):
    session = session or get_session()

    result = (
        model_query(
            context, models.ShareSnapshotInstance,
            read_deleted="no", session=session).filter(
            models.ShareSnapshotInstance.id.in_(snapshot_instance_ids)
            ).update(values, synchronize_session=False))

    return result


###################################
# Share Snapshot Metadata functions
###################################

@require_context
@require_share_snapshot_exists
def share_snapshot_metadata_get(context, share_snapshot_id):
    session = get_session()
    return _share_snapshot_metadata_get(context,
                                        share_snapshot_id, session=session)


@require_context
@require_share_snapshot_exists
def share_snapshot_metadata_delete(context, share_snapshot_id, key):
    session = get_session()
    meta_ref = _share_snapshot_metadata_get_item(
        context, share_snapshot_id, key, session=session)
    meta_ref.soft_delete(session=session)


@require_context
@require_share_snapshot_exists
def share_snapshot_metadata_update(context, share_snapshot_id,
                                   metadata, delete):
    session = get_session()
    return _share_snapshot_metadata_update(context, share_snapshot_id,
                                           metadata, delete,
                                           session=session)


def share_snapshot_metadata_update_item(context, share_snapshot_id,
                                        item):
    session = get_session()
    return _share_snapshot_metadata_update(context, share_snapshot_id,
                                           item, delete=False,
                                           session=session)


def share_snapshot_metadata_get_item(context, share_snapshot_id,
                                     key):

    session = get_session()
    row = _share_snapshot_metadata_get_item(context, share_snapshot_id,
                                            key, session=session)
    result = {}
    result[row['key']] = row['value']

    return result


def _share_snapshot_metadata_get_query(context, share_snapshot_id,
                                       session=None):
    session = session or get_session()
    return (model_query(context, models.ShareSnapshotMetadata,
                        session=session,
                        read_deleted="no").
            filter_by(share_snapshot_id=share_snapshot_id).
            options(joinedload('share_snapshot')))


def _share_snapshot_metadata_get(context, share_snapshot_id, session=None):
    session = session or get_session()
    rows = _share_snapshot_metadata_get_query(context, share_snapshot_id,
                                              session=session).all()

    result = {}
    for row in rows:
        result[row['key']] = row['value']
    return result


def _share_snapshot_metadata_get_item(context, share_snapshot_id,
                                      key, session=None):
    session = session or get_session()
    result = (_share_snapshot_metadata_get_query(
        context, share_snapshot_id, session=session).filter_by(
            key=key).first())
    if not result:
        raise exception.MetadataItemNotFound
    return result


@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def _share_snapshot_metadata_update(context, share_snapshot_id,
                                    metadata, delete, session=None):
    session = session or get_session()
    delete = strutils.bool_from_string(delete)
    with session.begin():
        if delete:
            original_metadata = _share_snapshot_metadata_get(
                context, share_snapshot_id, session=session)
            for meta_key, meta_value in original_metadata.items():
                if meta_key not in metadata:
                    meta_ref = _share_snapshot_metadata_get_item(
                        context, share_snapshot_id, meta_key,
                        session=session)
                    meta_ref.soft_delete(session=session)
        meta_ref = None
        # Now update all existing items with new values, or create new meta
        # objects
        for meta_key, meta_value in metadata.items():

            # update the value whether it exists or not
            item = {"value": meta_value}
            meta_ref = _share_snapshot_metadata_get_query(
                context, share_snapshot_id,
                session=session).filter_by(
                key=meta_key).first()
            if not meta_ref:
                meta_ref = models.ShareSnapshotMetadata()
                item.update({"key": meta_key,
                             "share_snapshot_id": share_snapshot_id})
            meta_ref.update(item)
            meta_ref.save(session=session)

        return metadata

#################################


@require_context
def share_snapshot_access_create(context, values):
    values = ensure_model_dict_has_id(values)
    session = get_session()
    with session.begin():
        access_ref = models.ShareSnapshotAccessMapping()
        access_ref.update(values)
        access_ref.save(session=session)

        snapshot = share_snapshot_get(context, values['share_snapshot_id'],
                                      session=session)

        for instance in snapshot.instances:
            vals = {
                'share_snapshot_instance_id': instance['id'],
                'access_id': access_ref['id'],
            }

            _share_snapshot_instance_access_create(vals, session)

    return share_snapshot_access_get(context, access_ref['id'])


def _share_snapshot_access_get_query(context, session, filters,
                                     read_deleted='no'):

    query = model_query(context, models.ShareSnapshotAccessMapping,
                        session=session, read_deleted=read_deleted)
    return query.filter_by(**filters)


def _share_snapshot_instance_access_get_query(context, session,
                                              access_id=None,
                                              share_snapshot_instance_id=None):
    filters = {'deleted': 'False'}

    if access_id is not None:
        filters.update({'access_id': access_id})

    if share_snapshot_instance_id is not None:
        filters.update(
            {'share_snapshot_instance_id': share_snapshot_instance_id})

    return model_query(context, models.ShareSnapshotInstanceAccessMapping,
                       session=session).filter_by(**filters)


@require_context
def share_snapshot_instance_access_get_all(context, access_id, session):
    rules = _share_snapshot_instance_access_get_query(
        context, session, access_id=access_id).all()
    return rules


@require_context
def share_snapshot_access_get(context, access_id, session=None):
    session = session or get_session()

    access = _share_snapshot_access_get_query(
        context, session, {'id': access_id}).first()

    if access:
        return access
    else:
        raise exception.NotFound()


def _share_snapshot_instance_access_create(values, session):
    access_ref = models.ShareSnapshotInstanceAccessMapping()
    access_ref.update(ensure_model_dict_has_id(values))
    access_ref.save(session=session)
    return access_ref


@require_context
def share_snapshot_access_get_all_for_share_snapshot(context,
                                                     share_snapshot_id,
                                                     filters):
    session = get_session()
    filters['share_snapshot_id'] = share_snapshot_id
    access_list = _share_snapshot_access_get_query(
        context, session, filters).all()

    return access_list


@require_context
def share_snapshot_check_for_existing_access(context, share_snapshot_id,
                                             access_type, access_to):
    return _check_for_existing_access(
        context, 'share_snapshot', share_snapshot_id, access_type, access_to)


@require_context
def share_snapshot_access_get_all_for_snapshot_instance(
        context, snapshot_instance_id, filters=None,
        with_snapshot_access_data=True, session=None):
    """Get all access rules related to a certain snapshot instance."""
    session = session or get_session()
    filters = copy.deepcopy(filters) if filters else {}
    filters.update({'share_snapshot_instance_id': snapshot_instance_id})

    query = _share_snapshot_instance_access_get_query(context, session)

    legal_filter_keys = (
        'id', 'share_snapshot_instance_id', 'access_id', 'state')

    query = exact_filter(
        query, models.ShareSnapshotInstanceAccessMapping, filters,
        legal_filter_keys)

    instance_accesses = query.all()

    if with_snapshot_access_data:
        instance_accesses = _set_instances_snapshot_access_data(
            context, instance_accesses, session)

    return instance_accesses


@require_context
def share_snapshot_instance_access_update(
        context, access_id, instance_id, updates):

    snapshot_access_fields = ('access_type', 'access_to')
    snapshot_access_map_updates, share_instance_access_map_updates = (
        _extract_subdict_by_fields(updates, snapshot_access_fields)
    )

    updated_at = timeutils.utcnow()
    snapshot_access_map_updates['updated_at'] = updated_at
    share_instance_access_map_updates['updated_at'] = updated_at

    session = get_session()
    with session.begin():

        snapshot_access = _share_snapshot_access_get_query(
            context, session, {'id': access_id}).first()
        if not snapshot_access:
            raise exception.NotFound()
        snapshot_access.update(snapshot_access_map_updates)
        snapshot_access.save(session=session)

        access = _share_snapshot_instance_access_get_query(
            context, session, access_id=access_id,
            share_snapshot_instance_id=instance_id).first()
        if not access:
            raise exception.NotFound()
        access.update(share_instance_access_map_updates)
        access.save(session=session)

        return access


@require_context
def share_snapshot_instance_access_get(
        context, access_id, share_snapshot_instance_id,
        with_snapshot_access_data=True):

    session = get_session()

    with session.begin():
        access = _share_snapshot_instance_access_get_query(
            context, session, access_id=access_id,
            share_snapshot_instance_id=share_snapshot_instance_id).first()

        if access is None:
            raise exception.NotFound()

        if with_snapshot_access_data:
            return _set_instances_snapshot_access_data(
                context, access, session)[0]
        else:
            return access


@require_context
def share_snapshot_instance_access_delete(
        context, access_id, snapshot_instance_id):
    session = get_session()
    with session.begin():

        rule = _share_snapshot_instance_access_get_query(
            context, session, access_id=access_id,
            share_snapshot_instance_id=snapshot_instance_id).first()

        if not rule:
            exception.NotFound()

        rule.soft_delete(session, update_status=True,
                         status_field_name='state')

        other_mappings = share_snapshot_instance_access_get_all(
            context, rule['access_id'], session)

        if len(other_mappings) == 0:
            (
                session.query(models.ShareSnapshotAccessMapping)
                .filter_by(id=rule['access_id'])
                .soft_delete(update_status=True, status_field_name='state')
            )


@require_context
def share_snapshot_instance_export_location_create(context, values):

    values = ensure_model_dict_has_id(values)
    session = get_session()
    with session.begin():
        ssiel = models.ShareSnapshotInstanceExportLocation()
        ssiel.update(values)
        ssiel.save(session=session)

        return ssiel


def _share_snapshot_instance_export_locations_get_query(context, session,
                                                        values):
    query = model_query(context, models.ShareSnapshotInstanceExportLocation,
                        session=session)
    return query.filter_by(**values)


@require_context
def share_snapshot_export_locations_get(context, snapshot_id):
    session = get_session()
    snapshot = share_snapshot_get(context, snapshot_id, session=session)
    ins_ids = [ins['id'] for ins in snapshot.instances]
    export_locations = _share_snapshot_instance_export_locations_get_query(
        context, session, {}).filter(
        models.ShareSnapshotInstanceExportLocation.
            share_snapshot_instance_id.in_(ins_ids)).all()
    return export_locations


@require_context
def share_snapshot_instance_export_locations_get_all(
        context, share_snapshot_instance_id, session=None):

    if not session:
        session = get_session()
    export_locations = _share_snapshot_instance_export_locations_get_query(
        context, session,
        {'share_snapshot_instance_id': share_snapshot_instance_id}).all()
    return export_locations


@require_context
def share_snapshot_instance_export_location_get(context, el_id):
    session = get_session()

    export_location = _share_snapshot_instance_export_locations_get_query(
        context, session, {'id': el_id}).first()

    if export_location:
        return export_location
    else:
        raise exception.NotFound()


@require_context
def share_snapshot_instance_export_location_delete(context, el_id):
    session = get_session()
    with session.begin():

        el = _share_snapshot_instance_export_locations_get_query(
            context, session, {'id': el_id}).first()

        if not el:
            exception.NotFound()

        el.soft_delete(session=session)


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_snapshot_instance_export_locations_update(
        context, share_snapshot_instance_id, export_locations, delete):
    # NOTE(dviroel): Lets keep this backward compatibility for driver that
    # may still return export_locations as string
    if not isinstance(export_locations, (list, tuple, set)):
        export_locations = (export_locations, )
    export_locations_as_dicts = []
    for el in export_locations:
        export_location = el
        if isinstance(el, str):
            export_location = {
                "path": el,
                "is_admin_only": False,
            }
        elif not isinstance(export_location, dict):
            raise exception.ManilaException(
                _("Wrong export location type '%s'.") % type(export_location))
        export_locations_as_dicts.append(export_location)
    export_locations = export_locations_as_dicts

    export_locations_paths = [el['path'] for el in export_locations]

    session = get_session()

    current_el_rows = share_snapshot_instance_export_locations_get_all(
        context, share_snapshot_instance_id, session=session)

    def get_path_list_from_rows(rows):
        return set([row['path'] for row in rows])

    current_el_paths = get_path_list_from_rows(current_el_rows)

    def create_indexed_time_dict(key_list):
        base = timeutils.utcnow()
        return {
            # NOTE(u_glide): Incrementing timestamp by microseconds to make
            # timestamp order match index order.
            key: base + datetime.timedelta(microseconds=index)
            for index, key in enumerate(key_list)
        }

    indexed_update_time = create_indexed_time_dict(export_locations_paths)

    for el in current_el_rows:
        if delete and el['path'] not in export_locations_paths:
            el.soft_delete(session)
        else:
            updated_at = indexed_update_time[el['path']]
            el.update({
                'updated_at': updated_at,
            })
            el.save(session=session)

    # Now add new export locations
    for el in export_locations:
        if el['path'] in current_el_paths:
            # Already updated
            continue

        location_ref = models.ShareSnapshotInstanceExportLocation()
        location_ref.update({
            'id': uuidutils.generate_uuid(),
            'path': el['path'],
            'share_snapshot_instance_id': share_snapshot_instance_id,
            'updated_at': indexed_update_time[el['path']],
            'is_admin_only': el.get('is_admin_only', False),
        })
        location_ref.save(session=session)

    return get_path_list_from_rows(
        share_snapshot_instance_export_locations_get_all(
            context, share_snapshot_instance_id, session=session))

#################################


def _share_metadata_get_query(context, share_id):
    return model_query(
        context, models.ShareMetadata, read_deleted="no",
    ).filter_by(share_id=share_id).options(joinedload('share'))


@require_context
@require_share_exists
@context_manager.reader
def share_metadata_get(context, share_id):
    return _share_metadata_get(context, share_id)


def _share_metadata_get(context, share_id):
    rows = _share_metadata_get_query(context, share_id).all()
    result = {}
    for row in rows:
        result[row['key']] = row['value']

    return result


@require_context
@require_share_exists
@context_manager.reader
def share_metadata_get_item(context, share_id, key):
    try:
        row = _share_metadata_get_item(context, share_id, key)
    except exception.MetadataItemNotFound:
        raise exception.MetadataItemNotFound()

    result = {}
    result[row['key']] = row['value']

    return result


@require_context
@require_share_exists
@context_manager.writer
def share_metadata_delete(context, share_id, key):
    _share_metadata_get_query(
        context, share_id,
    ).filter_by(key=key).soft_delete()


@require_context
@require_share_exists
@context_manager.writer
def share_metadata_update(context, share_id, metadata, delete):
    return _share_metadata_update(context, share_id, metadata, delete)


@require_context
@require_share_exists
@context_manager.writer
def share_metadata_update_item(context, share_id, item):
    return _share_metadata_update(context, share_id, item, delete=False)


@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def _share_metadata_update(context, share_id, metadata, delete):
    # Set existing metadata to deleted if delete argument is True
    delete = strutils.bool_from_string(delete)
    if delete:
        original_metadata = _share_metadata_get(context, share_id)
        for meta_key, meta_value in original_metadata.items():
            if meta_key not in metadata:
                meta_ref = _share_metadata_get_item(
                    context, share_id, meta_key,
                )
                meta_ref.soft_delete(session=context.session)

    meta_ref = None

    # Now update all existing items with new values, or create new meta
    # objects
    for meta_key, meta_value in metadata.items():

        # update the value whether it exists or not
        item = {"value": meta_value}

        try:
            meta_ref = _share_metadata_get_item(
                context, share_id, meta_key,
            )
        except exception.MetadataItemNotFound:
            meta_ref = models.ShareMetadata()
            item.update({"key": meta_key, "share_id": share_id})

        meta_ref.update(item)
        meta_ref.save(session=context.session)

    return metadata


def _share_metadata_get_item(context, share_id, key):
    result = _share_metadata_get_query(
        context, share_id,
    ).filter_by(key=key).first()

    if not result:
        raise exception.MetadataItemNotFound()
    return result


############################
# Export locations functions
############################

def _share_export_locations_get(context, share_instance_ids,
                                include_admin_only=True,
                                ignore_secondary_replicas=False, session=None):
    session = session or get_session()

    if not isinstance(share_instance_ids, (set, list, tuple)):
        share_instance_ids = (share_instance_ids, )

    query = model_query(
        context,
        models.ShareInstanceExportLocations,
        session=session,
        read_deleted="no",
    ).filter(
        models.ShareInstanceExportLocations.share_instance_id.in_(
            share_instance_ids),
    ).order_by(
        "updated_at",
    ).options(
        joinedload("_el_metadata_bare"),
    )

    if not include_admin_only:
        query = query.filter_by(is_admin_only=False)

    if ignore_secondary_replicas:
        replica_state_attr = models.ShareInstance.replica_state
        query = query.join("share_instance").filter(
            or_(replica_state_attr == None,  # noqa
                replica_state_attr == constants.REPLICA_STATE_ACTIVE))

    return query.all()


@require_context
@require_share_exists
def share_export_locations_get_by_share_id(context, share_id,
                                           include_admin_only=True,
                                           ignore_migration_destination=False,
                                           ignore_secondary_replicas=False):
    share = share_get(context, share_id)
    if ignore_migration_destination:
        ids = [instance.id for instance in share.instances
               if instance['status'] != constants.STATUS_MIGRATING_TO]
    else:
        ids = [instance.id for instance in share.instances]
    rows = _share_export_locations_get(
        context, ids, include_admin_only=include_admin_only,
        ignore_secondary_replicas=ignore_secondary_replicas)
    return rows


@require_context
@require_share_instance_exists
def share_export_locations_get_by_share_instance_id(context,
                                                    share_instance_id,
                                                    include_admin_only=True):
    rows = _share_export_locations_get(
        context, [share_instance_id], include_admin_only=include_admin_only)
    return rows


@require_context
@require_share_exists
def share_export_locations_get(context, share_id):
    # NOTE(vponomaryov): this method is kept for compatibility with
    # old approach. New one uses 'share_export_locations_get_by_share_id'.
    # Which returns list of dicts instead of list of strings, as this one does.
    share = share_get(context, share_id)
    rows = _share_export_locations_get(
        context, share.instance.id, context.is_admin)

    return [location['path'] for location in rows]


@require_context
def share_export_location_get_by_uuid(context, export_location_uuid,
                                      ignore_secondary_replicas=False,
                                      session=None):
    session = session or get_session()

    query = model_query(
        context,
        models.ShareInstanceExportLocations,
        session=session,
        read_deleted="no",
    ).filter_by(
        uuid=export_location_uuid,
    ).options(
        joinedload("_el_metadata_bare"),
    )

    if ignore_secondary_replicas:
        replica_state_attr = models.ShareInstance.replica_state
        query = query.join("share_instance").filter(
            or_(replica_state_attr == None,  # noqa
                replica_state_attr == constants.REPLICA_STATE_ACTIVE))

    result = query.first()
    if not result:
        raise exception.ExportLocationNotFound(uuid=export_location_uuid)
    return result


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def share_export_locations_update(context, share_instance_id, export_locations,
                                  delete):
    # NOTE(u_glide):
    # Backward compatibility code for drivers,
    # which return single export_location as string
    if not isinstance(export_locations, (list, tuple, set)):
        export_locations = (export_locations, )
    export_locations_as_dicts = []
    for el in export_locations:
        # NOTE(vponomaryov): transform old export locations view to new one
        export_location = el
        if isinstance(el, str):
            export_location = {
                "path": el,
                "is_admin_only": False,
                "metadata": {},
            }
        elif isinstance(export_location, dict):
            if 'metadata' not in export_location:
                export_location['metadata'] = {}
        else:
            raise exception.ManilaException(
                _("Wrong export location type '%s'.") % type(export_location))
        export_locations_as_dicts.append(export_location)
    export_locations = export_locations_as_dicts

    export_locations_paths = [el['path'] for el in export_locations]

    session = get_session()

    current_el_rows = _share_export_locations_get(
        context, share_instance_id, session=session)

    def get_path_list_from_rows(rows):
        return set([row['path'] for row in rows])

    current_el_paths = get_path_list_from_rows(current_el_rows)

    def create_indexed_time_dict(key_list):
        base = timeutils.utcnow()
        return {
            # NOTE(u_glide): Incrementing timestamp by microseconds to make
            # timestamp order match index order.
            key: base + datetime.timedelta(microseconds=index)
            for index, key in enumerate(key_list)
        }

    indexed_update_time = create_indexed_time_dict(export_locations_paths)

    for el in current_el_rows:
        if delete and el['path'] not in export_locations_paths:
            export_location_metadata_delete(context, el['uuid'])
            el.soft_delete(session)
        else:
            updated_at = indexed_update_time[el['path']]
            el.update({
                'updated_at': updated_at,
                'deleted': 0,
            })
            el.save(session=session)
            if el['el_metadata']:
                export_location_metadata_update(
                    context, el['uuid'], el['el_metadata'], session=session)

    # Now add new export locations
    for el in export_locations:
        if el['path'] in current_el_paths:
            # Already updated
            continue

        location_ref = models.ShareInstanceExportLocations()
        location_ref.update({
            'uuid': uuidutils.generate_uuid(),
            'path': el['path'],
            'share_instance_id': share_instance_id,
            'updated_at': indexed_update_time[el['path']],
            'deleted': 0,
            'is_admin_only': el.get('is_admin_only', False),
        })
        location_ref.save(session=session)
        if not el.get('metadata'):
            continue
        export_location_metadata_update(
            context, location_ref['uuid'], el.get('metadata'), session=session)

    return get_path_list_from_rows(_share_export_locations_get(
        context, share_instance_id, session=session))


#####################################
# Export locations metadata functions
#####################################

def _export_location_metadata_get_query(context, export_location_uuid,
                                        session=None):
    session = session or get_session()
    export_location_id = share_export_location_get_by_uuid(
        context, export_location_uuid).id

    return model_query(
        context, models.ShareInstanceExportLocationsMetadata, session=session,
        read_deleted="no",
    ).filter_by(
        export_location_id=export_location_id,
    )


@require_context
def export_location_metadata_get(context, export_location_uuid, session=None):
    rows = _export_location_metadata_get_query(
        context, export_location_uuid, session=session).all()
    result = {}
    for row in rows:
        result[row["key"]] = row["value"]
    return result


@require_context
def export_location_metadata_delete(context, export_location_uuid, keys=None):
    session = get_session()
    metadata = _export_location_metadata_get_query(
        context, export_location_uuid, session=session,
    )
    # NOTE(vponomaryov): if keys is None then we delete all metadata.
    if keys is not None:
        keys = keys if isinstance(keys, (list, set, tuple)) else (keys, )
        metadata = metadata.filter(
            models.ShareInstanceExportLocationsMetadata.key.in_(keys))
    metadata = metadata.all()
    for meta_ref in metadata:
        meta_ref.soft_delete(session=session)


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def export_location_metadata_update(context, export_location_uuid, metadata,
                                    delete=False, session=None):
    session = session or get_session()
    if delete:
        original_metadata = export_location_metadata_get(
            context, export_location_uuid, session=session)
        keys_for_deletion = set(original_metadata).difference(metadata)
        if keys_for_deletion:
            export_location_metadata_delete(
                context, export_location_uuid, keys=keys_for_deletion)

    el = share_export_location_get_by_uuid(context, export_location_uuid)
    for meta_key, meta_value in metadata.items():
        # NOTE(vponomaryov): we should use separate session
        # for each meta_ref because of autoincrement of integer primary key
        # that will not take effect using one session and we will rewrite,
        # in that case, single record - first one added with this call.
        session = get_session()

        if meta_value is None:
            LOG.warning("%s should be properly defined in the driver.",
                        meta_key)

        item = {"value": meta_value, "updated_at": timeutils.utcnow()}

        meta_ref = _export_location_metadata_get_query(
            context, export_location_uuid, session=session,
        ).filter_by(
            key=meta_key,
        ).first()

        if not meta_ref:
            meta_ref = models.ShareInstanceExportLocationsMetadata()
            item.update({
                "key": meta_key,
                "export_location_id": el.id,
            })

        meta_ref.update(item)
        meta_ref.save(session=session)

    return metadata


###################################


def _security_service_get_query(context, project_only=False):
    return model_query(
        context, models.SecurityService, project_only=project_only,
    )


@require_context
@context_manager.writer
def security_service_create(context, values):
    values = ensure_model_dict_has_id(values)

    security_service_ref = models.SecurityService()
    security_service_ref.update(values)
    security_service_ref.save(session=context.session)

    return security_service_ref


@require_context
@context_manager.writer
def security_service_delete(context, id):
    security_service_ref = _security_service_get(context, id)
    security_service_ref.soft_delete(session=context.session)


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
@context_manager.writer
def security_service_update(context, id, values):
    security_service_ref = _security_service_get(context, id)
    security_service_ref.update(values)
    security_service_ref.save(session=context.session)
    return security_service_ref


@require_context
@context_manager.reader
def security_service_get(context, id, **kwargs):
    return _security_service_get(context, id, **kwargs)


@require_context
def _security_service_get(context, id, session=None, **kwargs):
    result = _security_service_get_query(
        context,
        **kwargs,
    ).filter_by(id=id).first()
    if result is None:
        raise exception.SecurityServiceNotFound(security_service_id=id)
    return result


@require_context
@context_manager.reader
def security_service_get_all(context):
    return _security_service_get_query(context).all()


@require_context
@context_manager.reader
def security_service_get_all_by_project(context, project_id):
    return _security_service_get_query(context).filter_by(
        project_id=project_id,
    ).all()


@require_context
@context_manager.reader
def security_service_get_all_by_share_network(context, share_network_id):
    return model_query(
        context, models.SecurityService,
    ).join(
        models.ShareNetworkSecurityServiceAssociation,
        models.SecurityService.id ==
        models.ShareNetworkSecurityServiceAssociation.security_service_id,
    ).filter_by(
        share_network_id=share_network_id, deleted=0,
    ).all()


###################


def _share_network_get_query(context):
    return model_query(
        context, models.ShareNetwork, project_only=True,
    ).options(
        joinedload('share_instances'),
        joinedload('security_services'),
        subqueryload('share_network_subnets'),
    )


@require_context
@context_manager.writer
def share_network_create(context, values):
    values = ensure_model_dict_has_id(values)

    network_ref = models.ShareNetwork()
    network_ref.update(values)
    network_ref.save(session=context.session)
    return _share_network_get(context, values['id'])


@require_context
@context_manager.writer
def share_network_delete(context, id):
    network_ref = _share_network_get(context, id)
    network_ref.soft_delete(session=context.session)


@require_context
@context_manager.writer
def share_network_update(context, id, values):
    network_ref = _share_network_get(context, id)
    network_ref.update(values)
    network_ref.save(session=context.session)
    return network_ref


@require_context
@context_manager.reader
def share_network_get(context, id):
    return _share_network_get(context, id)


@require_context
def _share_network_get(context, id):
    result = _share_network_get_query(context).filter_by(id=id).first()
    if result is None:
        raise exception.ShareNetworkNotFound(share_network_id=id)
    return result


@require_context
@context_manager.reader
def share_network_get_all_by_filter(context, filters=None):
    query = _share_network_get_query(context)

    legal_filter_keys = ('project_id', 'created_since', 'created_before')

    if not filters:
        filters = {}

    query = exact_filter(
        query, models.ShareNetwork, filters, legal_filter_keys,
    )
    if 'security_service_id' in filters:
        security_service_id = filters.get('security_service_id')
        query = query.join(
            models.ShareNetworkSecurityServiceAssociation,
            models.ShareNetwork.id == models.ShareNetworkSecurityServiceAssociation.share_network_id,  # noqa: E501
        ).filter_by(
            security_service_id=security_service_id,
            deleted=0,
        )

    return query.all()


@require_context
@context_manager.reader
def share_network_get_all(context):
    return _share_network_get_query(context).all()


@require_context
@context_manager.reader
def share_network_get_all_by_project(context, project_id):
    return _share_network_get_query(
        context,
    ).filter_by(project_id=project_id).all()


@require_context
@context_manager.reader
def share_network_get_all_by_security_service(context, security_service_id):
    return model_query(
        context, models.ShareNetwork,
    ).join(
        models.ShareNetworkSecurityServiceAssociation,
        models.ShareNetwork.id ==
        models.ShareNetworkSecurityServiceAssociation.share_network_id,
    ).filter_by(security_service_id=security_service_id, deleted=0).all()


@require_context
@context_manager.writer
def share_network_add_security_service(context, id, security_service_id):
    assoc_ref = model_query(
        context,
        models.ShareNetworkSecurityServiceAssociation,
    ).filter_by(
        share_network_id=id,
    ).filter_by(security_service_id=security_service_id).first()

    if assoc_ref:
        msg = "Already associated"
        raise exception.ShareNetworkSecurityServiceAssociationError(
            share_network_id=id,
            security_service_id=security_service_id,
            reason=msg,
        )

    share_nw_ref = _share_network_get(context, id)
    security_service_ref = _security_service_get(context, security_service_id)
    share_nw_ref.security_services += [security_service_ref]
    share_nw_ref.save(session=context.session)

    return share_nw_ref


@require_context
@context_manager.reader
def share_network_security_service_association_get(
    context, share_network_id, security_service_id,
):
    association = model_query(
        context,
        models.ShareNetworkSecurityServiceAssociation,
    ).filter_by(
        share_network_id=share_network_id,
    ).filter_by(
        security_service_id=security_service_id,
    ).first()
    return association


@require_context
@context_manager.writer
def share_network_remove_security_service(context, id, security_service_id):
    share_nw_ref = _share_network_get(context, id)
    _security_service_get(context, security_service_id)

    assoc_ref = model_query(
        context,
        models.ShareNetworkSecurityServiceAssociation,
    ).filter_by(
        share_network_id=id,
    ).filter_by(security_service_id=security_service_id).first()

    if assoc_ref:
        assoc_ref.soft_delete(session=context.session)
    else:
        msg = "No association defined"
        raise exception.ShareNetworkSecurityServiceDissociationError(
            share_network_id=id,
            security_service_id=security_service_id,
            reason=msg,
        )

    return share_nw_ref


@require_context
@context_manager.writer
def share_network_update_security_service(
    context, id, current_security_service_id, new_security_service_id,
):
    share_nw_ref = _share_network_get(context, id)
    # Check if the old security service exists
    _security_service_get(context, current_security_service_id)
    new_security_service_ref = _security_service_get(
        context, new_security_service_id,
    )

    assoc_ref = model_query(
        context,
        models.ShareNetworkSecurityServiceAssociation,
    ).filter_by(
        share_network_id=id,
    ).filter_by(
        security_service_id=current_security_service_id,
    ).first()

    if assoc_ref:
        assoc_ref.soft_delete(session=context.session)
    else:
        msg = "No association defined"
        raise exception.ShareNetworkSecurityServiceDissociationError(
            share_network_id=id,
            security_service_id=current_security_service_id,
            reason=msg)

    # Add new association
    share_nw_ref.security_services += [new_security_service_ref]
    share_nw_ref.save(session=context.session)

    return share_nw_ref


@require_context
def _count_share_networks(
    context, project_id, user_id=None, share_type_id=None,
):
    query = model_query(
        context, models.ShareNetwork,
        func.count(models.ShareNetwork.id),
        read_deleted="no",
    ).filter_by(project_id=project_id)
    if share_type_id:
        query = query.join("share_instances").filter_by(
            share_type_id=share_type_id)
    elif user_id is not None:
        query = query.filter_by(user_id=user_id)
    return query.first()[0]


###################


@require_context
def _share_network_subnet_get_query(context):
    return model_query(
        context, models.ShareNetworkSubnet,
    ).options(
        joinedload('share_servers'),
        joinedload('share_network'),
        joinedload('share_network_subnet_metadata'),
    )


@require_context
@context_manager.writer
def share_network_subnet_create(context, values):
    values = ensure_model_dict_has_id(values)
    values['share_network_subnet_metadata'] = _metadata_refs(
        values.pop('metadata', {}), models.ShareNetworkSubnetMetadata)

    network_subnet_ref = models.ShareNetworkSubnet()
    network_subnet_ref.update(values)
    network_subnet_ref.save(session=context.session)
    return _share_network_subnet_get(
        context, network_subnet_ref['id'],
    )


@require_context
@context_manager.writer
def share_network_subnet_delete(context, network_subnet_id):
    network_subnet_ref = _share_network_subnet_get(context, network_subnet_id)
    context.session.query(models.ShareNetworkSubnetMetadata).filter_by(
        share_network_subnet_id=network_subnet_id,
    ).soft_delete()
    network_subnet_ref.soft_delete(session=context.session, update_status=True)


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
@context_manager.writer
def share_network_subnet_update(context, network_subnet_id, values):
    network_subnet_ref = _share_network_subnet_get(context, network_subnet_id)
    network_subnet_ref.update(values)
    network_subnet_ref.save(session=context.session)
    return network_subnet_ref


@require_context
@context_manager.reader
def share_network_subnet_get(context, network_subnet_id, parent_id=None):
    return _share_network_subnet_get(
        context, network_subnet_id, parent_id=parent_id,
    )


@require_context
def _share_network_subnet_get(context, network_subnet_id, parent_id=None):
    kwargs = {'id': network_subnet_id}
    if parent_id:
        kwargs['share_network_id'] = parent_id
    result = _share_network_subnet_get_query(
        context,
    ).filter_by(**kwargs).first()
    if result is None:
        raise exception.ShareNetworkSubnetNotFound(
            share_network_subnet_id=network_subnet_id,
        )
    return result


@require_context
@context_manager.reader
def share_network_subnet_get_all_with_same_az(context, network_subnet_id):
    subnet = _share_network_subnet_get_query(
        context,
    ).filter_by(id=network_subnet_id).subquery()
    result = _share_network_subnet_get_query(
        context,
    ).join(
        subnet,
        subnet.c.share_network_id ==
        models.ShareNetworkSubnet.share_network_id,
    ).filter(
        func.coalesce(subnet.c.availability_zone_id, '0') ==
        func.coalesce(models.ShareNetworkSubnet.availability_zone_id, '0')
    ).all()
    if not result:
        raise exception.ShareNetworkSubnetNotFound(
            share_network_subnet_id=network_subnet_id,
        )
    return result


@require_context
@context_manager.reader
def share_network_subnet_get_all(context):
    return _share_network_subnet_get_query(context).all()


@require_context
@context_manager.reader
def share_network_subnet_get_all_by_share_network(context, network_id):
    return _share_network_subnet_get_query(context).filter_by(
        share_network_id=network_id,
    ).all()


@require_context
@context_manager.reader
def share_network_subnets_get_all_by_availability_zone_id(
    context, share_network_id, availability_zone_id,
    fallback_to_default=True,
):
    """Get the share network subnets DB records in a given AZ.

    This method returns list of subnets DB record for a given share network id
    and an availability zone. If the 'availability_zone_id' is 'None', a
    record may be returned and it will represent the default share network
    subnets. If there is no subnet for a specific availability zone id and
    "fallback_to_default" is True, this method will return the default share
    network subnets, if it exists.

    :param context: operation context.
    :param share_network_id: the share network id to be the subnets.
    :param  availability_zone_id: the availability zone id to be the subnets.
    :param fallback_to_default: determines in case no subnets found in the
                                given AZ, it will return the "default" subnets.
    :return: the list of share network subnets in the AZ and share network.
    """
    return _share_network_subnets_get_all_by_availability_zone_id(
        context, share_network_id, availability_zone_id,
        fallback_to_default=fallback_to_default,
    )


@require_context
def _share_network_subnets_get_all_by_availability_zone_id(
    context, share_network_id, availability_zone_id,
    fallback_to_default=True,
):
    result = _share_network_subnet_get_query(context).filter_by(
        share_network_id=share_network_id,
        availability_zone_id=availability_zone_id,
    ).all()
    # If a specific subnet wasn't found, try get the default one
    if availability_zone_id and not result and fallback_to_default:
        return _share_network_subnet_get_query(context).filter_by(
            share_network_id=share_network_id,
            availability_zone_id=None,
        ).all()
    return result


@require_context
@context_manager.reader
def share_network_subnet_get_default_subnets(context, share_network_id):
    return _share_network_subnets_get_all_by_availability_zone_id(
        context, share_network_id, availability_zone_id=None,
    )


@require_context
@context_manager.reader
def share_network_subnet_get_all_by_share_server_id(context, share_server_id):
    result = _share_network_subnet_get_query(context).filter(
        models.ShareNetworkSubnet.share_servers.any(
            id=share_server_id,
        )
    ).all()
    if not result:
        raise exception.ShareNetworkSubnetNotFoundByShareServer(
            share_server_id=share_server_id,
        )

    return result

###################


def _share_network_subnet_metadata_get_query(context, share_network_subnet_id):
    return model_query(
        context, models.ShareNetworkSubnetMetadata,
        read_deleted="no",
    ).filter_by(
        share_network_subnet_id=share_network_subnet_id,
    ).options(joinedload('share_network_subnet'))


@require_context
@require_share_network_subnet_exists
@context_manager.reader
def share_network_subnet_metadata_get(context, share_network_subnet_id):
    return _share_network_subnet_metadata_get(context, share_network_subnet_id)


@require_context
def _share_network_subnet_metadata_get(context, share_network_subnet_id):
    rows = _share_network_subnet_metadata_get_query(
        context, share_network_subnet_id,
    ).all()

    result = {}
    for row in rows:
        result[row['key']] = row['value']
    return result


@require_context
@require_share_network_subnet_exists
@context_manager.writer
def share_network_subnet_metadata_delete(
    context, share_network_subnet_id, key,
):
    meta_ref = _share_network_subnet_metadata_get_item(
        context, share_network_subnet_id, key,
    )
    meta_ref.soft_delete(session=context.session)


@require_context
@require_share_network_subnet_exists
@context_manager.writer
def share_network_subnet_metadata_update(
    context, share_network_subnet_id, metadata, delete,
):
    return _share_network_subnet_metadata_update(
        context, share_network_subnet_id, metadata, delete,
    )


@require_context
@context_manager.writer
def share_network_subnet_metadata_update_item(
    context, share_network_subnet_id, item,
):
    return _share_network_subnet_metadata_update(
        context, share_network_subnet_id, item, delete=False,
    )


@require_context
@context_manager.reader
def share_network_subnet_metadata_get_item(
    context, share_network_subnet_id, key,
):
    row = _share_network_subnet_metadata_get_item(
        context, share_network_subnet_id, key,
    )
    result = {row['key']: row['value']}
    return result


def _share_network_subnet_metadata_get_item(
    context, share_network_subnet_id, key,
):
    result = _share_network_subnet_metadata_get_query(
        context, share_network_subnet_id,
    ).filter_by(key=key).first()
    if not result:
        raise exception.MetadataItemNotFound
    return result


@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def _share_network_subnet_metadata_update(
    context, share_network_subnet_id, metadata, delete,
):
    delete = strutils.bool_from_string(delete)
    if delete:
        original_metadata = _share_network_subnet_metadata_get(
            context, share_network_subnet_id,
        )
        for meta_key, meta_value in original_metadata.items():
            if meta_key not in metadata:
                meta_ref = _share_network_subnet_metadata_get_item(
                    context, share_network_subnet_id, meta_key,
                )
                meta_ref.soft_delete(session=context.session)
    meta_ref = None
    # Now update all existing items with new values, or create new meta
    # objects.
    for meta_key, meta_value in metadata.items():

        # update the value whether it exists or not.
        item = {"value": meta_value}
        meta_ref = _share_network_subnet_metadata_get_query(
            context, share_network_subnet_id,
        ).filter_by(key=meta_key).first()
        if not meta_ref:
            meta_ref = models.ShareNetworkSubnetMetadata()
            item.update(
                {
                    "key": meta_key,
                    "share_network_subnet_id": share_network_subnet_id,
                }
            )
        meta_ref.update(item)
        meta_ref.save(session=context.session)

    return metadata

#################################


def _share_server_get_query(context):
    return model_query(
        context, models.ShareServer,
    ).options(
        joinedload('share_instances'),
        joinedload('network_allocations'),
        joinedload('share_network_subnets'),
    )


@require_context
@context_manager.writer
def share_server_create(context, values):
    values = ensure_model_dict_has_id(values)

    server_ref = models.ShareServer()
    # updated_at is needed for judgement of automatic cleanup
    server_ref.updated_at = timeutils.utcnow()
    server_ref.update(values)
    server_ref.save(session=context.session)
    # NOTE(u_glide): Do so to prevent errors with relationships
    return _share_server_get(context, server_ref['id'])


@require_context
@context_manager.writer
def share_server_delete(context, id):
    server_ref = _share_server_get(context, id)
    model_query(
        context, models.ShareServerShareNetworkSubnetMapping,
    ).filter_by(
        share_server_id=id,
    ).soft_delete()
    _share_server_backend_details_delete(context, id)
    server_ref.soft_delete(session=context.session, update_status=True)


@require_context
@context_manager.writer
def share_server_update(context, id, values):
    server_ref = _share_server_get(context, id)
    server_ref.update(values)
    server_ref.save(session=context.session)
    return server_ref


@require_context
@context_manager.reader
def share_server_get(context, server_id):
    return _share_server_get(context, server_id)


@require_context
def _share_server_get(context, server_id):
    result = _share_server_get_query(context).filter_by(id=server_id).first()
    if result is None:
        raise exception.ShareServerNotFound(share_server_id=server_id)
    return result


@require_context
@context_manager.reader
def share_server_search_by_identifier(context, identifier):

    identifier_field = models.ShareServer.identifier

    # try if given identifier is a substring of existing entry's identifier
    result = (_share_server_get_query(context).filter(
        identifier_field.like('%{}%'.format(identifier))).all())

    if not result:
        # repeat it with underscores instead of hyphens
        result = (_share_server_get_query(context).filter(
            identifier_field.like('%{}%'.format(
                identifier.replace("-", "_")))).all())

    if not result:
        # repeat it with hypens instead of underscores
        result = (_share_server_get_query(context).filter(
            identifier_field.like('%{}%'.format(
                identifier.replace("_", "-")))).all())

    if not result:
        # try if an existing identifier is a substring of given identifier
        result = (_share_server_get_query(context).filter(
            literal(identifier).contains(identifier_field)).all())

    if not result:
        # repeat it with underscores instead of hyphens
        result = (_share_server_get_query(context).filter(
            literal(identifier.replace("-", "_")).contains(
                identifier_field)).all())

    if not result:
        # repeat it with hypens instead of underscores
        result = (_share_server_get_query(context).filter(
            literal(identifier.replace("_", "-")).contains(
                identifier_field)).all())

    if not result:
        raise exception.ShareServerNotFound(share_server_id=identifier)

    return result


@require_context
@context_manager.reader
def share_server_get_all_by_host_and_share_subnet_valid(
    context, host, share_subnet_id,
):
    result = _share_server_get_query(
        context,
    ).filter_by(
        host=host,
    ).filter(
        models.ShareServer.share_network_subnets.any(id=share_subnet_id)
    ).filter(
        models.ShareServer.status.in_(
            (constants.STATUS_CREATING, constants.STATUS_ACTIVE),
        )
    ).all()

    if not result:
        filters_description = ('share_network_subnet_id is '
                               '"%(share_subnet_id)s", host is "%(host)s" and '
                               'status in "%(status_cr)s" or '
                               '"%(status_act)s"') % {
            'share_subnet_id': share_subnet_id,
            'host': host,
            'status_cr': constants.STATUS_CREATING,
            'status_act': constants.STATUS_ACTIVE,
        }
        raise exception.ShareServerNotFoundByFilters(
            filters_description=filters_description,
        )
    return result


@require_context
@context_manager.reader
def share_server_get_all_by_host_and_share_subnet(
    context, host, share_subnet_id,
):
    result = _share_server_get_query(
        context,
    ).filter_by(
        host=host,
    ).filter(
        models.ShareServer.share_network_subnets.any(id=share_subnet_id)
    ).all()

    if not result:
        filters_description = (
            'share_network_subnet_id is "%(share_subnet_id)s" and host is '
            '"%(host)s".'
        ) % {
            'share_subnet_id': share_subnet_id,
            'host': host,
        }
        raise exception.ShareServerNotFoundByFilters(
            filters_description=filters_description,
        )
    return result


@require_context
@context_manager.reader
def share_server_get_all(context):
    return _share_server_get_query(context).all()


@require_context
@context_manager.reader
def share_server_get_all_with_filters(context, filters):
    return _share_server_get_all_with_filters(context, filters)


@require_context
def _share_server_get_all_with_filters(context, filters):
    query = _share_server_get_query(context)

    if filters.get('host'):
        query = query.filter_by(host=filters.get('host'))
    if filters.get('status'):
        query = query.filter_by(status=filters.get('status'))
    if filters.get('source_share_server_id'):
        query = query.filter_by(
            source_share_server_id=filters.get('source_share_server_id'))
    if filters.get('share_network_id'):
        query = query.join(
            models.ShareServerShareNetworkSubnetMapping,
            models.ShareServerShareNetworkSubnetMapping.share_server_id ==
            models.ShareServer.id
        ).join(
            models.ShareNetworkSubnet,
            models.ShareNetworkSubnet.id ==
            models.ShareServerShareNetworkSubnetMapping.share_network_subnet_id
        ).filter(
            models.ShareNetworkSubnet.share_network_id ==
            filters.get('share_network_id'))
    return query.all()


@require_context
@context_manager.reader
def share_server_get_all_by_host(context, host, filters=None):
    if filters:
        filters.update({'host': host})
    else:
        filters = {'host': host}
    return _share_server_get_all_with_filters(context, filters=filters)


@require_context
@context_manager.reader
def share_server_get_all_unused_deletable(context, host, updated_before):
    valid_server_status = (
        constants.STATUS_INACTIVE,
        constants.STATUS_ACTIVE,
        constants.STATUS_ERROR,
    )
    result = (_share_server_get_query(context)
              .filter_by(is_auto_deletable=True)
              .filter_by(host=host)
              .filter(~models.ShareServer.share_groups.any())
              .filter(~models.ShareServer.share_instances.any())
              .filter(models.ShareServer.status.in_(valid_server_status))
              .filter(models.ShareServer.updated_at < updated_before).all())
    return result


def _share_server_backend_details_get_item(context,
                                           share_server_id,
                                           key, session=None):
    result = (_share_server_backend_details_get_query(
        context, share_server_id, session=session).filter_by(key=key).first())
    if not result:
        raise exception.ShareServerBackendDetailsNotFound()
    return result


def _share_server_backend_details_get_query(context,
                                            share_server_id,
                                            session=None):
    return (model_query(
        context, models.ShareServerBackendDetails, session=session,
        read_deleted="no").
        filter_by(share_server_id=share_server_id))


@require_context
@context_manager.writer
def share_server_backend_details_set(context, share_server_id, server_details):
    _share_server_get(context, share_server_id)

    for meta_key, meta_value in server_details.items():

        # update the value whether it exists or not
        item = {"value": meta_value}
        try:
            meta_ref = _share_server_backend_details_get_item(
                context, share_server_id, meta_key, session=context.session)
        except exception.ShareServerBackendDetailsNotFound:
            meta_ref = models.ShareServerBackendDetails()
            item.update({"key": meta_key, "share_server_id": share_server_id})

        meta_ref.update(item)
        meta_ref.save(session=context.session)
    return server_details


@require_context
@context_manager.writer
def share_server_backend_details_delete(context, share_server_id):
    return _share_server_backend_details_delete(context, share_server_id)


@require_context
def _share_server_backend_details_delete(context, share_server_id):
    share_server_details = model_query(
        context,
        models.ShareServerBackendDetails,
    ).filter_by(share_server_id=share_server_id).all()
    for item in share_server_details:
        item.soft_delete(session=context.session)


@require_context
@context_manager.writer
def share_servers_update(context, share_server_ids, values):
    result = model_query(
        context, models.ShareServer, read_deleted="no",
    ).filter(
        models.ShareServer.id.in_(share_server_ids),
    ).update(values, synchronize_session=False)
    return result


###################

def _driver_private_data_query(
    context, entity_id, key=None, read_deleted=False,
):
    query = model_query(
        context, models.DriverPrivateData,
        read_deleted=read_deleted,
    ).filter_by(
        entity_uuid=entity_id,
    )

    if isinstance(key, list):
        return query.filter(models.DriverPrivateData.key.in_(key))
    elif key is not None:
        return query.filter_by(key=key)

    return query


@require_context
@context_manager.reader
def driver_private_data_get(context, entity_id, key=None, default=None):
    query = _driver_private_data_query(context, entity_id, key)

    if key is None or isinstance(key, list):
        return {item.key: item.value for item in query.all()}
    else:
        result = query.first()
        return result["value"] if result is not None else default


@require_context
@context_manager.writer
def driver_private_data_update(
    context, entity_id, details, delete_existing=False,
):
    # NOTE(u_glide): following code modifies details dict, that's why we should
    # copy it
    new_details = copy.deepcopy(details)

    # Process existing data
    original_data = context.session.query(models.DriverPrivateData).filter_by(
        entity_uuid=entity_id,
    ).all()

    for data_ref in original_data:
        in_new_details = data_ref['key'] in new_details

        if in_new_details:
            new_value = str(new_details.pop(data_ref['key']))
            data_ref.update({
                "value": new_value,
                "deleted": 0,
                "deleted_at": None
            })
            data_ref.save(session=context.session)
        elif delete_existing and data_ref['deleted'] != 1:
            data_ref.update({
                "deleted": 1, "deleted_at": timeutils.utcnow()
            })
            data_ref.save(session=context.session)

    # Add new data
    for key, value in new_details.items():
        data_ref = models.DriverPrivateData()
        data_ref.update({
            "entity_uuid": entity_id,
            "key": key,
            "value": str(value)
        })
        data_ref.save(session=context.session)

    return details


@require_context
@context_manager.writer
def driver_private_data_delete(context, entity_id, key=None):
    query = _driver_private_data_query(context, entity_id, key)
    query.update({"deleted": 1, "deleted_at": timeutils.utcnow()})


###################


@require_context
@context_manager.writer
def network_allocation_create(context, values):
    values = ensure_model_dict_has_id(values)
    alloc_ref = models.NetworkAllocation()
    alloc_ref.update(values)
    alloc_ref.save(session=context.session)
    return alloc_ref


@require_context
@context_manager.writer
def network_allocation_delete(context, id):
    alloc_ref = _network_allocation_get(context, id)
    alloc_ref.soft_delete(session=context.session)


@require_context
@context_manager.reader
def network_allocation_get(context, id, read_deleted="no"):
    return _network_allocation_get(context, id, read_deleted=read_deleted)


@require_context
def _network_allocation_get(context, id, read_deleted="no"):
    result = model_query(
        context, models.NetworkAllocation,
        read_deleted=read_deleted,
    ).filter_by(id=id).first()
    if result is None:
        raise exception.NotFound()
    return result


@require_context
@context_manager.reader
def network_allocations_get_by_ip_address(context, ip_address):
    result = model_query(
        context, models.NetworkAllocation,
    ).filter_by(ip_address=ip_address).all()
    return result or []


@require_context
@context_manager.reader
def network_allocations_get_for_share_server(
    context, share_server_id, label=None, subnet_id=None,
):
    query = model_query(
        context, models.NetworkAllocation,
    ).filter_by(
        share_server_id=share_server_id,
    )
    if label:
        if label != 'admin':
            query = query.filter(or_(
                # NOTE(vponomaryov): we treat None as alias for 'user'.
                models.NetworkAllocation.label == None,  # noqa
                models.NetworkAllocation.label == label,
            ))
        else:
            query = query.filter(models.NetworkAllocation.label == label)
    if subnet_id:
        query = query.filter(
            models.NetworkAllocation.share_network_subnet_id == subnet_id)

    result = query.all()
    return result


@require_context
@context_manager.writer
def network_allocation_update(context, id, values, read_deleted=None):
    alloc_ref = _network_allocation_get(context, id, read_deleted=read_deleted)
    alloc_ref.update(values)
    alloc_ref.save(session=context.session)
    return alloc_ref


###################


def _dict_with_specs(inst_type_query, specs_key='extra_specs'):
    """Convert type query result to dict with extra_spec and rate_limit.

    Takes a share [group] type query returned by sqlalchemy and returns it
    as a dictionary, converting the extra/group specs entry from a list
    of dicts:

    'extra_specs' : [{'key': 'k1', 'value': 'v1', ...}, ...]
    'group_specs' : [{'key': 'k1', 'value': 'v1', ...}, ...]
    to a single dict:
    'extra_specs' : {'k1': 'v1'}
    'group_specs' : {'k1': 'v1'}
    """
    inst_type_dict = dict(inst_type_query)
    specs = {x['key']: x['value'] for x in inst_type_query[specs_key]}
    inst_type_dict[specs_key] = specs
    return inst_type_dict


@require_admin_context
@context_manager.writer
def share_type_create(context, values, projects=None):
    """Create a new share type.

    In order to pass in extra specs, the values dict should contain a
    'extra_specs' key/value pair:
    {'extra_specs' : {'k1': 'v1', 'k2': 'v2', ...}}
    """
    values = ensure_model_dict_has_id(values)

    projects = projects or []

    try:
        values['extra_specs'] = _metadata_refs(
            values.get('extra_specs'),
            models.ShareTypeExtraSpecs,
        )
        share_type_ref = models.ShareTypes()
        share_type_ref.update(values)
        share_type_ref.save(session=context.session)
    except db_exception.DBDuplicateEntry:
        raise exception.ShareTypeExists(id=values['name'])
    except Exception as e:
        raise db_exception.DBError(e)

    for project in set(projects):
        access_ref = models.ShareTypeProjects()
        access_ref.update(
            {"share_type_id": share_type_ref.id, "project_id": project},
        )
        access_ref.save(session=context.session)

    return share_type_ref


def _share_type_get_query(context, read_deleted=None, expected_fields=None):
    expected_fields = expected_fields or []
    query = model_query(
        context,
        models.ShareTypes,
        read_deleted=read_deleted,
    ).options(joinedload('extra_specs'))

    if 'projects' in expected_fields:
        query = query.options(joinedload('projects'))

    if not context.is_admin:
        the_filter = [models.ShareTypes.is_public == true()]
        projects_attr = getattr(models.ShareTypes, 'projects')
        the_filter.extend([
            projects_attr.any(project_id=context.project_id)
        ])
        query = query.filter(or_(*the_filter))

    return query


@handle_db_data_error
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def _share_type_update(context, type_id, values, is_group):

    if values.get('name') is None:
        values.pop('name', None)

    if is_group:
        model = models.ShareGroupTypes
        exists_exc = exception.ShareGroupTypeExists
        exists_args = {'type_id': values.get('name')}
    else:
        model = models.ShareTypes
        exists_exc = exception.ShareTypeExists
        exists_args = {'id': values.get('name')}

    query = model_query(context, model)

    try:
        result = query.filter_by(id=type_id).update(values)
    except db_exception.DBDuplicateEntry:
        # This exception only occurs if there's a non-deleted
        # share/group type which has the same name as the name being
        # updated.
        raise exists_exc(**exists_args)

    if not result:
        if is_group:
            raise exception.ShareGroupTypeNotFound(type_id=type_id)
        else:
            raise exception.ShareTypeNotFound(share_type_id=type_id)


@context_manager.writer
def share_type_update(context, share_type_id, values):
    _share_type_update(context, share_type_id, values, is_group=False)


@require_context
@context_manager.reader
def share_type_get_all(context, inactive=False, filters=None):
    """Returns a dict describing all share_types with name as key."""
    filters = filters or {}

    read_deleted = "yes" if inactive else "no"

    query = _share_type_get_query(context, read_deleted=read_deleted)

    if 'is_public' in filters and filters['is_public'] is not None:
        the_filter = [models. ShareTypes.is_public == filters['is_public']]
        if filters['is_public'] and context.project_id is not None:
            projects_attr = getattr(models. ShareTypes, 'projects')
            the_filter.extend([
                projects_attr.any(
                    project_id=context.project_id, deleted=0)
            ])
        if len(the_filter) > 1:
            query = query.filter(or_(*the_filter))
        else:
            query = query.filter(the_filter[0])

    rows = query.order_by("name").all()

    result = {}
    for row in rows:
        result[row['name']] = _dict_with_specs(row)

    return result


def _share_type_get_id_from_share_type(context, id):
    result = model_query(
        context, models.ShareTypes, read_deleted="no",
    ).filter_by(id=id).first()
    if not result:
        raise exception.ShareTypeNotFound(share_type_id=id)
    return result['id']


def _share_type_get(context, id, inactive=False, expected_fields=None):
    expected_fields = expected_fields or []
    read_deleted = "yes" if inactive else "no"
    result = _share_type_get_query(
        context, read_deleted, expected_fields,
    ).filter_by(id=id).first()

    if not result:
        # The only way that id could be None is if the default share type is
        # not configured and no other share type was specified.
        if id is None:
            raise exception.DefaultShareTypeNotConfigured()
        raise exception.ShareTypeNotFound(share_type_id=id)

    share_type = _dict_with_specs(result)

    if 'projects' in expected_fields:
        share_type['projects'] = [p['project_id'] for p in result['projects']]

    return share_type


@require_context
@context_manager.reader
def share_type_get(context, id, inactive=False, expected_fields=None):
    """Return a dict describing specific share_type."""
    return _share_type_get(context, id,
                           inactive=inactive,
                           expected_fields=expected_fields)


def _share_type_get_by_name(context, name):
    result = _share_type_get_query(context).filter_by(name=name).first()

    if not result:
        raise exception.ShareTypeNotFoundByName(share_type_name=name)

    return _dict_with_specs(result)


@require_context
@context_manager.reader
def share_type_get_by_name(context, name):
    """Return a dict describing specific share_type."""
    return _share_type_get_by_name(context, name)


@require_context
@context_manager.reader
def share_type_get_by_name_or_id(context, name_or_id):
    """Return a dict describing specific share_type using its name or ID.

    :returns: ShareType object or None if not found
    """
    try:
        return _share_type_get(context, name_or_id)
    except exception.ShareTypeNotFound:
        try:
            return _share_type_get_by_name(context, name_or_id)
        except exception.ShareTypeNotFoundByName:
            return None


@require_admin_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
@context_manager.writer
def share_type_destroy(context, id):
    _share_type_get(context, id)
    shares_count = model_query(
        context,
        models.ShareInstance,
        read_deleted="no",
    ).filter_by(share_type_id=id).count()
    share_group_types_count = model_query(
        context,
        models.ShareGroupTypeShareTypeMapping,
        read_deleted="no",
    ).filter_by(share_type_id=id).count()
    if shares_count or share_group_types_count:
        msg = ("Deletion of share type %(stype)s failed; it in use by "
               "%(shares)d shares and %(gtypes)d share group types")
        msg_args = {'stype': id,
                    'shares': shares_count,
                    'gtypes': share_group_types_count}
        LOG.error(msg, msg_args)
        raise exception.ShareTypeInUse(share_type_id=id)

    model_query(
        context, models.ShareTypeExtraSpecs,
    ).filter_by(
        share_type_id=id
    ).soft_delete()
    model_query(
        context, models.ShareTypeProjects,
    ).filter_by(
        share_type_id=id,
    ).soft_delete()
    model_query(
        context, models.ShareTypes,
    ).filter_by(
        id=id
    ).soft_delete()

    # NOTE(stephenfin): commit changes before we do anything with quotas

    context.session.commit()
    context.session.begin()

    # Destroy any quotas, usages and reservations for the share type:
    _quota_destroy_all_by_share_type(context, id)


def _share_type_access_query(context):
    return model_query(context, models.ShareTypeProjects, read_deleted="no")


@require_admin_context
@context_manager.reader
def share_type_access_get_all(context, type_id):
    share_type_id = _share_type_get_id_from_share_type(context, type_id)
    return _share_type_access_query(
        context,
    ).filter_by(share_type_id=share_type_id).all()


@require_admin_context
@context_manager.writer
def share_type_access_add(context, type_id, project_id):
    """Add given tenant to the share type access list."""
    share_type_id = _share_type_get_id_from_share_type(context, type_id)

    access_ref = models.ShareTypeProjects()
    access_ref.update(
        {"share_type_id": share_type_id, "project_id": project_id},
    )

    try:
        access_ref.save(session=context.session)
    except db_exception.DBDuplicateEntry:
        raise exception.ShareTypeAccessExists(
            share_type_id=type_id, project_id=project_id,
        )
    return access_ref


@require_admin_context
@context_manager.writer
def share_type_access_remove(context, type_id, project_id):
    """Remove given tenant from the share type access list."""
    share_type_id = _share_type_get_id_from_share_type(context, type_id)

    count = _share_type_access_query(
        context,
    ).filter_by(
        share_type_id=share_type_id,
    ).filter_by(
        project_id=project_id,
    ).soft_delete(synchronize_session=False)

    if count == 0:
        raise exception.ShareTypeAccessNotFound(
            share_type_id=type_id, project_id=project_id,
        )

####################


def _share_type_extra_specs_query(context, share_type_id):
    return model_query(
        context, models.ShareTypeExtraSpecs, read_deleted="no",
    ).filter_by(
        share_type_id=share_type_id,
    ).options(joinedload('share_type'))


@require_context
@context_manager.reader
def share_type_extra_specs_get(context, share_type_id):
    rows = _share_type_extra_specs_query(context, share_type_id).all()
    result = {}
    for row in rows:
        result[row['key']] = row['value']

    return result


@require_context
@context_manager.writer
def share_type_extra_specs_delete(context, share_type_id, key):
    _share_type_extra_specs_get_item(context, share_type_id, key)
    _share_type_extra_specs_query(
        context, share_type_id,
    ).filter_by(key=key).soft_delete()


def _share_type_extra_specs_get_item(context, share_type_id, key):
    result = _share_type_extra_specs_query(
        context, share_type_id,
    ).filter_by(key=key).options(joinedload('share_type')).first()

    if not result:
        raise exception.ShareTypeExtraSpecsNotFound(
            extra_specs_key=key,
            share_type_id=share_type_id,
        )

    return result


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
@context_manager.writer
def share_type_extra_specs_update_or_create(context, share_type_id, specs):
    spec_ref = None
    for key, value in specs.items():
        try:
            spec_ref = _share_type_extra_specs_get_item(
                context, share_type_id, key,
            )
        except exception.ShareTypeExtraSpecsNotFound:
            spec_ref = models.ShareTypeExtraSpecs()
        spec_ref.update(
            {
                "key": key,
                "value": value,
                "share_type_id": share_type_id,
                "deleted": 0,
            }
        )
        spec_ref.save(session=context.session)

    return specs

####################


def _ensure_availability_zone_exists(
    context, values, session=None, *, strict=True,
):
    az_name = values.pop('availability_zone', None)

    if strict and not az_name:
        msg = _("Values dict should have 'availability_zone' field.")
        raise ValueError(msg)
    elif not az_name:
        return

    if uuidutils.is_uuid_like(az_name):
        az_ref = _availability_zone_get(context, az_name, session=session)
    else:
        az_ref = _availability_zone_create_if_not_exist(
            context, az_name, session=session)

    values.update({'availability_zone_id': az_ref['id']})


@require_context
@context_manager.reader
def availability_zone_get(context, id_or_name):
    return _availability_zone_get(context, id_or_name)


# TODO(stephenfin): Remove the 'session' argument once all callers have been
# converted
@require_context
def _availability_zone_get(context, id_or_name, session=None):
    query = model_query(context, models.AvailabilityZone, session=session)

    if uuidutils.is_uuid_like(id_or_name):
        query = query.filter_by(id=id_or_name)
    else:
        query = query.filter_by(name=id_or_name)

    result = query.first()

    if not result:
        raise exception.AvailabilityZoneNotFound(id=id_or_name)

    return result


# TODO(stephenfin): Remove the 'session' argument once all callers have been
# converted
@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def _availability_zone_create_if_not_exist(context, name, session=None):
    try:
        return _availability_zone_get(context, name, session=session)
    except exception.AvailabilityZoneNotFound:
        az = models.AvailabilityZone()
        az.update({'id': uuidutils.generate_uuid(), 'name': name})
        # TODO(stephenfin): Remove this branch once all callers have been
        # updated not to pass 'session'
        if session is not None:
            with session.begin():
                az.save(session)
        else:
            az.save(context.session)
    return az


@require_context
@context_manager.reader
def availability_zone_get_all(context):
    enabled_services = model_query(
        context, models.Service,
        models.Service.availability_zone_id,
        read_deleted="no"
    ).filter_by(disabled=False).distinct()

    return model_query(
        context, models.AvailabilityZone, read_deleted="no",
    ).filter(
        models.AvailabilityZone.id.in_(enabled_services)
    ).all()

####################


@require_admin_context
@context_manager.writer
def purge_deleted_records(context, age_in_days):
    """Purge soft-deleted records older than(and equal) age from tables."""

    if age_in_days < 0:
        msg = _('Must supply a non-negative value for "age_in_days".')
        LOG.error(msg)
        raise exception.InvalidParameterValue(msg)

    metadata = MetaData()
    metadata.reflect(get_engine())
    deleted_age = timeutils.utcnow() - datetime.timedelta(days=age_in_days)

    for table in reversed(metadata.sorted_tables):
        if 'deleted' not in table.columns.keys():
            continue

        try:
            mds = [m for m in models.__dict__.values() if
                   (hasattr(m, '__tablename__') and
                    m.__tablename__ == str(table))]
            if len(mds) > 0:
                # collect all soft-deleted records
                with context.session.begin_nested():
                    model = mds[0]
                    s_deleted_records = context.session.query(
                        model,
                    ).filter(model.deleted_at <= deleted_age)
                deleted_count = 0
                # delete records one by one,
                # skip the records which has FK constraints
                for record in s_deleted_records:
                    try:
                        with context.session.begin_nested():
                            context.session.delete(record)
                            deleted_count += 1
                    except db_exc.DBError:
                        LOG.warning(
                            ("Deleting soft-deleted resource %s "
                             "failed, skipping."), record)
                if deleted_count != 0:
                    LOG.info("Deleted %(count)s records in "
                             "table %(table)s.",
                             {'count': deleted_count, 'table': table})
        except db_exc.DBError:
            LOG.warning("Querying table %s's soft-deleted records "
                        "failed, skipping.", table)


####################


def _share_group_get(context, share_group_id):
    result = (model_query(context, models.ShareGroup,
                          project_only=True,
                          read_deleted='no').
              filter_by(id=share_group_id).
              options(joinedload('share_types')).
              first())

    if not result:
        raise exception.ShareGroupNotFound(share_group_id=share_group_id)

    return result


@require_context
@context_manager.reader
def share_group_get(context, share_group_id):
    return _share_group_get(context, share_group_id)


def _share_group_get_all(context, project_id=None, share_server_id=None,
                         host=None, detailed=True, filters=None,
                         sort_key=None, sort_dir=None):
    sort_key = sort_key or 'created_at'
    sort_dir = sort_dir or 'desc'

    query = model_query(
        context, models.ShareGroup, read_deleted='no')

    # Apply filters
    if not filters:
        filters = {}
    no_key = 'key_is_absent'
    for k, v in filters.items():
        temp_k = k.rstrip('~') if k in constants.LIKE_FILTER else k
        filter_attr = getattr(models.ShareGroup, temp_k, no_key)

        if filter_attr == no_key:
            msg = _("Share groups cannot be filtered using '%s' key.")
            raise exception.InvalidInput(reason=msg % k)

        if k in constants.LIKE_FILTER:
            query = query.filter(filter_attr.op('LIKE')(u'%' + v + u'%'))
        else:
            query = query.filter(filter_attr == v)

    if project_id:
        query = query.filter(
            models.ShareGroup.project_id == project_id)
    if host:
        query = query.filter(
            models.ShareGroup.host == host)
    if share_server_id:
        query = query.filter(
            models.ShareGroup.share_server_id == share_server_id)

    try:
        query = apply_sorting(models.ShareGroup, query, sort_key, sort_dir)
    except AttributeError:
        msg = _("Wrong sorting key provided - '%s'.") % sort_key
        raise exception.InvalidInput(reason=msg)

    if detailed:
        return query.options(joinedload('share_types')).all()
    else:
        query = query.with_entities(
            models.ShareGroup.id, models.ShareGroup.name)
        values = []
        for sg_id, sg_name in query.all():
            values.append({"id": sg_id, "name": sg_name})
        return values


@require_admin_context
@context_manager.reader
def share_group_get_all(context, detailed=True, filters=None, sort_key=None,
                        sort_dir=None):
    return _share_group_get_all(
        context, detailed=detailed, filters=filters,
        sort_key=sort_key, sort_dir=sort_dir)


@require_admin_context
@context_manager.reader
def share_group_get_all_by_host(context, host, detailed=True):
    return _share_group_get_all(context, host=host, detailed=detailed)


@require_context
@context_manager.reader
def share_group_get_all_by_project(context, project_id, detailed=True,
                                   filters=None, sort_key=None, sort_dir=None):
    authorize_project_context(context, project_id)
    return _share_group_get_all(
        context, project_id=project_id, detailed=detailed, filters=filters,
        sort_key=sort_key, sort_dir=sort_dir)


@require_context
@context_manager.reader
def share_group_get_all_by_share_server(context, share_server_id, filters=None,
                                        sort_key=None, sort_dir=None):
    return _share_group_get_all(
        context, share_server_id=share_server_id, filters=filters,
        sort_key=sort_key, sort_dir=sort_dir)


@require_context
@context_manager.writer
def share_group_create(context, values):
    share_group = models.ShareGroup()
    if not values.get('id'):
        values['id'] = uuidutils.generate_uuid()

    mappings = []
    for item in values.get('share_types') or []:
        mapping = models.ShareGroupShareTypeMapping()
        mapping['id'] = uuidutils.generate_uuid()
        mapping['share_type_id'] = item
        mapping['share_group_id'] = values['id']
        mappings.append(mapping)

    values['share_types'] = mappings

    share_group.update(values)
    context.session.add(share_group)

    return _share_group_get(context, values['id'])


@require_context
@context_manager.writer
def share_group_update(context, share_group_id, values):
    share_group_ref = _share_group_get(
        context, share_group_id)
    share_group_ref.update(values)
    share_group_ref.save(session=context.session)
    return share_group_ref


@require_admin_context
@context_manager.writer
def share_group_destroy(context, share_group_id):
    share_group_ref = _share_group_get(context, share_group_id)
    share_group_ref.soft_delete(context.session)
    context.session.query(models.ShareGroupShareTypeMapping).filter_by(
        share_group_id=share_group_ref['id']).soft_delete()


@require_context
@context_manager.reader
def count_shares_in_share_group(context, share_group_id):
    return (model_query(context, models.Share,
                        project_only=True, read_deleted="no").
            filter_by(share_group_id=share_group_id).
            count())


@require_context
@context_manager.reader
def get_all_shares_by_share_group(context, share_group_id):
    return (model_query(
            context, models.Share,
            project_only=True, read_deleted="no").
            filter_by(share_group_id=share_group_id).
            all())


@require_context
def _count_share_groups(context, project_id, user_id=None, share_type_id=None):
    query = model_query(
        context, models.ShareGroup,
        func.count(models.ShareGroup.id),
        read_deleted="no",
    ).filter_by(project_id=project_id)
    if share_type_id:
        query = query.join("share_group_share_type_mappings").filter_by(
            share_type_id=share_type_id)
    elif user_id is not None:
        query = query.filter_by(user_id=user_id)
    return query.first()[0]


@require_context
def _count_share_group_snapshots(
    context, project_id, user_id=None, share_type_id=None,
):
    query = model_query(
        context, models.ShareGroupSnapshot,
        func.count(models.ShareGroupSnapshot.id),
        read_deleted="no",
    ).filter_by(project_id=project_id)
    if share_type_id:
        query = query.join(
            "share_group"
        ).join(
            "share_group_share_type_mappings"
        ).filter_by(share_type_id=share_type_id)
    elif user_id is not None:
        query = query.filter_by(user_id=user_id)
    return query.first()[0]


@require_context
def _share_replica_data_get_for_project(
    context, project_id, user_id=None, share_type_id=None,
):
    query = model_query(
        context, models.ShareInstance,
        func.count(models.ShareInstance.id),
        func.sum(models.Share.size),
        read_deleted="no",
    ).join(
        models.Share,
        models.ShareInstance.share_id == models.Share.id
    ).filter(
        models.Share.project_id == project_id
    ).filter(
        models.ShareInstance.replica_state.isnot(None)
    )

    if share_type_id:
        query = query.filter(
            models.ShareInstance.share_type_id == share_type_id)
    elif user_id:
        query = query.filter(models.Share.user_id == user_id)

    result = query.first()
    return result[0] or 0, result[1] or 0


@require_context
@context_manager.reader
def count_share_group_snapshots_in_share_group(context, share_group_id):
    return model_query(
        context, models.ShareGroupSnapshot,
        project_only=True, read_deleted="no",
    ).filter_by(
        share_group_id=share_group_id,
    ).count()


@require_context
@context_manager.reader
def count_share_groups_in_share_network(context, share_network_id):
    return (model_query(
            context, models.ShareGroup,
            project_only=True, read_deleted="no").
            filter_by(share_network_id=share_network_id).
            count())


@require_context
@context_manager.reader
def count_share_group_snapshot_members_in_share(context, share_id):
    return model_query(
        context, models.ShareSnapshotInstance,
        project_only=True, read_deleted="no",
    ).join(
        models.ShareInstance,
        models.ShareInstance.id == (
            models.ShareSnapshotInstance.share_instance_id),
    ).filter(
        models.ShareInstance.share_id == share_id,
    ).count()


####################


@require_context
def _share_group_snapshot_get(context, share_group_snapshot_id):
    result = model_query(
        context,
        models.ShareGroupSnapshot,
        project_only=True,
        read_deleted='no',
    ).options(
        joinedload('share_group'),
        joinedload('share_group_snapshot_members'),
    ).filter_by(
        id=share_group_snapshot_id,
    ).first()

    if not result:
        raise exception.ShareGroupSnapshotNotFound(
            share_group_snapshot_id=share_group_snapshot_id)

    return result


def _share_group_snapshot_get_all(
    context,
    project_id=None,
    detailed=True,
    filters=None,
    sort_key=None,
    sort_dir=None,
):
    if not sort_key:
        sort_key = 'created_at'
    if not sort_dir:
        sort_dir = 'desc'

    query = model_query(context, models.ShareGroupSnapshot, read_deleted='no')

    # Apply filters
    if not filters:
        filters = {}
    no_key = 'key_is_absent'
    for k, v in filters.items():
        filter_attr = getattr(models.ShareGroupSnapshot, k, no_key)
        if filter_attr == no_key:
            msg = _("Share group snapshots cannot be filtered using '%s' key.")
            raise exception.InvalidInput(reason=msg % k)
        query = query.filter(filter_attr == v)

    if project_id:
        query = query.filter(
            models.ShareGroupSnapshot.project_id == project_id)

    try:
        query = apply_sorting(
            models.ShareGroupSnapshot, query, sort_key, sort_dir)
    except AttributeError:
        msg = _("Wrong sorting key provided - '%s'.") % sort_key
        raise exception.InvalidInput(reason=msg)

    if detailed:
        return query.options(
            joinedload('share_group'),
            joinedload('share_group_snapshot_members')
        ).all()
    else:
        query = query.with_entities(models.ShareGroupSnapshot.id,
                                    models.ShareGroupSnapshot.name)
        values = []
        for sgs_id, sgs_name in query.all():
            values.append({"id": sgs_id, "name": sgs_name})
        return values


@require_context
@context_manager.reader
def share_group_snapshot_get(context, share_group_snapshot_id):
    return _share_group_snapshot_get(context, share_group_snapshot_id)


@require_admin_context
@context_manager.reader
def share_group_snapshot_get_all(
        context, detailed=True, filters=None, sort_key=None, sort_dir=None):
    return _share_group_snapshot_get_all(
        context, filters=filters, detailed=detailed,
        sort_key=sort_key, sort_dir=sort_dir)


@require_context
@context_manager.reader
def share_group_snapshot_get_all_by_project(
        context, project_id, detailed=True, filters=None,
        sort_key=None, sort_dir=None):
    authorize_project_context(context, project_id)
    return _share_group_snapshot_get_all(
        context, project_id=project_id, filters=filters, detailed=detailed,
        sort_key=sort_key, sort_dir=sort_dir,
    )


@require_context
@context_manager.writer
def share_group_snapshot_create(context, values):
    share_group_snapshot = models.ShareGroupSnapshot()
    if not values.get('id'):
        values['id'] = uuidutils.generate_uuid()

    share_group_snapshot.update(values)
    context.session.add(share_group_snapshot)

    return _share_group_snapshot_get(context, values['id'])


@require_context
@context_manager.writer
def share_group_snapshot_update(context, share_group_snapshot_id, values):
    share_group_ref = _share_group_snapshot_get(
        context, share_group_snapshot_id,
    )
    share_group_ref.update(values)
    share_group_ref.save(session=context.session)
    return share_group_ref


@require_admin_context
@context_manager.writer
def share_group_snapshot_destroy(context, share_group_snapshot_id):
    share_group_snap_ref = _share_group_snapshot_get(
        context,
        share_group_snapshot_id,
    )
    share_group_snap_ref.soft_delete(context.session)
    context.session.query(
        models.ShareSnapshotInstance
    ).filter_by(
        share_group_snapshot_id=share_group_snapshot_id
    ).soft_delete()


####################


@require_context
@context_manager.reader
def share_group_snapshot_members_get_all(context, share_group_snapshot_id):
    query = model_query(
        context,
        models.ShareSnapshotInstance,
        read_deleted='no',
    ).filter_by(share_group_snapshot_id=share_group_snapshot_id)
    return query.all()


@require_context
@context_manager.reader
def share_group_snapshot_member_get(context, member_id):
    return _share_group_snapshot_member_get(context, member_id)


def _share_group_snapshot_member_get(context, member_id):
    result = model_query(
        context,
        models.ShareSnapshotInstance,
        project_only=True,
        read_deleted='no',
    ).filter_by(id=member_id).first()
    if not result:
        raise exception.ShareGroupSnapshotMemberNotFound(member_id=member_id)
    return result


@require_context
@context_manager.writer
def share_group_snapshot_member_create(context, values):
    if not values.get('id'):
        values['id'] = uuidutils.generate_uuid()

    _change_size_to_instance_size(values)

    member = models.ShareSnapshotInstance()
    member.update(values)
    context.session.add(member)

    return _share_group_snapshot_member_get(context, values['id'])


@require_context
@context_manager.writer
def share_group_snapshot_member_update(context, member_id, values):
    _change_size_to_instance_size(values)

    member = _share_group_snapshot_member_get(context, member_id)
    member.update(values)
    context.session.add(member)

    return _share_group_snapshot_member_get(context, member_id)


####################


@require_admin_context
@context_manager.writer
def share_group_type_create(context, values, projects=None):
    """Create a new share group type.

    In order to pass in group specs, the values dict should contain a
    'group_specs' key/value pair:
    {'group_specs' : {'k1': 'v1', 'k2': 'v2', ...}}
    """
    values = ensure_model_dict_has_id(values)

    projects = projects or []

    try:
        values['group_specs'] = _metadata_refs(
            values.get('group_specs'), models.ShareGroupTypeSpecs)
        mappings = []
        for item in values.get('share_types', []):
            share_type = share_type_get_by_name_or_id(context, item)
            if not share_type:
                raise exception.ShareTypeDoesNotExist(share_type=item)
            mapping = models.ShareGroupTypeShareTypeMapping()
            mapping['id'] = uuidutils.generate_uuid()
            mapping['share_type_id'] = share_type['id']
            mapping['share_group_type_id'] = values['id']
            mappings.append(mapping)

        values['share_types'] = mappings
        share_group_type_ref = models.ShareGroupTypes()
        share_group_type_ref.update(values)
        share_group_type_ref.save(session=context.session)
    except db_exception.DBDuplicateEntry:
        raise exception.ShareGroupTypeExists(type_id=values['name'])
    except exception.ShareTypeDoesNotExist:
        raise
    except Exception as e:
        raise db_exception.DBError(e)

    for project in set(projects):
        access_ref = models.ShareGroupTypeProjects()
        access_ref.update({"share_group_type_id": share_group_type_ref.id,
                           "project_id": project})
        access_ref.save(session=context.session)

    return share_group_type_ref


def _share_group_type_get_query(
    context,
    read_deleted=None,
    expected_fields=None,
):
    expected_fields = expected_fields or []
    query = model_query(
        context,
        models.ShareGroupTypes,
        read_deleted=read_deleted
    ).options(
        joinedload('group_specs'),
        joinedload('share_types'),
    )

    if 'projects' in expected_fields:
        query = query.options(joinedload('projects'))

    if not context.is_admin:
        the_filter = [models.ShareGroupTypes.is_public == true()]
        projects_attr = getattr(models.ShareGroupTypes, 'projects')
        the_filter.extend([
            projects_attr.any(project_id=context.project_id)
        ])
        query = query.filter(or_(*the_filter))

    return query


@require_context
@context_manager.reader
def share_group_type_get_all(context, inactive=False, filters=None):
    """Returns a dict describing all share group types with name as key."""
    filters = filters or {}
    read_deleted = "yes" if inactive else "no"
    query = _share_group_type_get_query(context, read_deleted=read_deleted)

    if 'is_public' in filters and filters['is_public'] is not None:
        the_filter = [models.ShareGroupTypes.is_public == filters['is_public']]
        if filters['is_public'] and context.project_id is not None:
            projects_attr = getattr(models. ShareGroupTypes, 'projects')
            the_filter.extend([
                projects_attr.any(
                    project_id=context.project_id, deleted=0)
            ])
        if len(the_filter) > 1:
            query = query.filter(or_(*the_filter))
        else:
            query = query.filter(the_filter[0])

    rows = query.order_by("name").all()

    result = {}
    for row in rows:
        result[row['name']] = _dict_with_specs(row, 'group_specs')

    return result


def _share_group_type_get_id_from_share_group_type_query(context, type_id):
    return model_query(
        context,
        models.ShareGroupTypes,
        read_deleted="no",
    ).filter_by(id=type_id)


def _share_group_type_get_id_from_share_group_type(context, type_id):
    result = _share_group_type_get_id_from_share_group_type_query(
        context,
        type_id,
    ).first()
    if not result:
        raise exception.ShareGroupTypeNotFound(type_id=type_id)
    return result['id']


@require_context
def _share_group_type_get(
    context,
    type_id,
    inactive=False,
    expected_fields=None,
):
    expected_fields = expected_fields or []
    read_deleted = "yes" if inactive else "no"
    result = _share_group_type_get_query(
        context,
        read_deleted,
        expected_fields,
    ).filter_by(id=type_id).first()

    if not result:
        raise exception.ShareGroupTypeNotFound(type_id=type_id)

    share_group_type = _dict_with_specs(result, 'group_specs')

    if 'projects' in expected_fields:
        share_group_type['projects'] = [
            p['project_id'] for p in result['projects']]

    return share_group_type


@require_context
@context_manager.reader
def share_group_type_get(context, type_id, inactive=False,
                         expected_fields=None):
    """Return a dict describing specific share group type."""
    return _share_group_type_get(
        context,
        type_id,
        inactive=inactive,
        expected_fields=expected_fields,
    )


@require_context
def _share_group_type_get_by_name(context, name):
    result = model_query(
        context,
        models.ShareGroupTypes,
    ).options(
        joinedload('group_specs'),
        joinedload('share_types'),
    ).filter_by(
        name=name,
    ).first()
    if not result:
        raise exception.ShareGroupTypeNotFoundByName(type_name=name)
    return _dict_with_specs(result, 'group_specs')


@require_context
@context_manager.reader
def share_group_type_get_by_name(context, name):
    """Return a dict describing specific share group type."""
    return _share_group_type_get_by_name(context, name)


@require_admin_context
@context_manager.writer
def share_group_type_destroy(context, type_id):
    _share_group_type_get(context, type_id)
    results = model_query(
        context,
        models.ShareGroup,
        read_deleted="no",
    ).filter_by(
        share_group_type_id=type_id,
    ).count()
    if results:
        LOG.error('Share group type %s deletion failed, it in use.',
                  type_id)
        raise exception.ShareGroupTypeInUse(type_id=type_id)

    model_query(
        context,
        models.ShareGroupTypeSpecs,
    ).filter_by(
        share_group_type_id=type_id,
    ).soft_delete()

    model_query(
        context,
        models.ShareGroupTypeShareTypeMapping,
    ).filter_by(
        share_group_type_id=type_id,
    ).soft_delete()

    model_query(
        context,
        models.ShareGroupTypeProjects,
    ).filter_by(
        share_group_type_id=type_id,
    ).soft_delete()

    model_query(
        context,
        models.ShareGroupTypes,
    ).filter_by(
        id=type_id,
    ).soft_delete()


###############################


def _share_group_type_access_query(context,):
    return model_query(
        context,
        models.ShareGroupTypeProjects,
        read_deleted="no",
    )


@require_admin_context
@context_manager.reader
def share_group_type_access_get_all(context, type_id):
    share_group_type_id = _share_group_type_get_id_from_share_group_type(
        context, type_id)
    return _share_group_type_access_query(context).filter_by(
        share_group_type_id=share_group_type_id,
    ).all()


@require_admin_context
@context_manager.writer
def share_group_type_access_add(context, type_id, project_id):
    """Add given tenant to the share group type  access list."""
    share_group_type_id = _share_group_type_get_id_from_share_group_type(
        context, type_id)
    access_ref = models.ShareGroupTypeProjects()
    access_ref.update({"share_group_type_id": share_group_type_id,
                       "project_id": project_id})
    try:
        access_ref.save(session=context.session)
    except db_exception.DBDuplicateEntry:
        raise exception.ShareGroupTypeAccessExists(
            type_id=share_group_type_id, project_id=project_id)
    return access_ref


@require_admin_context
@context_manager.writer
def share_group_type_access_remove(context, type_id, project_id):
    """Remove given tenant from the share group type access list."""
    share_group_type_id = _share_group_type_get_id_from_share_group_type(
        context, type_id)
    count = _share_group_type_access_query(context).filter_by(
        share_group_type_id=share_group_type_id,
    ).filter_by(
        project_id=project_id,
    ).soft_delete(
        synchronize_session=False,
    )
    if count == 0:
        raise exception.ShareGroupTypeAccessNotFound(
            type_id=share_group_type_id, project_id=project_id)


###############################


def _share_group_type_specs_query(context, type_id):
    return model_query(
        context,
        models.ShareGroupTypeSpecs,
        read_deleted="no"
    ).filter_by(
        share_group_type_id=type_id,
    ).options(
        joinedload('share_group_type'),
    )


@require_context
@context_manager.reader
def share_group_type_specs_get(context, type_id):
    rows = _share_group_type_specs_query(context, type_id).all()
    result = {}
    for row in rows:
        result[row['key']] = row['value']
    return result


@require_context
@context_manager.writer
def share_group_type_specs_delete(context, type_id, key):
    _share_group_type_specs_get_item(context, type_id, key)
    _share_group_type_specs_query(
        context,
        type_id,
    ).filter_by(
        key=key,
    ).soft_delete()


@require_context
def _share_group_type_specs_get_item(context, type_id, key):
    result = _share_group_type_specs_query(
        context,
        type_id,
    ).filter_by(
        key=key,
    ).options(
        joinedload('share_group_type'),
    ).first()

    if not result:
        raise exception.ShareGroupTypeSpecsNotFound(
            specs_key=key, type_id=type_id)

    return result


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
@context_manager.writer
def share_group_type_specs_update_or_create(context, type_id, specs):
    spec_ref = None
    for key, value in specs.items():
        try:
            spec_ref = _share_group_type_specs_get_item(
                context,
                type_id,
                key,
            )
        except exception.ShareGroupTypeSpecsNotFound:
            spec_ref = models.ShareGroupTypeSpecs()
        spec_ref.update({"key": key, "value": value,
                         "share_group_type_id": type_id, "deleted": 0})
        spec_ref.save(session=context.session)

    return specs


###############################


@require_context
def _message_get(context, message_id):
    query = model_query(context,
                        models.Message,
                        read_deleted="no",
                        project_only="yes")
    result = query.filter_by(id=message_id).first()
    if not result:
        raise exception.MessageNotFound(message_id=message_id)
    return result


@require_context
@context_manager.reader
def message_get(context, message_id):
    return _message_get(context, message_id)


@require_context
@context_manager.reader
def message_get_all(context, filters=None, limit=None, offset=None,
                    sort_key='created_at', sort_dir='desc'):
    """Retrieves all messages.

    If no sort parameters are specified then the returned messages are
    sorted by the 'created_at' key in descending order.

    :param context: context to query under
    :param limit: maximum number of items to return
    :param offset: the number of items to skip from the marker or from the
                    first element.
    :param sort_key: attributes by which results should be sorted.
    :param sort_dir: directions in which results should be sorted.
    :param filters: dictionary of filters; values that are in lists, tuples,
                    or sets cause an 'IN' operation, while exact matching
                    is used for other values, see exact_filter function for
                    more information
    :returns: list of matching messages
    """
    messages = models.Message

    query = model_query(context,
                        messages,
                        read_deleted="no",
                        project_only="yes")

    legal_filter_keys = ('request_id', 'resource_type', 'resource_id',
                         'action_id', 'detail_id', 'message_level',
                         'created_since', 'created_before')

    if not filters:
        filters = {}

    query = exact_filter(query, messages, filters, legal_filter_keys)

    query = utils.paginate_query(query, messages, limit,
                                 sort_key=sort_key,
                                 sort_dir=sort_dir,
                                 offset=offset)

    return query.all()


@require_context
@context_manager.writer
def message_create(context, message_values):
    values = copy.deepcopy(message_values)
    message_ref = models.Message()
    if not values.get('id'):
        values['id'] = uuidutils.generate_uuid()
    message_ref.update(values)

    context.session.add(message_ref)

    return _message_get(context, message_ref['id'])


@require_context
@context_manager.writer
def message_destroy(context, message):
    model_query(
        context, models.Message,
    ).filter_by(id=message.get('id')).soft_delete()


@require_admin_context
@context_manager.writer
def cleanup_expired_messages(context):
    now = timeutils.utcnow()
    return context.session.query(
        models.Message
    ).filter(
        models.Message.expires_at < now
    ).delete()


###############################


@require_context
@context_manager.reader
def backend_info_get(context, host):
    """Get hash info for given host."""
    result = _backend_info_query(context, host)
    return result


@require_context
@context_manager.writer
def backend_info_create(context, host, value):
    info_ref = models.BackendInfo()
    info_ref.update({"host": host, "info_hash": value})
    info_ref.save(context.session)
    return info_ref


@require_context
@context_manager.writer
def backend_info_update(context, host, value=None, delete_existing=False):
    """Remove backend info for host name."""
    info_ref = _backend_info_query(context, host)
    if info_ref:
        if value:
            info_ref.update({"info_hash": value})
        elif delete_existing and info_ref['deleted'] != 1:
            info_ref.update({"deleted": 1, "deleted_at": timeutils.utcnow()})
    else:
        info_ref = models.BackendInfo()
        info_ref.update({"host": host, "info_hash": value})
    info_ref.save(context.session)
    return info_ref


def _backend_info_query(context, host, read_deleted=False):
    result = model_query(
        context,
        models.BackendInfo,
        read_deleted=read_deleted,
    ).filter_by(
        host=host,
    ).first()

    return result

###################


def _async_operation_data_query(
    context, entity_id, key=None, read_deleted=False,
):
    query = model_query(
        context, models.AsynchronousOperationData,
        read_deleted=read_deleted,
    ).filter_by(
        entity_uuid=entity_id,
    )

    if isinstance(key, list):
        return query.filter(models.AsynchronousOperationData.key.in_(key))
    elif key is not None:
        return query.filter_by(key=key)

    return query


@require_context
@context_manager.reader
def async_operation_data_get(context, entity_id, key=None, default=None):
    query = _async_operation_data_query(context, entity_id, key)

    if key is None or isinstance(key, list):
        return {item.key: item.value for item in query.all()}
    else:
        result = query.first()
        return result["value"] if result is not None else default


@require_context
@context_manager.writer
def async_operation_data_update(
    context, entity_id, details, delete_existing=False,
):
    new_details = copy.deepcopy(details)

    # Process existing data
    original_data = context.session.query(
        models.AsynchronousOperationData).filter_by(
        entity_uuid=entity_id,
    ).all()

    for data_ref in original_data:
        in_new_details = data_ref['key'] in new_details

        if in_new_details:
            new_value = str(new_details.pop(data_ref['key']))
            data_ref.update({
                "value": new_value,
                "deleted": 0,
                "deleted_at": None
            })
            data_ref.save(session=context.session)
        elif delete_existing and data_ref['deleted'] != 1:
            data_ref.update({
                "deleted": 1, "deleted_at": timeutils.utcnow()
            })
            data_ref.save(session=context.session)

    # Add new data
    for key, value in new_details.items():
        data_ref = models.AsynchronousOperationData()
        data_ref.update({
            "entity_uuid": entity_id,
            "key": key,
            "value": str(value)
        })
        data_ref.save(session=context.session)

    return details


@require_context
@context_manager.writer
def async_operation_data_delete(context, entity_id, key=None):
    query = _async_operation_data_query(context, entity_id, key)
    query.update({"deleted": 1, "deleted_at": timeutils.utcnow()})


@require_context
def share_backup_create(context, share_id, values):
    return _share_backup_create(context, share_id, values)


@require_context
@context_manager.writer
def _share_backup_create(context, share_id, values):
    if not values.get('id'):
        values['id'] = uuidutils.generate_uuid()
    values.update({'share_id': share_id})
    _ensure_availability_zone_exists(context, values)

    share_backup_ref = models.ShareBackup()
    share_backup_ref.update(values)
    share_backup_ref.save(session=context.session)
    return share_backup_get(context, share_backup_ref['id'])


@require_context
@context_manager.reader
def share_backup_get(context, share_backup_id):
    result = model_query(
        context, models.ShareBackup, project_only=True, read_deleted="no"
    ).filter_by(
        id=share_backup_id,
    ).first()
    if result is None:
        raise exception.ShareBackupNotFound(backup_id=share_backup_id)

    return result


@require_context
@context_manager.reader
def share_backups_get_all(context, filters=None,
                          limit=None, offset=None,
                          sort_key=None, sort_dir=None):
    project_id = filters.pop('project_id', None) if filters else None
    query = _share_backups_get_with_filters(
        context,
        project_id=project_id,
        filters=filters, limit=limit, offset=offset,
        sort_key=sort_key, sort_dir=sort_dir)

    return query


def _share_backups_get_with_filters(context, project_id=None, filters=None,
                                    limit=None, offset=None,
                                    sort_key=None, sort_dir=None):
    """Retrieves all backups.

    If no sorting parameters are specified then returned backups are sorted
    by the 'created_at' key and desc order.

    :param context: context to query under
    :param filters: dictionary of filters
    :param limit: maximum number of items to return
    :param sort_key: attribute by which results should be sorted,default is
                     created_at
    :param sort_dir: direction in which results should be sorted
    :returns: list of matching backups
    """
    # Init data
    sort_key = sort_key or 'created_at'
    sort_dir = sort_dir or 'desc'
    filters = copy.deepcopy(filters) if filters else {}
    query = model_query(context, models.ShareBackup)

    if project_id:
        query = query.filter_by(project_id=project_id)

    legal_filter_keys = ('display_name', 'display_name~',
                         'display_description', 'display_description~',
                         'id', 'share_id', 'host', 'topic', 'status')
    query = exact_filter(query, models.ShareBackup,
                         filters, legal_filter_keys)

    query = apply_sorting(models.ShareBackup, query, sort_key, sort_dir)

    if limit is not None:
        query = query.limit(limit)

    if offset:
        query = query.offset(offset)

    return query.all()


@require_admin_context
@context_manager.reader
def _backup_data_get_for_project(context, project_id, user_id):
    query = model_query(context, models.ShareBackup,
                        func.count(models.ShareBackup.id),
                        func.sum(models.ShareBackup.size),
                        read_deleted="no").\
        filter_by(project_id=project_id)

    if user_id:
        result = query.filter_by(user_id=user_id).first()
    else:
        result = query.first()

    return (result[0] or 0, result[1] or 0)


@require_context
@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
@context_manager.writer
def share_backup_update(context, backup_id, values):
    _ensure_availability_zone_exists(context, values, strict=False)
    backup_ref = share_backup_get(context, backup_id)
    backup_ref.update(values)
    backup_ref.save(session=context.session)
    return backup_ref


@require_context
@context_manager.writer
def share_backup_delete(context, backup_id):
    backup_ref = share_backup_get(context, backup_id)
    backup_ref.soft_delete(session=context.session, update_status=True)

###############################


@require_context
def _resource_lock_get(context, lock_id):
    query = model_query(context,
                        models.ResourceLock,
                        read_deleted="no",
                        project_only="yes")
    result = query.filter_by(id=lock_id).first()
    if not result:
        raise exception.ResourceLockNotFound(lock_id=lock_id)
    return result


@require_context
@context_manager.writer
def resource_lock_create(context, kwargs):
    """Create a resource lock."""
    values = copy.deepcopy(kwargs)
    lock_ref = models.ResourceLock()
    if not values.get('id'):
        values['id'] = uuidutils.generate_uuid()
    lock_ref.update(values)

    context.session.add(lock_ref)

    return _resource_lock_get(context, lock_ref['id'])


@require_context
@context_manager.writer
def resource_lock_update(context, lock_id, kwargs):
    """Update a resource lock."""
    lock_ref = _resource_lock_get(context, lock_id)
    lock_ref.update(kwargs)
    lock_ref.save(session=context.session)
    return lock_ref


@require_context
@context_manager.writer
def resource_lock_delete(context, lock_id):
    """Delete a resource lock."""
    lock_ref = _resource_lock_get(context, lock_id)
    lock_ref.soft_delete(session=context.session)


@require_context
@context_manager.reader
def resource_lock_get(context, lock_id):
    """Retrieve a resource lock."""
    return _resource_lock_get(context, lock_id)


@require_context
@context_manager.reader
def resource_lock_get_all(context, filters=None, limit=None, offset=None,
                          sort_key='created_at', sort_dir='desc',
                          show_count=False):
    """Retrieve all resource locks.

    If no sort parameters are specified then the returned locks are
    sorted by the 'created_at' key in descending order.

    :param context: context to query under
    :param limit: maximum number of items to return
    :param offset: the number of items to skip from the marker or from the
                    first element.
    :param sort_key: attributes by which results should be sorted.
    :param sort_dir: directions in which results should be sorted.
    :param filters: dictionary of filters; values that are in lists, tuples,
                    or sets cause an 'IN' operation, while exact matching
                    is used for other values, see exact_filter function for
                    more information
    :returns: list of matching resource locks
    """
    locks = models.ResourceLock

    # add policy check to allow: all_projects, project_id filters
    filters = filters or {}

    query = model_query(context, locks, read_deleted="no")

    project_id = filters.get('project_id')
    all_projects = filters.get('all_projects') or filters.get('all_tenants')
    if project_id is None and not all_projects:
        filters['project_id'] = context.project_id

    legal_filter_keys = ('id', 'user_id', 'resource_id', 'resource_type',
                         'lock_context', 'resource_action', 'created_since',
                         'created_before', 'lock_reason', 'lock_reason~',
                         'project_id')

    query = exact_filter(query, locks, filters, legal_filter_keys)

    count = query.count() if show_count else None

    query = utils.paginate_query(query, locks, limit,
                                 sort_key=sort_key,
                                 sort_dir=sort_dir,
                                 offset=offset)

    return query.all(), count
