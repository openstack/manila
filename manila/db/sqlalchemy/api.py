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

import sys
import uuid
import warnings

from oslo_config import cfg
from oslo_db import exception as db_exception
from oslo_db import options as db_options
from oslo_db.sqlalchemy import session
from oslo_log import log
from oslo_utils import timeutils
import six
from sqlalchemy import or_
from sqlalchemy.orm import joinedload
from sqlalchemy.sql.expression import literal_column
from sqlalchemy.sql import func

from manila.common import constants
from manila.db.sqlalchemy import models
from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LW


CONF = cfg.CONF

LOG = log.getLogger(__name__)

_DEFAULT_QUOTA_NAME = 'default'
PER_PROJECT_QUOTAS = []

_FACADE = None

_DEFAULT_SQL_CONNECTION = 'sqlite://'
db_options.set_defaults(cfg.CONF,
                        connection=_DEFAULT_SQL_CONNECTION)


def _create_facade_lazily():
    global _FACADE
    if _FACADE is None:
        _FACADE = session.EngineFacade.from_config(cfg.CONF)
    return _FACADE


def get_engine():
    facade = _create_facade_lazily()
    return facade.get_engine()


def get_session(**kwargs):
    facade = _create_facade_lazily()
    return facade.get_session(**kwargs)


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

    def wrapper(context, share_id, *args, **kwargs):
        share_get(context, share_id)
        return f(context, share_id, *args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


def model_query(context, model, *args, **kwargs):
    """Query helper that accounts for context's `read_deleted` field.

    :param context: context to query under
    :param session: if present, the session to use
    :param read_deleted: if present, overrides context's read_deleted field.
    :param project_only: if present and context is user-type, then restrict
            query to match the context's project_id.
    """
    session = kwargs.get('session') or get_session()
    read_deleted = kwargs.get('read_deleted') or context.read_deleted
    project_only = kwargs.get('project_only')

    query = session.query(model, *args)

    default_deleted_value = str(model.__mapper__.c.deleted.default.arg)
    if read_deleted == 'no':
        query = query.filter(model.deleted == default_deleted_value)
    elif read_deleted == 'yes':
        pass  # omit the filter to include deleted and active
    elif read_deleted == 'only':
        query = query.filter(model.deleted != default_deleted_value)
    else:
        raise Exception(_("Unrecognized read_deleted value '%s'")
                        % read_deleted)

    if project_only and is_user_context(context):
        query = query.filter_by(project_id=context.project_id)

    return query


def exact_filter(query, model, filters, legal_keys):
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

    # Walk through all the keys
    for key in legal_keys:
        # Skip ones we're not filtering on
        if key not in filters:
            continue

        # OK, filtering on this key; what value do we search for?
        value = filters.pop(key)

        if isinstance(value, (list, tuple, set, frozenset)):
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


def _sync_shares(context, project_id, user_id, session):
    (shares, gigs) = share_data_get_for_project(context,
                                                project_id,
                                                user_id,
                                                session=session)
    return {'shares': shares}


def _sync_snapshots(context, project_id, user_id, session):
    (snapshots, gigs) = snapshot_data_get_for_project(context,
                                                      project_id,
                                                      user_id,
                                                      session=session)
    return {'snapshots': snapshots}


def _sync_gigabytes(context, project_id, user_id, session):
    _junk, share_gigs = share_data_get_for_project(
        context, project_id, user_id, session=session)
    return dict(gigabytes=share_gigs)


def _sync_snapshot_gigabytes(context, project_id, user_id, session):
    _junk, snapshot_gigs = snapshot_data_get_for_project(
        context, project_id, user_id, session=session)
    return dict(snapshot_gigabytes=snapshot_gigs)


def _sync_share_networks(context, project_id, user_id, session):
    share_networks = share_network_get_all_by_project(context,
                                                      project_id,
                                                      user_id,
                                                      session=session)
    return {'share_networks': len(share_networks)}


QUOTA_SYNC_FUNCTIONS = {
    '_sync_shares': _sync_shares,
    '_sync_snapshots': _sync_snapshots,
    '_sync_gigabytes': _sync_gigabytes,
    '_sync_snapshot_gigabytes': _sync_snapshot_gigabytes,
    '_sync_share_networks': _sync_share_networks,
}


###################


@require_admin_context
def service_destroy(context, service_id):
    session = get_session()
    with session.begin():
        service_ref = service_get(context, service_id, session=session)
        service_ref.delete(session=session)


@require_admin_context
def service_get(context, service_id, session=None):
    result = model_query(
        context,
        models.Service,
        session=session).\
        filter_by(id=service_id).\
        first()
    if not result:
        raise exception.ServiceNotFound(service_id=service_id)

    return result


@require_admin_context
def service_get_all(context, disabled=None):
    query = model_query(context, models.Service)

    if disabled is not None:
        query = query.filter_by(disabled=disabled)

    return query.all()


@require_admin_context
def service_get_all_by_topic(context, topic):
    return model_query(
        context, models.Service, read_deleted="no").\
        filter_by(disabled=False).\
        filter_by(topic=topic).\
        all()


@require_admin_context
def service_get_by_host_and_topic(context, host, topic):
    result = model_query(
        context, models.Service, read_deleted="no").\
        filter_by(disabled=False).\
        filter_by(host=host).\
        filter_by(topic=topic).\
        first()
    if not result:
        raise exception.ServiceNotFound(service_id=None)
    return result


@require_admin_context
def service_get_all_by_host(context, host):
    return model_query(
        context, models.Service, read_deleted="no").\
        filter_by(host=host).\
        all()


@require_admin_context
def _service_get_all_topic_subquery(context, session, topic, subq, label):
    sort_value = getattr(subq.c, label)
    return model_query(context, models.Service,
                       func.coalesce(sort_value, 0),
                       session=session, read_deleted="no").\
        filter_by(topic=topic).\
        filter_by(disabled=False).\
        outerjoin((subq, models.Service.host == subq.c.host)).\
        order_by(sort_value).\
        all()


@require_admin_context
def service_get_all_share_sorted(context):
    session = get_session()
    with session.begin():
        topic = CONF.share_topic
        label = 'share_gigabytes'
        subq = model_query(context, models.Share, models.Share.host,
                           func.sum(models.Share.size).label(label),
                           session=session, read_deleted="no").\
            group_by(models.Share.host).\
            subquery()
        return _service_get_all_topic_subquery(context,
                                               session,
                                               topic,
                                               subq,
                                               label)


@require_admin_context
def service_get_by_args(context, host, binary):
    result = model_query(context, models.Service).\
        filter_by(host=host).\
        filter_by(binary=binary).\
        first()

    if not result:
        raise exception.HostBinaryNotFound(host=host, binary=binary)

    return result


@require_admin_context
def service_create(context, values):
    service_ref = models.Service()
    service_ref.update(values)
    if not CONF.enable_new_services:
        service_ref.disabled = True

    session = get_session()
    with session.begin():
        service_ref.save(session)
        return service_ref


@require_admin_context
def service_update(context, service_id, values):
    session = get_session()
    with session.begin():
        service_ref = service_get(context, service_id, session=session)
        service_ref.update(values)
        service_ref.save(session=session)


###################


@require_context
def quota_get(context, project_id, resource, session=None):
    result = model_query(context, models.Quota, session=session,
                         read_deleted="no").\
        filter_by(project_id=project_id).\
        filter_by(resource=resource).\
        first()

    if not result:
        raise exception.ProjectQuotaNotFound(project_id=project_id)

    return result


@require_context
def quota_get_all_by_project_and_user(context, project_id, user_id):
    authorize_project_context(context, project_id)

    user_quotas = model_query(context, models.ProjectUserQuota,
                              models.ProjectUserQuota.resource,
                              models.ProjectUserQuota.hard_limit).\
        filter_by(project_id=project_id).\
        filter_by(user_id=user_id).\
        all()

    result = {'project_id': project_id, 'user_id': user_id}
    for quota in user_quotas:
        result[quota.resource] = quota.hard_limit

    return result


@require_context
def quota_get_all_by_project(context, project_id):
    authorize_project_context(context, project_id)

    rows = model_query(context, models.Quota, read_deleted="no").\
        filter_by(project_id=project_id).\
        all()

    result = {'project_id': project_id}
    for row in rows:
        result[row.resource] = row.hard_limit

    return result


@require_context
def quota_get_all(context, project_id):
    authorize_project_context(context, project_id)

    result = model_query(context, models.ProjectUserQuota).\
        filter_by(project_id=project_id).\
        all()

    return result


@require_admin_context
def quota_create(context, project_id, resource, limit, user_id=None):
    per_user = user_id and resource not in PER_PROJECT_QUOTAS

    if per_user:
        check = model_query(context, models.ProjectUserQuota).\
            filter_by(project_id=project_id).\
            filter_by(user_id=user_id).\
            filter_by(resource=resource).\
            all()
    else:
        check = model_query(context, models.Quota).\
            filter_by(project_id=project_id).\
            filter_by(resource=resource).\
            all()
    if check:
        raise exception.QuotaExists(project_id=project_id, resource=resource)

    quota_ref = models.ProjectUserQuota() if per_user else models.Quota()
    if per_user:
        quota_ref.user_id = user_id
    quota_ref.project_id = project_id
    quota_ref.resource = resource
    quota_ref.hard_limit = limit
    session = get_session()
    with session.begin():
        quota_ref.save(session)
    return quota_ref


@require_admin_context
def quota_update(context, project_id, resource, limit, user_id=None):
    per_user = user_id and resource not in PER_PROJECT_QUOTAS
    model = models.ProjectUserQuota if per_user else models.Quota
    query = model_query(context, model).\
        filter_by(project_id=project_id).\
        filter_by(resource=resource)
    if per_user:
        query = query.filter_by(user_id=user_id)

    result = query.update({'hard_limit': limit})
    if not result:
        if per_user:
            raise exception.ProjectUserQuotaNotFound(project_id=project_id,
                                                     user_id=user_id)
        else:
            raise exception.ProjectQuotaNotFound(project_id=project_id)


###################


@require_context
def quota_class_get(context, class_name, resource, session=None):
    result = model_query(context, models.QuotaClass, session=session,
                         read_deleted="no").\
        filter_by(class_name=class_name).\
        filter_by(resource=resource).\
        first()

    if not result:
        raise exception.QuotaClassNotFound(class_name=class_name)

    return result


def quota_class_get_default(context):
    rows = model_query(context, models.QuotaClass, read_deleted="no").\
        filter_by(class_name=_DEFAULT_QUOTA_NAME).\
        all()

    result = {'class_name': _DEFAULT_QUOTA_NAME}
    for row in rows:
        result[row.resource] = row.hard_limit

    return result


@require_context
def quota_class_get_all_by_name(context, class_name):
    authorize_quota_class_context(context, class_name)

    rows = model_query(context, models.QuotaClass, read_deleted="no").\
        filter_by(class_name=class_name).\
        all()

    result = {'class_name': class_name}
    for row in rows:
        result[row.resource] = row.hard_limit

    return result


@require_admin_context
def quota_class_create(context, class_name, resource, limit):
    quota_class_ref = models.QuotaClass()
    quota_class_ref.class_name = class_name
    quota_class_ref.resource = resource
    quota_class_ref.hard_limit = limit
    session = get_session()
    with session.begin():
        quota_class_ref.save(session)
    return quota_class_ref


@require_admin_context
def quota_class_update(context, class_name, resource, limit):
    result = model_query(context, models.QuotaClass, read_deleted="no").\
        filter_by(class_name=class_name).\
        filter_by(resource=resource).\
        update({'hard_limit': limit})

    if not result:
        raise exception.QuotaClassNotFound(class_name=class_name)


###################


@require_context
def quota_usage_get(context, project_id, resource, user_id=None):
    query = model_query(context, models.QuotaUsage, read_deleted="no").\
        filter_by(project_id=project_id).\
        filter_by(resource=resource)
    if user_id:
        if resource not in PER_PROJECT_QUOTAS:
            result = query.filter_by(user_id=user_id).first()
        else:
            result = query.filter_by(user_id=None).first()
    else:
        result = query.first()

    if not result:
        raise exception.QuotaUsageNotFound(project_id=project_id)

    return result


def _quota_usage_get_all(context, project_id, user_id=None):
    authorize_project_context(context, project_id)
    query = model_query(context, models.QuotaUsage, read_deleted="no").\
        filter_by(project_id=project_id)
    result = {'project_id': project_id}
    if user_id:
        query = query.filter(or_(models.QuotaUsage.user_id == user_id,
                                 models.QuotaUsage.user_id is None))
        result['user_id'] = user_id

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
def quota_usage_get_all_by_project(context, project_id):
    return _quota_usage_get_all(context, project_id)


@require_context
def quota_usage_get_all_by_project_and_user(context, project_id, user_id):
    return _quota_usage_get_all(context, project_id, user_id=user_id)


def _quota_usage_create(context, project_id, user_id, resource, in_use,
                        reserved, until_refresh, session=None):
    quota_usage_ref = models.QuotaUsage()
    quota_usage_ref.project_id = project_id
    quota_usage_ref.user_id = user_id
    quota_usage_ref.resource = resource
    quota_usage_ref.in_use = in_use
    quota_usage_ref.reserved = reserved
    quota_usage_ref.until_refresh = until_refresh
    # updated_at is needed for judgement of max_age
    quota_usage_ref.updated_at = timeutils.utcnow()

    quota_usage_ref.save(session=session)

    return quota_usage_ref


@require_admin_context
def quota_usage_update(context, project_id, user_id, resource, **kwargs):
    updates = {}

    for key in ['in_use', 'reserved', 'until_refresh']:
        if key in kwargs:
            updates[key] = kwargs[key]

    result = model_query(context, models.QuotaUsage, read_deleted="no").\
        filter_by(project_id=project_id).\
        filter_by(resource=resource).\
        filter(or_(models.QuotaUsage.user_id == user_id,
                   models.QuotaUsage.user_id is None)).\
        update(updates)

    if not result:
        raise exception.QuotaUsageNotFound(project_id=project_id)


###################


@require_context
def reservation_get(context, uuid, session=None):
    result = model_query(context, models.Reservation, session=session,
                         read_deleted="no").\
        filter_by(uuid=uuid).first()

    if not result:
        raise exception.ReservationNotFound(uuid=uuid)

    return result


@require_admin_context
def reservation_create(context, uuid, usage, project_id, user_id, resource,
                       delta, expire):
    return _reservation_create(context, uuid, usage, project_id, user_id,
                               resource, delta, expire)


def _reservation_create(context, uuid, usage, project_id, user_id, resource,
                        delta, expire, session=None):
    reservation_ref = models.Reservation()
    reservation_ref.uuid = uuid
    reservation_ref.usage_id = usage['id']
    reservation_ref.project_id = project_id
    reservation_ref.user_id = user_id
    reservation_ref.resource = resource
    reservation_ref.delta = delta
    reservation_ref.expire = expire
    reservation_ref.save(session=session)
    return reservation_ref


###################


# NOTE(johannes): The quota code uses SQL locking to ensure races don't
# cause under or over counting of resources. To avoid deadlocks, this
# code always acquires the lock on quota_usages before acquiring the lock
# on reservations.

def _get_user_quota_usages(context, session, project_id, user_id):
    # Broken out for testability
    rows = model_query(context, models.QuotaUsage,
                       read_deleted="no",
                       session=session).\
        filter_by(project_id=project_id).\
        filter(or_(models.QuotaUsage.user_id == user_id,
                   models.QuotaUsage.user_id is None)).\
        with_lockmode('update').\
        all()
    return dict((row.resource, row) for row in rows)


def _get_project_quota_usages(context, session, project_id):
    rows = model_query(context, models.QuotaUsage,
                       read_deleted="no",
                       session=session).\
        filter_by(project_id=project_id).\
        with_lockmode('update').\
        all()
    result = dict()
    # Get the total count of in_use,reserved
    for row in rows:
        if row.resource in result:
            result[row.resource]['in_use'] += row.in_use
            result[row.resource]['reserved'] += row.reserved
            result[row.resource]['total'] += (row.in_use + row.reserved)
        else:
            result[row.resource] = dict(in_use=row.in_use,
                                        reserved=row.reserved,
                                        total=row.in_use + row.reserved)
    return result


@require_context
def quota_reserve(context, resources, project_quotas, user_quotas, deltas,
                  expire, until_refresh, max_age, project_id=None,
                  user_id=None):
    elevated = context.elevated()
    session = get_session()
    with session.begin():

        if project_id is None:
            project_id = context.project_id
        if user_id is None:
            user_id = context.user_id

        # Get the current usages
        user_usages = _get_user_quota_usages(context, session,
                                             project_id, user_id)
        project_usages = _get_project_quota_usages(context, session,
                                                   project_id)

        # Handle usage refresh
        work = set(deltas.keys())
        while work:
            resource = work.pop()

            # Do we need to refresh the usage?
            refresh = False
            if ((resource not in PER_PROJECT_QUOTAS) and
                    (resource not in user_usages)):
                user_usages[resource] = _quota_usage_create(
                    elevated,
                    project_id,
                    user_id,
                    resource,
                    0, 0,
                    until_refresh or None,
                    session=session)
                refresh = True
            elif ((resource in PER_PROJECT_QUOTAS) and
                    (resource not in user_usages)):
                user_usages[resource] = _quota_usage_create(
                    elevated,
                    project_id,
                    None,
                    resource,
                    0, 0,
                    until_refresh or None,
                    session=session)
                refresh = True
            elif user_usages[resource].in_use < 0:
                # Negative in_use count indicates a desync, so try to
                # heal from that...
                refresh = True
            elif user_usages[resource].until_refresh is not None:
                user_usages[resource].until_refresh -= 1
                if user_usages[resource].until_refresh <= 0:
                    refresh = True
            elif max_age and (user_usages[resource].updated_at -
                              timeutils.utcnow()).seconds >= max_age:
                refresh = True

            # OK, refresh the usage
            if refresh:
                # Grab the sync routine
                sync = QUOTA_SYNC_FUNCTIONS[resources[resource].sync]

                updates = sync(elevated, project_id, user_id, session)
                for res, in_use in updates.items():
                    # Make sure we have a destination for the usage!
                    if ((res not in PER_PROJECT_QUOTAS) and
                            (res not in user_usages)):
                        user_usages[res] = _quota_usage_create(
                            elevated,
                            project_id,
                            user_id,
                            res,
                            0, 0,
                            until_refresh or None,
                            session=session)
                    if ((res in PER_PROJECT_QUOTAS) and
                            (res not in user_usages)):
                        user_usages[res] = _quota_usage_create(
                            elevated,
                            project_id,
                            None,
                            res,
                            0, 0,
                            until_refresh or None,
                            session=session)

                    if user_usages[res].in_use != in_use:
                        LOG.debug('quota_usages out of sync, updating. '
                                  'project_id: %(project_id)s, '
                                  'user_id: %(user_id)s, '
                                  'resource: %(res)s, '
                                  'tracked usage: %(tracked_use)s, '
                                  'actual usage: %(in_use)s',
                                  {'project_id': project_id,
                                   'user_id': user_id,
                                   'res': res,
                                   'tracked_use': user_usages[res].in_use,
                                   'in_use': in_use})

                    # Update the usage
                    user_usages[res].in_use = in_use
                    user_usages[res].until_refresh = until_refresh or None

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
                  delta + user_usages[res].in_use < 0]

        # Now, let's check the quotas
        # NOTE(Vek): We're only concerned about positive increments.
        #            If a project has gone over quota, we want them to
        #            be able to reduce their usage without any
        #            problems.
        for key, value in user_usages.items():
            if key not in project_usages:
                project_usages[key] = value
        overs = [res for res, delta in deltas.items()
                 if user_quotas[res] >= 0 and delta >= 0 and
                 (project_quotas[res] < delta +
                  project_usages[res]['total'] or
                  user_quotas[res] < delta +
                  user_usages[res].total)]

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
                reservation = _reservation_create(elevated,
                                                  str(uuid.uuid4()),
                                                  user_usages[res],
                                                  project_id,
                                                  user_id,
                                                  res, delta, expire,
                                                  session=session)
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
                    user_usages[res].reserved += delta

        # Apply updates to the usages table
        for usage_ref in user_usages.values():
            session.add(usage_ref)

    if unders:
        LOG.warning(_LW("Change will make usage less than 0 for the following "
                        "resources: %s"), unders)
    if overs:
        if project_quotas == user_quotas:
            usages = project_usages
        else:
            usages = user_usages
        usages = dict((k, dict(in_use=v['in_use'], reserved=v['reserved']))
                      for k, v in usages.items())
        raise exception.OverQuota(overs=sorted(overs), quotas=user_quotas,
                                  usages=usages)

    return reservations


def _quota_reservations_query(session, context, reservations):
    """Return the relevant reservations."""

    # Get the listed reservations
    return model_query(context, models.Reservation,
                       read_deleted="no",
                       session=session).\
        filter(models.Reservation.uuid.in_(reservations)).\
        with_lockmode('update')


@require_context
def reservation_commit(context, reservations, project_id=None, user_id=None):
    session = get_session()
    with session.begin():
        usages = _get_user_quota_usages(context, session, project_id, user_id)
        reservation_query = _quota_reservations_query(session, context,
                                                      reservations)
        for reservation in reservation_query.all():
            usage = usages[reservation.resource]
            if reservation.delta >= 0:
                usage.reserved -= reservation.delta
            usage.in_use += reservation.delta
        reservation_query.update({'deleted': True,
                                  'deleted_at': timeutils.utcnow(),
                                  'updated_at': literal_column('updated_at')},
                                 synchronize_session=False)


@require_context
def reservation_rollback(context, reservations, project_id=None, user_id=None):
    session = get_session()
    with session.begin():
        usages = _get_user_quota_usages(context, session, project_id, user_id)
        reservation_query = _quota_reservations_query(session, context,
                                                      reservations)
        for reservation in reservation_query.all():
            usage = usages[reservation.resource]
            if reservation.delta >= 0:
                usage.reserved -= reservation.delta
        reservation_query.update({'deleted': True,
                                  'deleted_at': timeutils.utcnow(),
                                  'updated_at': literal_column('updated_at')},
                                 synchronize_session=False)


@require_admin_context
def quota_destroy_all_by_project_and_user(context, project_id, user_id):
    session = get_session()
    with session.begin():
        model_query(context, models.ProjectUserQuota, session=session,
                    read_deleted="no").\
            filter_by(project_id=project_id).\
            filter_by(user_id=user_id).\
            update({'deleted': True,
                    'deleted_at': timeutils.utcnow(),
                    'updated_at': literal_column('updated_at')},
                   synchronize_session=False)

        model_query(context, models.QuotaUsage,
                    session=session, read_deleted="no").\
            filter_by(project_id=project_id).\
            filter_by(user_id=user_id).\
            update({'deleted': True,
                    'deleted_at': timeutils.utcnow(),
                    'updated_at': literal_column('updated_at')},
                   synchronize_session=False)

        model_query(context, models.Reservation,
                    session=session, read_deleted="no").\
            filter_by(project_id=project_id).\
            filter_by(user_id=user_id).\
            update({'deleted': True,
                    'deleted_at': timeutils.utcnow(),
                    'updated_at': literal_column('updated_at')},
                   synchronize_session=False)


@require_admin_context
def quota_destroy_all_by_project(context, project_id):
    session = get_session()
    with session.begin():
        model_query(context, models.Quota, session=session,
                    read_deleted="no").\
            filter_by(project_id=project_id).\
            update({'deleted': True,
                    'deleted_at': timeutils.utcnow(),
                    'updated_at': literal_column('updated_at')},
                   synchronize_session=False)

        model_query(context, models.ProjectUserQuota, session=session,
                    read_deleted="no").\
            filter_by(project_id=project_id).\
            update({'deleted': True,
                    'deleted_at': timeutils.utcnow(),
                    'updated_at': literal_column('updated_at')},
                   synchronize_session=False)

        model_query(context, models.QuotaUsage,
                    session=session, read_deleted="no").\
            filter_by(project_id=project_id).\
            update({'deleted': True,
                    'deleted_at': timeutils.utcnow(),
                    'updated_at': literal_column('updated_at')},
                   synchronize_session=False)

        model_query(context, models.Reservation,
                    session=session, read_deleted="no").\
            filter_by(project_id=project_id).\
            update({'deleted': True,
                    'deleted_at': timeutils.utcnow(),
                    'updated_at': literal_column('updated_at')},
                   synchronize_session=False)


@require_admin_context
def reservation_expire(context):
    session = get_session()
    with session.begin():
        current_time = timeutils.utcnow()
        reservation_query = model_query(context, models.Reservation,
                                        session=session, read_deleted="no").\
            filter(models.Reservation.expire < current_time)

        for reservation in reservation_query.join(models.QuotaUsage).all():
            if reservation.delta >= 0:
                reservation.usage.reserved -= reservation.delta
                session.add(reservation.usage)

        reservation_query.update({'deleted': True,
                                  'deleted_at': timeutils.utcnow(),
                                  'updated_at': literal_column('updated_at')},
                                 synchronize_session=False)


################


def _share_get_query(context, session=None):
    if session is None:
        session = get_session()
    return model_query(context, models.Share, session=session).\
        options(joinedload('share_metadata')).\
        options(joinedload('share_type'))


def _metadata_refs(metadata_dict, meta_class):
    metadata_refs = []
    if metadata_dict:
        for k, v in six.iteritems(metadata_dict):
            value = six.text_type(v) if isinstance(v, bool) else v

            metadata_ref = meta_class()
            metadata_ref['key'] = k
            metadata_ref['value'] = value
            metadata_refs.append(metadata_ref)
    return metadata_refs


@require_context
def share_create(context, values):
    values['share_metadata'] = _metadata_refs(values.get('metadata'),
                                              models.ShareMetadata)
    share_ref = models.Share()
    if not values.get('id'):
        values['id'] = str(uuid.uuid4())
    share_ref.update(values)
    session = get_session()
    with session.begin():
        share_ref.save(session=session)

    return share_ref


@require_admin_context
def share_data_get_for_project(context, project_id, user_id, session=None):
    query = model_query(context, models.Share,
                        func.count(models.Share.id),
                        func.sum(models.Share.size),
                        read_deleted="no",
                        session=session).\
        filter_by(project_id=project_id)
    if user_id:
        result = query.filter_by(user_id=user_id).first()
    else:
        result = query.first()

    return (result[1] or 0, result[2] or 0)


@require_context
def share_update(context, share_id, values):
    session = get_session()
    with session.begin():
        share_ref = share_get(context, share_id, session=session)
        share_ref.update(values)
        share_ref.save(session=session)
        return share_ref


@require_context
def share_get(context, share_id, session=None):
    result = _share_get_query(context, session).filter_by(id=share_id).first()
    if result is None:
        raise exception.NotFound()
    return result


@require_context
def _share_get_all_with_filters(context, project_id=None, share_server_id=None,
                                share_network_id=None, host=None, filters=None,
                                sort_key=None, sort_dir=None):
    """Returns sorted list of shares that satisfies filters.

    :param context: context to query under
    :param project_id: project id that owns shares
    :param share_server_id: share server that hosts shares
    :param share_network_id: share network that was used for shares
    :param host: host name where shares [and share servers] are located
    :param filters: dict of filters to specify share selection
    :param sort_key: key of models.Share to be used for sorting
    :param sort_dir: desired direction of sorting, can be 'asc' and 'desc'
    :returns: list -- models.Share
    :raises: exception.InvalidInput
    """
    if not sort_key:
        sort_key = 'created_at'
    if not sort_dir:
        sort_dir = 'desc'
    query = _share_get_query(context)
    if project_id:
        query = query.filter_by(project_id=project_id)
    if share_server_id:
        query = query.filter_by(share_server_id=share_server_id)
    if share_network_id:
        query = query.filter_by(share_network_id=share_network_id)
    if host and isinstance(host, six.string_types):
        session = get_session()
        with session.begin():
            host_attr = getattr(models.Share, 'host')
            conditions = [host_attr == host,
                          host_attr.op('LIKE')(host + '#%')]
            query = query.filter(or_(*conditions))

    # Apply filters
    if not filters:
        filters = {}
    if 'metadata' in filters:
        for k, v in filters['metadata'].items():
            query = query.filter(
                or_(models.Share.share_metadata.any(  # pylint: disable=E1101
                    key=k, value=v)))
    if 'extra_specs' in filters:
        query = query.join(
            models.ShareTypeExtraSpecs,
            models.ShareTypeExtraSpecs.share_type_id ==
            models.Share.share_type_id)
        for k, v in filters['extra_specs'].items():
            query = query.filter(or_(models.ShareTypeExtraSpecs.key == k,
                                     models.ShareTypeExtraSpecs.value == v))

    # Apply sorting
    try:
        attr = getattr(models.Share, sort_key)
    except AttributeError:
        msg = _("Wrong sorting key provided - '%s'.") % sort_key
        raise exception.InvalidInput(reason=msg)
    if sort_dir.lower() == 'desc':
        query = query.order_by(attr.desc())
    elif sort_dir.lower() == 'asc':
        query = query.order_by(attr.asc())
    else:
        msg = _("Wrong sorting data provided: sort key is '%(sort_key)s' "
                "and sort direction is '%(sort_dir)s'.") % {
                    "sort_key": sort_key, "sort_dir": sort_dir}
        raise exception.InvalidInput(reason=msg)

    # Returns list of shares that satisfy filters.
    query = query.all()
    return query


@require_admin_context
def share_get_all(context, filters=None, sort_key=None, sort_dir=None):
    query = _share_get_all_with_filters(
        context, filters=filters, sort_key=sort_key, sort_dir=sort_dir)
    return query


@require_admin_context
def share_get_all_by_host(context, host, filters=None,
                          sort_key=None, sort_dir=None):
    """Retrieves all shares hosted on a host."""
    query = _share_get_all_with_filters(
        context, host=host, filters=filters,
        sort_key=sort_key, sort_dir=sort_dir,
    )
    return query


@require_context
def share_get_all_by_project(context, project_id, filters=None,
                             sort_key=None, sort_dir=None):
    """Returns list of shares with given project ID."""
    query = _share_get_all_with_filters(
        context, project_id=project_id, filters=filters,
        sort_key=sort_key, sort_dir=sort_dir,
    )
    return query


@require_context
def share_get_all_by_share_network(context, share_network_id, filters=None,
                                   sort_key=None, sort_dir=None):
    """Returns list of shares that belong to given share network."""
    query = _share_get_all_with_filters(
        context, share_network_id=share_network_id, filters=filters,
        sort_key=sort_key, sort_dir=sort_dir)
    return query


@require_context
def share_get_all_by_share_server(context, share_server_id, filters=None,
                                  sort_key=None, sort_dir=None):
    """Returns list of shares with given share server."""
    query = _share_get_all_with_filters(
        context, share_server_id=share_server_id, filters=filters,
        sort_key=sort_key, sort_dir=sort_dir,
    )
    return query


@require_context
def share_delete(context, share_id):
    session = get_session()
    share_ref = share_get(context, share_id, session)
    share_ref.update({'deleted': True,
                      'deleted_at': timeutils.utcnow(),
                      'updated_at': literal_column('updated_at'),
                      'status': 'deleted'})
    session.query(models.ShareMetadata).\
        filter_by(share_id=share_id).\
        update({'deleted': True,
                'deleted_at': timeutils.utcnow(),
                'updated_at': literal_column('updated_at')})

    share_ref.save(session)


###################


def _share_access_get_query(context, session, values):
    """Get access record."""
    query = model_query(context, models.ShareAccessMapping, session=session)
    return query.filter_by(**values)


@require_context
def share_access_create(context, values):
    session = get_session()
    with session.begin():
        access_ref = models.ShareAccessMapping()
        if not values.get('id'):
            values['id'] = str(uuid.uuid4())
        access_ref.update(values)
        access_ref.save(session=session)
        return access_ref


@require_context
def share_access_get(context, access_id):
    """Get access record."""
    session = get_session()
    access = _share_access_get_query(context, session,
                                     {'id': access_id}).first()
    if access:
        return access
    else:
        raise exception.NotFound()


@require_context
def share_access_get_all_for_share(context, share_id):
    session = get_session()
    return _share_access_get_query(context, session,
                                   {'share_id': share_id}).all()


@require_context
def share_access_get_all_by_type_and_access(context, share_id, access_type,
                                            access):
    session = get_session()
    return _share_access_get_query(context, session,
                                   {'share_id': share_id,
                                    'access_type': access_type,
                                    'access_to': access}).all()


@require_context
def share_access_delete(context, access_id):
    session = get_session()
    with session.begin():
        session.query(models.ShareAccessMapping).\
            filter_by(id=access_id).\
            update({'deleted': True,
                    'deleted_at': timeutils.utcnow(),
                    'updated_at': literal_column('updated_at'),
                    'state': models.ShareAccessMapping.STATE_DELETED})


@require_context
def share_access_update(context, access_id, values):
    session = get_session()
    with session.begin():
        access = _share_access_get_query(context, session, {'id': access_id})
        access = access.one()
        access.update(values)
        access.save(session=session)
        return access


###################


@require_context
def share_snapshot_create(context, values):
    snapshot_ref = models.ShareSnapshot()
    if not values.get('id'):
        values['id'] = str(uuid.uuid4())
    snapshot_ref.update(values)

    session = get_session()
    with session.begin():
        snapshot_ref.save(session=session)

    return share_snapshot_get(context, values['id'], session=session)


@require_admin_context
def snapshot_data_get_for_project(context, project_id, user_id, session=None):
    query = model_query(context, models.ShareSnapshot,
                        func.count(models.ShareSnapshot.id),
                        func.sum(models.ShareSnapshot.size),
                        read_deleted="no",
                        session=session).\
        filter_by(project_id=project_id).\
        options(joinedload('share'))

    if user_id:
        result = query.filter_by(user_id=user_id).first()
    else:
        result = query.first()

    return (result[1] or 0, result[2] or 0)


@require_context
def share_snapshot_destroy(context, snapshot_id):
    session = get_session()
    with session.begin():
        session.query(models.ShareSnapshot).\
            filter_by(id=snapshot_id).\
            update({'status': 'deleted',
                    'deleted': True,
                    'deleted_at': timeutils.utcnow(),
                    'updated_at': literal_column('updated_at')})


@require_context
def share_snapshot_get(context, snapshot_id, session=None):
    result = model_query(context, models.ShareSnapshot, session=session,
                         project_only=True).\
        filter_by(id=snapshot_id).\
        options(joinedload('share')).\
        first()

    if not result:
        raise exception.ShareSnapshotNotFound(snapshot_id=snapshot_id)

    return result


def _share_snapshot_get_all_with_filters(context, project_id=None,
                                         share_id=None, filters=None,
                                         sort_key=None, sort_dir=None):
    # Init data
    sort_key = sort_key or 'share_id'
    sort_dir = sort_dir or 'desc'
    filters = filters or {}
    query = model_query(context, models.ShareSnapshot)

    if project_id:
        query = query.filter_by(project_id=project_id)
    if share_id:
        query = query.filter_by(share_id=share_id)
    query = query.options(joinedload('share'))

    # Apply filters
    if 'usage' in filters:
        usage_filter_keys = ['any', 'used', 'unused']
        if filters['usage'] == 'any':
            pass
        elif filters['usage'] == 'used':
            query = query.filter(or_(models.Share.snapshot_id == (
                models.ShareSnapshot.id)))
        elif filters['usage'] == 'unused':
            query = query.filter(or_(models.Share.snapshot_id != (
                models.ShareSnapshot.id)))
        else:
            msg = _("Wrong 'usage' key provided - '%(key)s'. "
                    "Expected keys are '%(ek)s'.") % {
                        'key': filters['usage'],
                        'ek': six.text_type(usage_filter_keys)}
            raise exception.InvalidInput(reason=msg)

    # Apply sorting
    try:
        attr = getattr(models.ShareSnapshot, sort_key)
    except AttributeError:
        msg = _("Wrong sorting key provided - '%s'.") % sort_key
        raise exception.InvalidInput(reason=msg)
    if sort_dir.lower() == 'desc':
        query = query.order_by(attr.desc())
    elif sort_dir.lower() == 'asc':
        query = query.order_by(attr.asc())
    else:
        msg = _("Wrong sorting data provided: sort key is '%(sort_key)s' "
                "and sort direction is '%(sort_dir)s'.") % {
                    "sort_key": sort_key, "sort_dir": sort_dir}
        raise exception.InvalidInput(reason=msg)

    # Returns list of shares that satisfy filters
    return query.all()


@require_admin_context
def share_snapshot_get_all(context, filters=None, sort_key=None,
                           sort_dir=None):
    return _share_snapshot_get_all_with_filters(
        context, filters=filters, sort_key=sort_key, sort_dir=sort_dir,
    )


@require_context
def share_snapshot_get_all_by_project(context, project_id, filters=None,
                                      sort_key=None, sort_dir=None):
    authorize_project_context(context, project_id)
    return _share_snapshot_get_all_with_filters(
        context, project_id=project_id,
        filters=filters, sort_key=sort_key, sort_dir=sort_dir,
    )


@require_context
def share_snapshot_get_all_for_share(context, share_id, filters=None,
                                     sort_key=None, sort_dir=None):
    return _share_snapshot_get_all_with_filters(
        context, share_id=share_id,
        filters=filters, sort_key=sort_key, sort_dir=sort_dir,
    )


@require_context
def share_snapshot_data_get_for_project(context, project_id, session=None):
    authorize_project_context(context, project_id)
    result = model_query(context, models.ShareSnapshot,
                         func.count(models.ShareSnapshot.id),
                         func.sum(models.ShareSnapshot.share_size),
                         read_deleted="no",
                         session=session).\
        filter_by(project_id=project_id).\
        options(joinedload('share')).\
        first()

    # NOTE(vish): convert None to 0
    return (result[0] or 0, result[1] or 0)


@require_context
def share_snapshot_update(context, snapshot_id, values):
    session = get_session()
    with session.begin():
        snapshot_ref = share_snapshot_get(context, snapshot_id,
                                          session=session)
        snapshot_ref.update(values)
        snapshot_ref.save(session=session)
        return snapshot_ref


#################################


@require_context
@require_share_exists
def share_metadata_get(context, share_id):
    return _share_metadata_get(context, share_id)


@require_context
@require_share_exists
def share_metadata_delete(context, share_id, key):
    _share_metadata_get_query(context, share_id).\
        filter_by(key=key).\
        update({'deleted': True,
                'deleted_at': timeutils.utcnow(),
                'updated_at': literal_column('updated_at')})


@require_context
@require_share_exists
def share_metadata_update(context, share_id, metadata, delete):
    return _share_metadata_update(context, share_id, metadata, delete)


def _share_metadata_get_query(context, share_id, session=None):
    return model_query(context, models.ShareMetadata, session=session,
                       read_deleted="no").\
        filter_by(share_id=share_id).\
        options(joinedload('share'))


@require_context
@require_share_exists
def _share_metadata_get(context, share_id, session=None):
    rows = _share_metadata_get_query(context, share_id,
                                     session=session).all()
    result = {}
    for row in rows:
        result[row['key']] = row['value']

    return result


@require_context
@require_share_exists
def _share_metadata_update(context, share_id, metadata, delete, session=None):
    if not session:
        session = get_session()

    with session.begin():
        # Set existing metadata to deleted if delete argument is True
        if delete:
            original_metadata = _share_metadata_get(context, share_id,
                                                    session=session)
            for meta_key, meta_value in six.iteritems(original_metadata):
                if meta_key not in metadata:
                    meta_ref = _share_metadata_get_item(context, share_id,
                                                        meta_key,
                                                        session=session)
                    meta_ref.update({'deleted': True})
                    meta_ref.save(session=session)

        meta_ref = None

        # Now update all existing items with new values, or create new meta
        # objects
        for meta_key, meta_value in metadata.items():

            # update the value whether it exists or not
            item = {"value": meta_value}

            try:
                meta_ref = _share_metadata_get_item(context, share_id,
                                                    meta_key,
                                                    session=session)
            except exception.ShareMetadataNotFound:
                meta_ref = models.ShareMetadata()
                item.update({"key": meta_key, "share_id": share_id})

            meta_ref.update(item)
            meta_ref.save(session=session)

        return metadata


def _share_metadata_get_item(context, share_id, key, session=None):
    result = _share_metadata_get_query(context, share_id, session=session).\
        filter_by(key=key).\
        first()

    if not result:
        raise exception.ShareMetadataNotFound(metadata_key=key,
                                              share_id=share_id)
    return result


@require_context
def security_service_create(context, values):
    if not values.get('id'):
        values['id'] = str(uuid.uuid4())

    security_service_ref = models.SecurityService()
    security_service_ref.update(values)
    session = get_session()

    with session.begin():
        security_service_ref.save(session=session)

    return security_service_ref


@require_context
def security_service_delete(context, id):
    session = get_session()
    with session.begin():
        security_service_ref = security_service_get(context,
                                                    id,
                                                    session=session)
        security_service_ref.delete(session=session)


@require_context
def security_service_update(context, id, values):
    session = get_session()
    with session.begin():
        security_service_ref = security_service_get(context,
                                                    id,
                                                    session=session)
        security_service_ref.update(values)
        security_service_ref.save(session=session)
        return security_service_ref


@require_context
def security_service_get(context, id, session=None):
    result = _security_service_get_query(context, session=session).\
        filter_by(id=id).first()

    if result is None:
        raise exception.SecurityServiceNotFound(security_service_id=id)
    return result


@require_context
def security_service_get_all(context):
    return _security_service_get_query(context).all()


@require_context
def security_service_get_all_by_project(context, project_id):
    return _security_service_get_query(context).\
        filter_by(project_id=project_id).all()


def _security_service_get_query(context, session=None):
    if session is None:
        session = get_session()
    return model_query(context, models.SecurityService, session=session)


###################


def _network_get_query(context, session=None):
    if session is None:
        session = get_session()
    return model_query(context, models.ShareNetwork, session=session).\
        options(joinedload('shares'),
                joinedload('security_services'),
                joinedload('share_servers'))


@require_context
def share_network_create(context, values):
    if not values.get('id'):
        values['id'] = str(uuid.uuid4())

    network_ref = models.ShareNetwork()
    network_ref.update(values)
    session = get_session()
    with session.begin():
        network_ref.save(session=session)
    return share_network_get(context, values['id'], session)


@require_context
def share_network_delete(context, id):
    session = get_session()
    with session.begin():
        network_ref = share_network_get(context, id, session=session)
        network_ref.delete(session=session)


@require_context
def share_network_update(context, id, values):
    session = get_session()
    with session.begin():
        network_ref = share_network_get(context, id, session=session)
        network_ref.update(values)
        network_ref.save(session=session)
        return network_ref


@require_context
def share_network_get(context, id, session=None):
    result = _network_get_query(context, session).filter_by(id=id).first()
    if result is None:
        raise exception.ShareNetworkNotFound(share_network_id=id)
    return result


@require_context
def share_network_get_all(context):
    return _network_get_query(context).all()


@require_context
def share_network_get_all_by_project(context, project_id, user_id=None,
                                     session=None):
    query = _network_get_query(context, session)
    query = query.filter_by(project_id=project_id)
    if user_id is not None:
        query = query.filter_by(user_id=user_id)
    return query.all()


@require_context
def share_network_get_all_by_security_service(context, security_service_id):
    session = get_session()
    return model_query(context, models.ShareNetwork, session=session).\
        join(models.ShareNetworkSecurityServiceAssociation,
             models.ShareNetwork.id ==
             models.ShareNetworkSecurityServiceAssociation.share_network_id).\
        filter_by(security_service_id=security_service_id, deleted=False).\
        options(joinedload('share_servers')).all()


@require_context
def share_network_add_security_service(context, id, security_service_id):
    session = get_session()

    with session.begin():
        assoc_ref = model_query(
            context,
            models.ShareNetworkSecurityServiceAssociation,
            session=session).\
            filter_by(share_network_id=id).\
            filter_by(security_service_id=security_service_id).first()

        if assoc_ref:
            msg = "Already associated"
            raise exception.ShareNetworkSecurityServiceAssociationError(
                share_network_id=id,
                security_service_id=security_service_id,
                reason=msg)

        share_nw_ref = share_network_get(context, id, session=session)
        security_service_ref = security_service_get(context,
                                                    security_service_id,
                                                    session=session)
        share_nw_ref.security_services += [security_service_ref]
        share_nw_ref.save(session=session)

    return share_nw_ref


@require_context
def share_network_remove_security_service(context, id, security_service_id):
    session = get_session()

    with session.begin():
        share_nw_ref = share_network_get(context, id, session=session)
        security_service_get(context, security_service_id, session=session)

        assoc_ref = model_query(
            context,
            models.ShareNetworkSecurityServiceAssociation,
            session=session).\
            filter_by(share_network_id=id).\
            filter_by(security_service_id=security_service_id).first()

        if assoc_ref:
            assoc_ref.delete(session=session)
        else:
            msg = "No association defined"
            raise exception.ShareNetworkSecurityServiceDissociationError(
                share_network_id=id,
                security_service_id=security_service_id,
                reason=msg)

    return share_nw_ref


###################


def _server_get_query(context, session=None):
    if session is None:
        session = get_session()
    return model_query(context, models.ShareServer, session=session).\
        options(joinedload('shares'), joinedload('network_allocations'),
                joinedload('share_network'))


@require_context
def share_server_create(context, values):
    if not values.get('id'):
        values['id'] = str(uuid.uuid4())
    server_ref = models.ShareServer()
    server_ref.update(values)
    session = get_session()
    with session.begin():
        server_ref.save(session=session)
    return server_ref


@require_context
def share_server_delete(context, id):
    session = get_session()
    with session.begin():
        server_ref = share_server_get(context, id, session=session)
        share_server_backend_details_delete(context, id, session=session)
        server_ref.update({'deleted': server_ref.id,
                           'deleted_at': timeutils.utcnow(),
                           'updated_at': literal_column('updated_at'),
                           'status': constants.STATUS_DELETED})


@require_context
def share_server_update(context, id, values):
    session = get_session()
    with session.begin():
        server_ref = share_server_get(context, id, session=session)
        server_ref.update(values)
        server_ref.save(session=session)
        return server_ref


@require_context
def share_server_get(context, server_id, session=None):
    result = _server_get_query(context, session).filter_by(id=server_id)\
        .first()
    if result is None:
        raise exception.ShareServerNotFound(share_server_id=server_id)
    result['backend_details'] = share_server_backend_details_get(
        context, server_id, session=session)
    return result


@require_context
def share_server_get_by_host_and_share_net_valid(context, host, share_net_id,
                                                 session=None):
    result = _server_get_query(context, session).filter_by(host=host)\
        .filter_by(share_network_id=share_net_id)\
        .filter(models.ShareServer.status.in_(
            (constants.STATUS_CREATING, constants.STATUS_ACTIVE))).first()
    if result is None:
        filters_description = ('share_network_id is "%(share_net_id)s",'
                               ' host is "%(host)s" and status in'
                               ' "%(status_cr)s" or "%(status_act)s"') % {
            'share_net_id': share_net_id,
            'host': host,
            'status_cr': constants.STATUS_CREATING,
            'status_act': constants.STATUS_ACTIVE,
        }
        raise exception.ShareServerNotFoundByFilters(
            filters_description=filters_description)
    result['backend_details'] = share_server_backend_details_get(
        context, result['id'], session=session)
    return result


@require_context
def share_server_get_all(context):
    return _server_get_query(context).all()


@require_context
def share_server_backend_details_set(context, share_server_id, server_details):
    share_server_get(context, share_server_id)

    for meta_key, meta_value in server_details.items():
        meta_ref = models.ShareServerBackendDetails()
        meta_ref.update({
            'key': meta_key,
            'value': meta_value,
            'share_server_id': share_server_id
        })
        session = get_session()
        with session.begin():
            meta_ref.save(session)
    return server_details


@require_context
def share_server_backend_details_delete(context, share_server_id,
                                        session=None):
    if not session:
        session = get_session()
    share_server_details = model_query(context,
                                       models.ShareServerBackendDetails,
                                       session=session)\
        .filter_by(share_server_id=share_server_id).all()
    for item in share_server_details:
        item.delete(session=session)


@require_context
def share_server_backend_details_get(context, share_server_id,
                                     session=None):
    if not session:
        session = get_session()
    query = model_query(context, models.ShareServerBackendDetails,
                        session=session)\
        .filter_by(share_server_id=share_server_id).all()
    return dict([(item.key, item.value) for item in query])


###################


@require_context
def network_allocation_create(context, values):
    values['id'] = values.get('id', six.text_type(uuid.uuid4()))
    alloc_ref = models.NetworkAllocation()
    alloc_ref.update(values)
    session = get_session()
    with session.begin():
        alloc_ref.save(session=session)
    return alloc_ref


@require_context
def network_allocation_delete(context, id):
    session = get_session()
    with session.begin():
        alloc_ref = network_allocation_get(context, id, session=session)
        alloc_ref.delete(session=session)


@require_context
def network_allocation_get(context, id, session=None):
    if session is None:
        session = get_session()
    result = model_query(context, models.NetworkAllocation, session=session).\
        filter_by(id=id).first()
    if result is None:
        raise exception.NotFound()
    return result


@require_context
def network_allocations_get_by_ip_address(context, ip_address):
    session = get_session()
    result = model_query(context, models.NetworkAllocation, session=session).\
        filter_by(ip_address=ip_address).all()
    return result or []


@require_context
def network_allocations_get_for_share_server(context, share_server_id,
                                             session=None):
    if session is None:
        session = get_session()
    result = model_query(context, models.NetworkAllocation, session=session).\
        filter_by(share_server_id=share_server_id).all()
    return result


@require_context
def network_allocation_update(context, id, values):
    session = get_session()
    with session.begin():
        alloc_ref = network_allocation_get(context, id, session=session)
        alloc_ref.update(values)
        alloc_ref.save(session=session)
        return alloc_ref


###################


def _dict_with_extra_specs(inst_type_query):
    """Convert type query result to dict with extra_spec and rate_limit.

Takes a volume type query returned by sqlalchemy and returns it
as a dictionary, converting the extra_specs entry from a list
of dicts:

'extra_specs' : [{'key': 'k1', 'value': 'v1', ...}, ...]
to a single dict:
'extra_specs' : {'k1': 'v1'}
"""
    inst_type_dict = dict(inst_type_query)
    extra_specs = dict([(x['key'], x['value'])
                        for x in inst_type_query['extra_specs']])
    inst_type_dict['extra_specs'] = extra_specs
    return inst_type_dict


@require_admin_context
def share_type_create(context, values):
    """Create a new instance type.

    In order to pass in extra specs, the values dict should contain a
    'extra_specs' key/value pair:
    {'extra_specs' : {'k1': 'v1', 'k2': 'v2', ...}}
    """
    if not values.get('id'):
        values['id'] = str(uuid.uuid4())

    session = get_session()
    with session.begin():
        try:
            values['extra_specs'] = _metadata_refs(values.get('extra_specs'),
                                                   models.ShareTypeExtraSpecs)
            share_type_ref = models.ShareTypes()
            share_type_ref.update(values)
            share_type_ref.save(session=session)
        except db_exception.DBDuplicateEntry:
            raise exception.ShareTypeExists(id=values['name'])
        except Exception as e:
            raise db_exception.DBError(e)
        return share_type_ref


@require_context
def share_type_get_all(context, inactive=False, filters=None):
    """Returns a dict describing all share_types with name as key."""
    filters = filters or {}

    read_deleted = "yes" if inactive else "no"
    rows = model_query(context, models.ShareTypes,
                       read_deleted=read_deleted).\
        options(joinedload('extra_specs')).\
        options(joinedload('shares')).\
        order_by("name").\
        all()

    result = {}
    for row in rows:
        result[row['name']] = _dict_with_extra_specs(row)

    return result


@require_context
def _share_type_get(context, id, session=None, inactive=False):
    read_deleted = "yes" if inactive else "no"
    result = model_query(context,
                         models.ShareTypes,
                         session=session,
                         read_deleted=read_deleted).\
        options(joinedload('extra_specs')).\
        filter_by(id=id).\
        options(joinedload('shares')).\
        first()

    if not result:
        raise exception.ShareTypeNotFound(share_type_id=id)

    return _dict_with_extra_specs(result)


@require_context
def share_type_get(context, id, inactive=False):
    """Return a dict describing specific share_type."""
    return _share_type_get(context, id, None, inactive)


@require_context
def _share_type_get_by_name(context, name, session=None):
    result = model_query(context, models.ShareTypes, session=session).\
        options(joinedload('extra_specs')).\
        filter_by(name=name).\
        options(joinedload('shares')).\
        first()

    if not result:
        raise exception.ShareTypeNotFoundByName(share_type_name=name)
    else:
        return _dict_with_extra_specs(result)


@require_context
def share_type_get_by_name(context, name):
    """Return a dict describing specific share_type."""

    return _share_type_get_by_name(context, name)


@require_admin_context
def share_type_destroy(context, id):
    session = get_session()
    with session.begin():
        _share_type_get(context, id, session)
        results = model_query(context, models.Share, session=session). \
            filter_by(share_type_id=id).all()
        if results:
            LOG.error(_LE('ShareType %s deletion failed, ShareType in use.'),
                      id)
            raise exception.ShareTypeInUse(share_type_id=id)
        model_query(context, models.ShareTypeExtraSpecs, session=session).\
            filter_by(share_type_id=id).update(
                {'deleted': True,
                 'deleted_at': timeutils.utcnow(),
                 'updated_at': literal_column('updated_at')})
        model_query(context, models.ShareTypes, session=session).\
            filter_by(id=id).update(
                {'deleted': id,
                 'deleted_at': timeutils.utcnow(),
                 'updated_at': literal_column('updated_at')})


@require_context
def volume_get_active_by_window(context,
                                begin,
                                end=None,
                                project_id=None):
    """Return volumes that were active during window."""
    query = model_query(context, models.Share, read_deleted="yes")
    query = query.filter(or_(models.Share.deleted_at is None,
                             models.Share.deleted_at > begin))
    if end:
        query = query.filter(models.Share.created_at < end)
    if project_id:
        query = query.filter_by(project_id=project_id)

    return query.all()

####################


def _share_type_extra_specs_query(context, share_type_id, session=None):
    return model_query(context, models.ShareTypeExtraSpecs, session=session,
                       read_deleted="no").\
        filter_by(share_type_id=share_type_id).\
        options(joinedload('share_type'))


@require_context
def share_type_extra_specs_get(context, share_type_id):
    rows = _share_type_extra_specs_query(context, share_type_id).\
        all()

    result = {}
    for row in rows:
        result[row['key']] = row['value']

    return result


@require_context
def share_type_extra_specs_delete(context, share_type_id, key):
    session = get_session()
    with session.begin():
        _share_type_extra_specs_get_item(context, share_type_id, key, session)
        _share_type_extra_specs_query(context, share_type_id, session).\
            filter_by(key=key).\
            update({'deleted': True,
                    'deleted_at': timeutils.utcnow(),
                    'updated_at': literal_column('updated_at')})


@require_context
def _share_type_extra_specs_get_item(context, share_type_id, key,
                                     session=None):
    result = _share_type_extra_specs_query(
        context, share_type_id, session=session
    ).filter_by(key=key).options(joinedload('share_type')).first()

    if not result:
        raise exception.ShareTypeExtraSpecsNotFound(
            extra_specs_key=key,
            share_type_id=share_type_id)

    return result


@require_context
def share_type_extra_specs_update_or_create(context, share_type_id, specs):
    session = get_session()
    with session.begin():
        spec_ref = None
        for key, value in six.iteritems(specs):
            try:
                spec_ref = _share_type_extra_specs_get_item(
                    context, share_type_id, key, session)
            except exception.ShareTypeExtraSpecsNotFound:
                spec_ref = models.ShareTypeExtraSpecs()
            spec_ref.update({"key": key, "value": value,
                             "share_type_id": share_type_id,
                             "deleted": False})
            spec_ref.save(session=session)

        return specs
