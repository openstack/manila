# Copyright (c) 2014 OpenStack Foundation.
# Copyright (c) 2015 Tom Barron.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Built-in share type properties."""

import re

from oslo_config import cfg
from oslo_db import exception as db_exception
from oslo_log import log
from oslo_utils import strutils
from oslo_utils import uuidutils

from manila.api import common
from manila.common import constants
from manila import context
from manila import db
from manila import exception
from manila.i18n import _
from manila import quota

CONF = cfg.CONF
LOG = log.getLogger(__name__)
QUOTAS = quota.QUOTAS

MIN_SIZE_KEY = "provisioning:min_share_size"
MAX_SIZE_KEY = "provisioning:max_share_size"
MAX_EXTEND_SIZE_KEY = "provisioning:max_share_extend_size"


def create(context, name, extra_specs=None, is_public=True,
           projects=None, description=None):
    """Creates share types."""
    extra_specs = extra_specs or {}
    projects = projects or []

    try:
        get_valid_required_extra_specs(extra_specs)
        get_valid_optional_extra_specs(extra_specs)
    except exception.InvalidExtraSpec as e:
        raise exception.InvalidShareType(reason=e.message)

    extra_specs = sanitize_extra_specs(extra_specs)

    try:
        type_ref = db.share_type_create(context,
                                        dict(name=name,
                                             description=description,
                                             extra_specs=extra_specs,
                                             is_public=is_public),
                                        projects=projects)
    except db_exception.DBError:
        LOG.exception('DB error.')
        raise exception.ShareTypeCreateFailed(name=name,
                                              extra_specs=extra_specs)
    return type_ref


def sanitize_extra_specs(extra_specs):
    """Post process extra specs here if necessary"""
    az_spec = constants.ExtraSpecs.AVAILABILITY_ZONES
    if az_spec in extra_specs:
        extra_specs[az_spec] = sanitize_csv(extra_specs[az_spec])
    return extra_specs


def update(context, id, name, description, is_public=None):
    """Update share type by id."""
    values = {}
    if name:
        values.update({'name': name})
    if description == "":
        values.update({'description': None})
    elif description:
        values.update({'description': description})
    if is_public is not None:
        values.update({'is_public': is_public})
    try:
        db.share_type_update(context, id, values)
    except db_exception.DBError:
        LOG.exception('DB error.')
        raise exception.ShareTypeUpdateFailed(id=id)


def destroy(context, id):
    """Marks share types as deleted."""
    if id is None:
        msg = _("id cannot be None")
        raise exception.InvalidShareType(reason=msg)
    else:
        db.share_type_destroy(context, id)


def get_all_types(context, inactive=0, search_opts=None):
    """Get all non-deleted share_types.

    """
    search_opts = search_opts or {}
    filters = {}

    if 'is_public' in search_opts:
        filters['is_public'] = search_opts.pop('is_public')

    share_types = db.share_type_get_all(context, inactive, filters=filters)

    for type_name, type_args in share_types.items():
        required_extra_specs = {}
        try:
            required_extra_specs = get_valid_required_extra_specs(
                type_args['extra_specs'])
        except exception.InvalidExtraSpec:
            LOG.exception('Share type %(share_type)s has invalid required'
                          ' extra specs.', {'share_type': type_name})

        type_args['required_extra_specs'] = required_extra_specs

    search_vars = {}
    availability_zones = search_opts.get('extra_specs', {}).pop(
        'availability_zones', None)
    extra_specs = search_opts.pop('extra_specs', {})

    if extra_specs:
        search_vars['extra_specs'] = extra_specs

    if availability_zones:
        search_vars['availability_zones'] = availability_zones.split(',')

    if search_opts:
        # No other search options are currently supported
        return {}
    elif not search_vars:
        return share_types

    LOG.debug("Searching by: %s", search_vars)

    def _check_extra_specs_match(share_type, searchdict):
        for k, v in searchdict.items():
            if (k not in share_type['extra_specs'].keys()
                    or share_type['extra_specs'][k] != v):
                return False
            return True

    def _check_availability_zones_match(share_type, availability_zones):
        type_azs = share_type['extra_specs'].get('availability_zones')
        if type_azs:
            type_azs = type_azs.split(',')
            return set(availability_zones).issubset(set(type_azs))
        return True

    # search_option to filter_name mapping.
    filter_mapping = {
        'extra_specs': _check_extra_specs_match,
        'availability_zones': _check_availability_zones_match,
    }

    result = {}
    for type_name, type_args in share_types.items():
        # go over all filters in the list (*AND* operation)
        type_matches = True
        for opt, value in search_vars.items():
            try:
                filter_func = filter_mapping[opt]
            except KeyError:
                # no such filter - ignore it, go to next filter
                continue
            else:
                if not filter_func(type_args, value):
                    type_matches = False
                    break
        if type_matches:
            result[type_name] = type_args
    return result


def get_share_type(ctxt, id, expected_fields=None):
    """Retrieves single share type by id."""
    if id is None:
        msg = _("id cannot be None")
        raise exception.InvalidShareType(reason=msg)

    if ctxt is None:
        ctxt = context.get_admin_context()

    return db.share_type_get(ctxt, id, expected_fields=expected_fields)


def get_share_type_by_name(context, name):
    """Retrieves single share type by name."""
    if name is None:
        msg = _("name cannot be None")
        raise exception.InvalidShareType(reason=msg)

    return db.share_type_get_by_name(context, name)


def get_share_type_by_name_or_id(context, share_type=None):
    if not share_type:
        share_type_ref = get_default_share_type(context)
        if not share_type_ref:
            msg = _("Default share type not found.")
            raise exception.ShareTypeNotFound(message=msg)
        return share_type_ref

    if uuidutils.is_uuid_like(share_type):
        return get_share_type(context, share_type)
    else:
        return get_share_type_by_name(context, share_type)


def get_default_share_type(ctxt=None):
    """Get the default share type."""
    name = CONF.default_share_type

    if name is None:
        return {}

    if ctxt is None:
        ctxt = context.get_admin_context()

    share_type = {}
    try:
        share_type = get_share_type_by_name(ctxt, name)
        required_extra_specs = get_valid_required_extra_specs(
            share_type['extra_specs'])
        share_type['required_extra_specs'] = required_extra_specs
        return share_type
    except exception.ShareTypeNotFoundByName as e:
        # Couldn't find share type with the name in default_share_type
        # flag, record this issue and move on
        # TODO(zhiteng) consider add notification to warn admin
        LOG.exception('Default share type is not found, '
                      'please check default_share_type config: %s', e)
    except exception.InvalidExtraSpec as ex:
        LOG.exception('Default share type has invalid required extra'
                      ' specs: %s', ex)


def get_share_type_extra_specs(share_type_id, key=False):
    share_type = get_share_type(context.get_admin_context(),
                                share_type_id)
    extra_specs = share_type['extra_specs']
    if key:
        if extra_specs.get(key):
            return extra_specs.get(key)
        else:
            return False
    else:
        return extra_specs


def get_required_extra_specs():
    return constants.ExtraSpecs.REQUIRED


def get_optional_extra_specs():
    return constants.ExtraSpecs.OPTIONAL


def get_tenant_visible_extra_specs():
    return constants.ExtraSpecs.TENANT_VISIBLE


def get_boolean_extra_specs():
    return constants.ExtraSpecs.BOOLEAN


def is_valid_required_extra_spec(key, value):
    """Validates required extra_spec value.

    :param key: extra_spec name
    :param value: extra_spec value
    :return: None if provided extra_spec is not required
             True/False if extra_spec is required and valid or not.
    """
    if key not in get_required_extra_specs():
        return

    if key == constants.ExtraSpecs.DRIVER_HANDLES_SHARE_SERVERS:
        return strutils.bool_from_string(value, default=None) is not None

    return False


def get_valid_required_extra_specs(extra_specs):
    """Validates and returns required extra specs from dict.

    Raises InvalidExtraSpec if extra specs are not valid, or if any required
    extra specs are missing.
    """
    extra_specs = extra_specs or {}

    missed_extra_specs = set(get_required_extra_specs()) - set(extra_specs)

    if missed_extra_specs:
        specs = ",".join(missed_extra_specs)
        msg = _("Required extra specs '%s' not specified.") % specs
        raise exception.InvalidExtraSpec(reason=msg)

    required_extra_specs = {}

    for k in get_required_extra_specs():
        value = extra_specs.get(k, '')
        if not is_valid_required_extra_spec(k, value):
            msg = _("Value of required extra_spec %s is not valid") % k
            raise exception.InvalidExtraSpec(reason=msg)

        required_extra_specs[k] = value

    return required_extra_specs


def is_valid_csv(extra_spec_value):
    if not isinstance(extra_spec_value, str):
        extra_spec_value = str(extra_spec_value)
    values = extra_spec_value.split(',')
    return all([v.strip() for v in values])


def sanitize_csv(csv_string):
    return ','.join(value.strip() for value in csv_string.split(',')
                    if (csv_string and value))


def is_valid_optional_extra_spec(key, value):
    """Validates optional but standardized extra_spec value.

    :param key: extra_spec name
    :param value: extra_spec value
    :return: None if provided extra_spec is not required
             True/False if extra_spec is required and valid or not.
    """
    if key not in get_optional_extra_specs():
        return

    if key == constants.ExtraSpecs.SNAPSHOT_SUPPORT:
        return parse_boolean_extra_spec(key, value) is not None
    elif key == constants.ExtraSpecs.CREATE_SHARE_FROM_SNAPSHOT_SUPPORT:
        return parse_boolean_extra_spec(key, value) is not None
    elif key == constants.ExtraSpecs.REVERT_TO_SNAPSHOT_SUPPORT:
        return parse_boolean_extra_spec(key, value) is not None
    elif key == constants.ExtraSpecs.REPLICATION_TYPE_SPEC:
        return value in constants.ExtraSpecs.REPLICATION_TYPES
    elif key == constants.ExtraSpecs.MOUNT_SNAPSHOT_SUPPORT:
        return parse_boolean_extra_spec(key, value) is not None
    elif key == constants.ExtraSpecs.AVAILABILITY_ZONES:
        return is_valid_csv(value)
    elif key in [constants.ExtraSpecs.PROVISIONING_MAX_SHARE_SIZE,
                 constants.ExtraSpecs.PROVISIONING_MIN_SHARE_SIZE,
                 constants.ExtraSpecs.PROVISIONING_MAX_SHARE_EXTEND_SIZE]:
        try:
            common.validate_integer(value, 'share_size', min_value=1)
            return True
        except ValueError:
            return False

    return False


def get_valid_optional_extra_specs(extra_specs):
    """Validates and returns optional/standard extra specs from dict.

    Raises InvalidExtraSpec if extra specs are not valid.
    """

    extra_specs = extra_specs or {}
    present_optional_extra_spec_keys = set(extra_specs).intersection(
        set(get_optional_extra_specs()))

    optional_extra_specs = {}

    for key in present_optional_extra_spec_keys:
        value = extra_specs.get(key, '')
        if not is_valid_optional_extra_spec(key, value):
            msg = _("Value of optional extra_spec %s is not valid.") % key
            raise exception.InvalidExtraSpec(reason=msg)

        optional_extra_specs[key] = value

    return optional_extra_specs


def add_share_type_access(context, share_type_id, project_id):
    """Add access to share type for project_id."""
    if share_type_id is None:
        msg = _("share_type_id cannot be None")
        raise exception.InvalidShareType(reason=msg)
    return db.share_type_access_add(context, share_type_id, project_id)


def remove_share_type_access(context, share_type_id, project_id):
    """Remove access to share type for project_id."""
    if share_type_id is None:
        msg = _("share_type_id cannot be None")
        raise exception.InvalidShareType(reason=msg)
    return db.share_type_access_remove(context, share_type_id, project_id)


def get_extra_specs_from_share(share):
    type_id = share.get('share_type_id', None)
    return get_share_type_extra_specs(type_id)


def parse_boolean_extra_spec(extra_spec_key, extra_spec_value):
    """Parse extra spec values of the form '<is> True' or '<is> False'

    This method returns the boolean value of an extra spec value.  If
    the value does not conform to the standard boolean pattern, it raises
    an InvalidExtraSpec exception.
    """
    if not isinstance(extra_spec_value, str):
        extra_spec_value = str(extra_spec_value)

    match = re.match(r'^<is>\s*(?P<value>True|False)$',
                     extra_spec_value.strip(),
                     re.IGNORECASE)
    if match:
        extra_spec_value = match.group('value')
    try:
        return strutils.bool_from_string(extra_spec_value, strict=True)
    except ValueError:
        msg = (_('Invalid boolean extra spec %(key)s : %(value)s') %
               {'key': extra_spec_key, 'value': extra_spec_value})
        raise exception.InvalidExtraSpec(reason=msg)


def provision_filter_on_size(context, share_type, size, operation='create'):
    """This function filters share provisioning requests on size limits.

    If a share type has provisioning size min/max set, this filter
    will ensure that the share size requested is within the size
    limits specified in the share type.
    """
    if not share_type:
        share_type = get_default_share_type()
        if not share_type:
            return

    size_int = int(size)
    extra_specs = share_type.get('extra_specs', {})
    if operation in ['create', 'shrink']:
        min_size = extra_specs.get(MIN_SIZE_KEY)
        if min_size and size_int < int(min_size):
            msg = _("Specified share size of '%(req_size)d' is less "
                    "than the minimum required size of '%(min_size)s' "
                    "for share type '%(sha_type)s'."
                    ) % {'req_size': size_int, 'min_size': min_size,
                         'sha_type': share_type['name']}
            raise exception.InvalidInput(reason=msg)
    if operation in ['create', 'extend']:
        max_size = extra_specs.get(MAX_SIZE_KEY)
        if max_size and size_int > int(max_size):
            msg = _("Specified share size of '%(req_size)d' is "
                    "greater than the maximum allowable size of "
                    "'%(max_size)s' for share type '%(sha_type)s'."
                    ) % {'req_size': size_int, 'max_size': max_size,
                         'sha_type': share_type['name']}
            raise exception.InvalidInput(reason=msg)
    if operation in ['admin-extend']:
        max_extend_size = extra_specs.get(MAX_EXTEND_SIZE_KEY)
        if max_extend_size and size_int > int(max_extend_size):
            msg = _("Specified share size of '%(req_size)d' is "
                    "greater than the maximum allowable extend size of "
                    "'%(max_extend_size)s' for share type '%(sha_type)s'."
                    ) % {'req_size': size_int,
                         'max_extend_size': max_extend_size,
                         'sha_type': share_type['name']}
            raise exception.InvalidInput(reason=msg)


def revert_allocated_share_type_quotas_during_migration(
        context, share, share_type_id,
        allow_deallocate_from_current_type=False):

    # If both new share type and share's share type ID, there is no need
    # to revert quotas because new quotas weren't allocated, as share
    # type changes weren't identified, unless it is a migration that was
    # successfully completed
    if ((share_type_id == share['share_type_id'])
            and not allow_deallocate_from_current_type):
        return

    new_share_type = get_share_type(context, share_type_id)
    new_type_extra_specs = new_share_type.get('extra_specs', None)

    new_type_replication_type = None
    if new_type_extra_specs:
        new_type_replication_type = new_type_extra_specs.get(
            'replication_type', None)

    deltas = {}

    if new_type_replication_type:
        deltas['share_replicas'] = -1
        deltas['replica_gigabytes'] = -share['size']

    deltas.update({
        'share_type_id': new_share_type['id'],
        'shares': -1,
        'gigabytes': -share['size']
    })

    try:
        reservations = QUOTAS.reserve(
            context, project_id=share['project_id'],
            user_id=share['user_id'], **deltas)
    except Exception:
        LOG.exception("Failed to update usages for share_replicas and "
                      "replica_gigabytes.")
    else:
        QUOTAS.commit(
            context, reservations, project_id=share['project_id'],
            user_id=share['user_id'], share_type_id=share_type_id)
