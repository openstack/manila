# Copyright (c) 2014 Openstack Foundation.
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


from oslo_config import cfg
from oslo_db import exception as db_exception
from oslo_log import log
import six

from manila import context
from manila import db
from manila import exception
from manila.i18n import _
from manila.i18n import _LE

CONF = cfg.CONF
LOG = log.getLogger(__name__)


def create(context, name, extra_specs={}):
    """Creates share types."""
    try:
        type_ref = db.share_type_create(context,
                                        dict(name=name,
                                             extra_specs=extra_specs))
    except db_exception.DBError as e:
        LOG.exception(_LE('DB error: %s'), e)
        raise exception.ShareTypeCreateFailed(name=name,
                                              extra_specs=extra_specs)
    return type_ref


def destroy(context, id):
    """Marks share types as deleted."""
    if id is None:
        msg = _("id cannot be None")
        raise exception.InvalidShareType(reason=msg)
    else:
        db.share_type_destroy(context, id)


def get_all_types(context, inactive=0, search_opts={}):
    """Get all non-deleted share_types.

    Pass true as argument if you want deleted share types returned also.
    """
    share_types = db.share_type_get_all(context, inactive)

    if search_opts:
        LOG.debug("Searching by: %s", search_opts)

        def _check_extra_specs_match(share_type, searchdict):
            for k, v in six.iteritems(searchdict):
                if (k not in share_type['extra_specs'].keys()
                        or share_type['extra_specs'][k] != v):
                    return False
            return True

        # search_option to filter_name mapping.
        filter_mapping = {'extra_specs': _check_extra_specs_match}

        result = {}
        for type_name, type_args in six.iteritems(share_types):
            # go over all filters in the list
            for opt, values in six.iteritems(search_opts):
                try:
                    filter_func = filter_mapping[opt]
                except KeyError:
                    # no such filter - ignore it, go to next filter
                    continue
                else:
                    if filter_func(type_args, values):
                        result[type_name] = type_args
                        break
        share_types = result
    return share_types


def get_share_type(ctxt, id):
    """Retrieves single share type by id."""
    if id is None:
        msg = _("id cannot be None")
        raise exception.InvalidShareType(reason=msg)

    if ctxt is None:
        ctxt = context.get_admin_context()

    return db.share_type_get(ctxt, id)


def get_share_type_by_name(context, name):
    """Retrieves single share type by name."""
    if name is None:
        msg = _("name cannot be None")
        raise exception.InvalidShareType(reason=msg)

    return db.share_type_get_by_name(context, name)


def get_default_share_type(ctxt=None):
    """Get the default share type."""
    name = CONF.default_share_type

    if name is None:
        return {}

    if ctxt is None:
        ctxt = context.get_admin_context()

    try:
        return get_share_type_by_name(ctxt, name)
    except exception.ShareTypeNotFoundByName as e:
        # Couldn't find share type with the name in default_share_type
        # flag, record this issue and move on
        # TODO(zhiteng) consider add notification to warn admin
        LOG.exception(_LE('Default share type is not found, '
                          'please check default_share_type config: %s'),
                      e)


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


def share_types_diff(context, share_type_id1, share_type_id2):
    """Returns a 'diff' of two share types and whether they are equal.

    Returns a tuple of (diff, equal), where 'equal' is a boolean indicating
    whether there is any difference, and 'diff' is a dictionary with the
    following format:
    {'extra_specs': {
    'key1': (value_in_1st_share_type, value_in_2nd_share_type),
    'key2': (value_in_1st_share_type, value_in_2nd_share_type),
    ...}
    """

    def _dict_diff(dict1, dict2):
        res = {}
        equal = True
        if dict1 is None:
            dict1 = {}
        if dict2 is None:
            dict2 = {}
        for k, v in six.iteritems(dict1):
            res[k] = (v, dict2.get(k))
            if k not in dict2 or res[k][0] != res[k][1]:
                equal = False
        for k, v in six.iteritems(dict2):
            res[k] = (dict1.get(k), v)
            if k not in dict1 or res[k][0] != res[k][1]:
                equal = False
        return (res, equal)

    all_equal = True
    diff = {}
    share_type1 = get_share_type(context, share_type_id1)
    share_type2 = get_share_type(context, share_type_id2)

    extra_specs1 = share_type1.get('extra_specs')
    extra_specs2 = share_type2.get('extra_specs')
    diff['extra_specs'], equal = _dict_diff(extra_specs1, extra_specs2)
    if not equal:
        all_equal = False

    return (diff, all_equal)


def get_extra_specs_from_share(share):
    type_id = share.get('share_type_id', None)
    return get_share_type_extra_specs(type_id)
