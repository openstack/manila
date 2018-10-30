# Copyright (c) 2014 Red Hat, Inc.
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

import os
import pipes

from oslo_concurrency import processutils
from oslo_log import log

from manila import exception
from manila.i18n import _
from manila import utils

LOG = log.getLogger(__name__)


def patch(base, *overlays):
    """Recursive dictionary patching."""
    for ovl in overlays:
        for k, v in ovl.items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                patch(base[k], v)
            else:
                base[k] = v
    return base


def walk(dct):
    """Recursive iteration over dictionary."""
    for k, v in dct.items():
        if isinstance(v, dict):
            for w in walk(v):
                yield w
        else:
            yield k, v


class RootExecutor(object):
    """Execute wrapper defaulting to root execution."""

    def __init__(self, execute=utils.execute):
        self.execute = execute

    def __call__(self, *args, **kwargs):
        exkwargs = {"run_as_root": True}
        exkwargs.update(kwargs)
        return self.execute(*args, **exkwargs)


class SSHExecutor(object):
    """Callable encapsulating exec through ssh."""

    def __init__(self, *args, **kwargs):
        self.pool = utils.SSHPool(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        # argument with identifier 'run_as_root=' is not accepted by
        # processutils's ssh_execute() method unlike processutils's execute()
        # method. So implement workaround to enable or disable 'run as root'
        # behavior.
        run_as_root = kwargs.pop('run_as_root', False)
        cmd = ' '.join(pipes.quote(a) for a in args)
        if run_as_root:
            cmd = ' '.join(['sudo', cmd])
        ssh = self.pool.get()
        try:
            ret = processutils.ssh_execute(ssh, cmd, **kwargs)
        finally:
            self.pool.put(ssh)
        return ret


def path_from(fpath, *rpath):
    """Return the join of the dir of fpath and rpath in absolute form."""
    return os.path.join(os.path.abspath(os.path.dirname(fpath)), *rpath)


def validate_access_rule(supported_access_types, supported_access_levels,
                         access_rule, abort=False):

    """Validate an access rule.

    :param access_rule: Access rules to be validated.
    :param supported_access_types: List of access types that are regarded
           valid.
    :param supported_access_levels: List of access levels that are
           regarded valid.
    :param abort: a boolean value that indicates if an exception should
                  be raised whether the rule is invalid.
    :return: Boolean.
    """

    errmsg = _("Unsupported access rule of 'type' %(access_type)s, "
               "'level' %(access_level)s, 'to' %(access_to)s: "
               "%(field)s should be one of %(supported)s.")
    access_param = access_rule.to_dict()

    def validate(field, supported_tokens, excinfo):
        if access_rule['access_%s' % field] in supported_tokens:
            return True

        access_param['field'] = field
        access_param['supported'] = ', '.join(
            "'%s'" % x for x in supported_tokens)
        if abort:
            LOG.error(errmsg, access_param)
            raise excinfo['type'](
                **{excinfo['about']: excinfo['details'] % access_param})
        else:
            LOG.warning(errmsg, access_param)
            return False

    valid = True
    valid &= validate(
        'type', supported_access_types,
        {'type': exception.InvalidShareAccess, 'about': "reason",
         'details': _(
             "%(access_type)s; only %(supported)s access type is allowed")})
    valid &= validate(
        'level', supported_access_levels,
        {'type': exception.InvalidShareAccessLevel, 'about': "level",
         'details': "%(access_level)s"})

    return valid


def fixup_access_rule(access_rule):
    """Adjust access rule as required for ganesha to handle it properly.

    :param access_rule: Access rules to be validated.
    :return: access_rule
    """
    if access_rule['access_to'] == '0.0.0.0/0':
        access_rule['access_to'] = '0.0.0.0'
        LOG.debug("Set access_to field to '0.0.0.0' in ganesha back end.")

    return access_rule
