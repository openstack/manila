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

from manila import utils


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
