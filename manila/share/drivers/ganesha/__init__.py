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

import abc
import errno
import os
import re

from oslo_config import cfg
from oslo_log import log
import six

from manila import exception
from manila.i18n import _LI
from manila.share.drivers.ganesha import manager as ganesha_manager
from manila.share.drivers.ganesha import utils as ganesha_utils

CONF = cfg.CONF
LOG = log.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class NASHelperBase(object):
    """Interface to work with share."""

    def __init__(self, execute, config, **kwargs):
        self.configuration = config
        self._execute = execute

    def init_helper(self):
        """Initializes protocol-specific NAS drivers."""

    @abc.abstractmethod
    def allow_access(self, base_path, share, access):
        """Allow access to the host."""

    @abc.abstractmethod
    def deny_access(self, base_path, share, access):
        """Deny access to the host."""


class GaneshaNASHelper(NASHelperBase):
    """Execute commands relating to Shares."""

    def __init__(self, execute, config, tag='<no name>', **kwargs):
        super(GaneshaNASHelper, self).__init__(execute, config, **kwargs)
        self.tag = tag

    _confrx = re.compile('\.(conf|json)\Z')

    def _load_conf_dir(self, dirpath, must_exist=True):
        """Load Ganesha config files in dirpath in alphabetic order."""
        try:
            dirlist = os.listdir(dirpath)
        except OSError as e:
            if e.errno != errno.ENOENT or must_exist:
                raise
            dirlist = []
        LOG.info(_LI('Loading Ganesha config from %s.'), dirpath)
        conf_files = list(filter(self._confrx.search, dirlist))
        conf_files.sort()
        export_template = {}
        for conf_file in conf_files:
            with open(os.path.join(dirpath, conf_file)) as f:
                ganesha_utils.patch(
                    export_template,
                    ganesha_manager.parseconf(f.read()))
        return export_template

    def init_helper(self):
        """Initializes protocol-specific NAS drivers."""
        self.ganesha = ganesha_manager.GaneshaManager(
            self._execute,
            self.tag,
            ganesha_config_path=self.configuration.ganesha_config_path,
            ganesha_export_dir=self.configuration.ganesha_export_dir,
            ganesha_db_path=self.configuration.ganesha_db_path,
            ganesha_service_name=self.configuration.ganesha_service_name)
        system_export_template = self._load_conf_dir(
            self.configuration.ganesha_export_template_dir,
            must_exist=False)
        if system_export_template:
            self.export_template = system_export_template
        else:
            self.export_template = self._default_config_hook()

    def _default_config_hook(self):
        """The default export block.

        Subclass this to add FSAL specific defaults.

        Suggested approach: take the return value of superclass'
        method, patch with dict containing your defaults, and
        return the result. However, you can also provide your
        defaults from scratch with no regard to superclass.
        """

        return self._load_conf_dir(ganesha_utils.path_from(__file__, "conf"))

    def _fsal_hook(self, base_path, share, access):
        """Subclass this to create FSAL block."""
        return {}

    def allow_access(self, base_path, share, access):
        """Allow access to the share."""
        if access['access_type'] != 'ip':
            raise exception.InvalidShareAccess('Only IP access type allowed')
        cf = {}
        accid = access['id']
        name = share['name']
        export_name = "%s--%s" % (name, accid)
        ganesha_utils.patch(cf, self.export_template, {
            'EXPORT': {
                'Export_Id': self.ganesha.get_export_id(),
                'Path': os.path.join(base_path, name),
                'Pseudo': os.path.join(base_path, export_name),
                'Tag': accid,
                'CLIENT': {
                    'Clients': access['access_to']
                },
                'FSAL': self._fsal_hook(base_path, share, access)
            }
        })
        self.ganesha.add_export(export_name, cf)

    def deny_access(self, base_path, share, access):
        """Deny access to the share."""
        self.ganesha.remove_export("%s--%s" % (share['name'], access['id']))
