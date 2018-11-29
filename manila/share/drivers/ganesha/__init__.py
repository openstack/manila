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

from manila.common import constants
from manila import exception
from manila.i18n import _
from manila.share.drivers.ganesha import manager as ganesha_manager
from manila.share.drivers.ganesha import utils as ganesha_utils

CONF = cfg.CONF
LOG = log.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class NASHelperBase(object):
    """Interface to work with share."""

    # drivers that use a helper derived from this class
    # should pass the following attributes to
    # ganesha_utils.validate_acces_rule in their
    # update_access implementation.
    supported_access_types = ()
    supported_access_levels = ()

    def __init__(self, execute, config, **kwargs):
        self.configuration = config
        self._execute = execute

    def init_helper(self):
        """Initializes protocol-specific NAS drivers."""

    @abc.abstractmethod
    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules of share."""


class GaneshaNASHelper(NASHelperBase):
    """Perform share access changes using Ganesha version < 2.4."""

    supported_access_types = ('ip', )
    supported_access_levels = (constants.ACCESS_LEVEL_RW, )

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
        LOG.info('Loading Ganesha config from %s.', dirpath)
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

    def _cleanup_fsal_hook(self, base_path, share, access):
        """Callback for FSAL specific cleanup after removing an export."""
        pass

    def _allow_access(self, base_path, share, access):
        """Allow access to the share."""
        if access['access_type'] != 'ip':
            raise exception.InvalidShareAccess('Only IP access type allowed')

        access = ganesha_utils.fixup_access_rule(access)

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

    def _deny_access(self, base_path, share, access):
        """Deny access to the share."""
        self.ganesha.remove_export("%s--%s" % (share['name'], access['id']))

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules of share."""
        if not (add_rules or delete_rules):
            add_rules = access_rules
            self.ganesha.reset_exports()
            self.ganesha.restart_service()

        for rule in add_rules:
            self._allow_access('/', share, rule)
        for rule in delete_rules:
            self._deny_access('/', share, rule)


class GaneshaNASHelper2(GaneshaNASHelper):
    """Perform share access changes using Ganesha version >= 2.4."""

    def __init__(self, execute, config, tag='<no name>', **kwargs):
        super(GaneshaNASHelper2, self).__init__(execute, config, **kwargs)
        if self.configuration.ganesha_rados_store_enable:
            self.ceph_vol_client = kwargs.pop('ceph_vol_client')

    def init_helper(self):
        """Initializes protocol-specific NAS drivers."""
        kwargs = {
            'ganesha_config_path': self.configuration.ganesha_config_path,
            'ganesha_export_dir': self.configuration.ganesha_export_dir,
            'ganesha_service_name': self.configuration.ganesha_service_name
        }
        if self.configuration.ganesha_rados_store_enable:
            kwargs['ganesha_rados_store_enable'] = (
                self.configuration.ganesha_rados_store_enable)
            if not self.configuration.ganesha_rados_store_pool_name:
                raise exception.GaneshaException(
                    _('"ganesha_rados_store_pool_name" config option is not '
                      'set in the driver section.'))
            kwargs['ganesha_rados_store_pool_name'] = (
                self.configuration.ganesha_rados_store_pool_name)
            kwargs['ganesha_rados_export_index'] = (
                self.configuration.ganesha_rados_export_index)
            kwargs['ganesha_rados_export_counter'] = (
                self.configuration.ganesha_rados_export_counter)
            kwargs['ceph_vol_client'] = (
                self.ceph_vol_client)
        else:
            kwargs['ganesha_db_path'] = self.configuration.ganesha_db_path
        self.ganesha = ganesha_manager.GaneshaManager(
            self._execute, self.tag, **kwargs)
        system_export_template = self._load_conf_dir(
            self.configuration.ganesha_export_template_dir,
            must_exist=False)
        if system_export_template:
            self.export_template = system_export_template
        else:
            self.export_template = self._default_config_hook()

    def _get_export_path(self, share):
        """Subclass this to return export path."""
        raise NotImplementedError()

    def _get_export_pseudo_path(self, share):
        """Subclass this to return export pseudo path."""
        raise NotImplementedError()

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules of share.

        Creates an export per share. Modifies access rules of shares by
        dynamically updating exports via DBUS.
        """

        confdict = {}
        existing_access_rules = []

        if self.ganesha.check_export_exists(share['name']):
            confdict = self.ganesha._read_export(share['name'])
            existing_access_rules = confdict["EXPORT"]["CLIENT"]
            if not isinstance(existing_access_rules, list):
                existing_access_rules = [existing_access_rules]
        else:
            if not access_rules:
                LOG.warning("Trying to remove export file '%s' but it's "
                            "already gone",
                            self.ganesha._getpath(share['name']))
                return

        wanted_rw_clients, wanted_ro_clients = [], []
        for rule in access_rules:
            rule = ganesha_utils.fixup_access_rule(rule)
            if rule['access_level'] == 'rw':
                wanted_rw_clients.append(rule['access_to'])
            elif rule['access_level'] == 'ro':
                wanted_ro_clients.append(rule['access_to'])

        if access_rules:
            # Add or Update export.
            clients = []
            if wanted_ro_clients:
                clients.append({
                    'Access_Type': 'ro',
                    'Clients': ','.join(wanted_ro_clients)
                })
            if wanted_rw_clients:
                clients.append({
                    'Access_Type': 'rw',
                    'Clients': ','.join(wanted_rw_clients)
                })

            if existing_access_rules:
                # Update existing export.
                ganesha_utils.patch(confdict, {
                    'EXPORT': {
                        'CLIENT': clients
                    }
                })
                self.ganesha.update_export(share['name'], confdict)
            else:
                # Add new export.
                ganesha_utils.patch(confdict, self.export_template, {
                    'EXPORT': {
                        'Export_Id': self.ganesha.get_export_id(),
                        'Path': self._get_export_path(share),
                        'Pseudo': self._get_export_pseudo_path(share),
                        'Tag': share['name'],
                        'CLIENT': clients,
                        'FSAL': self._fsal_hook(None, share, None)
                    }
                })
                self.ganesha.add_export(share['name'], confdict)
        else:
            # No clients have access to the share. Remove export.
            self.ganesha.remove_export(share['name'])
            self._cleanup_fsal_hook(None, share, None)
