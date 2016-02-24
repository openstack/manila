# Copyright (c) 2015 Red Hat, Inc.
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

"""GlusterFS share layouts.

A share layout encapsulates a particular way of mapping GlusterFS entities
to a share and utilizing them to back the share.
"""

import abc
import errno

from oslo_config import cfg
from oslo_utils import importutils
import six

from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share.drivers.ganesha import utils as ganesha_utils

glusterfs_share_layout_opts = [
    cfg.StrOpt(
        'glusterfs_share_layout',
        help="Specifies GlusterFS share layout, that is, "
             "the method of associating backing GlusterFS "
             "resources to shares."),
]

CONF = cfg.CONF
CONF.register_opts(glusterfs_share_layout_opts)


class GlusterfsShareDriverBase(driver.ShareDriver):

    LAYOUT_PREFIX = 'manila.share.drivers.glusterfs'

    supported_layouts = ()
    supported_protocols = ()
    _supported_access_types = ()
    _supported_access_levels = ()

    GLUSTERFS_VERSION_MIN = (0, 0)

    def __init__(self, *args, **kwargs):
        super(GlusterfsShareDriverBase, self).__init__(*args, **kwargs)
        self.configuration.append_config_values(
            glusterfs_share_layout_opts)
        layout_name = self.configuration.glusterfs_share_layout
        if not layout_name:
            layout_name = self.supported_layouts[0]
        if layout_name not in self.supported_layouts:
            raise exception.GlusterfsException(
                _('driver %(driver)s does not support %(layout)s layout') %
                {'driver': type(self).__name__, 'layout': layout_name})

        self.layout = importutils.import_object(
            '.'.join((self.LAYOUT_PREFIX, layout_name)),
            self, **kwargs)
        # we determine snapshot support in our own scope, as
        # 1) the calculation based on parent method
        #    redefinition does not work for us, as actual
        #    glusterfs driver classes are subclassed from
        #    *this* class, not from driver.ShareDriver
        #    and they don't need to redefine snapshot
        #    methods for themselves;
        # 2) snapshot support depends on choice of layout.
        self._snapshots_are_supported = getattr(self.layout,
                                                '_snapshots_are_supported',
                                                False)

    def _setup_via_manager(self, share_mgr, share_mgr_parent=None):
        """Callback for layout's `create_share` and `create_share_from_snapshot`

        :param share_mgr: a {'share': <share>, 'manager': <gmgr>}
               dict where <share> is the share created
               in `create_share` or `create_share_from_snapshot`
               and <gmgr> is a GlusterManager instance
               representing the GlusterFS resource
               allocated for it.
        :param gluster_mgr_parent: a {'share': <share>, 'manager': <gmgr>}
               dict where <share> is the original share of the snapshot
               used in `create_share_from_snapshot` and <gmgr> is a
               GlusterManager instance representing the GlusterFS
               resource allocated for it.
        :returns: export location for share_mgr['share'].
        """

    @property
    def supported_access_levels(self):
        return self._supported_access_levels

    @property
    def supported_access_types(self):
        return self._supported_access_types

    def _access_rule_validator(self, abort):

        def validator(rule):
            return ganesha_utils.validate_access_rule(
                self.supported_access_types, self.supported_access_levels,
                rule, abort)

        return validator

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules for given share.

        Driver supports 2 different cases in this method:
        1. Recovery after error - 'access_rules' contains all access_rules,
        'add_rules' and 'delete_rules' are []. Driver should clear any
        existent access rules and apply all access rules for given share.
        This recovery is made at driver start up.

        2. Adding/Deleting of several access rules - 'access_rules' contains
        all access_rules, 'add_rules' and 'delete_rules' contain rules which
        should be added/deleted. Driver can ignore rules in 'access_rules' and
        apply only rules from 'add_rules' and 'delete_rules'.
        """
        gluster_mgr = self.layout._share_manager(share)

        access_rules, add_rules, delete_rules = (
            list(filter(self._access_rule_validator(abort), rules)) for (
                rules, abort) in ((access_rules, True),
                                  (add_rules, True),
                                  (delete_rules, False)))

        # Recovery mode.
        if not (add_rules or delete_rules):
            ruleop, recovery = (access_rules, []), True
        else:
            ruleop, recovery = (add_rules, delete_rules), False

        self._update_access_via_manager(gluster_mgr, context, share,
                                        *ruleop, recovery=recovery)

    def _update_access_via_manager(self, gluster_mgr, context, share,
                                   add_rules, delete_rules, recovery=False,
                                   share_server=None):
        raise NotImplementedError()

    def do_setup(self, *a, **kw):
        return self.layout.do_setup(*a, **kw)

    @classmethod
    def _check_proto(cls, share):
        proto = share['share_proto'].upper()
        if proto not in cls.supported_protocols:
            msg = _("Share protocol %s is not supported.") % proto
            raise exception.ShareBackendException(msg=msg)

    def create_share(self, context, share, *a, **kw):
        self._check_proto(share)
        return self.layout.create_share(context, share, *a, **kw)

    def create_share_from_snapshot(self, context, share, *a, **kw):
        self._check_proto(share)
        return self.layout.create_share_from_snapshot(context, share, *a, **kw)

    def create_snapshot(self, *a, **kw):
        return self.layout.create_snapshot(*a, **kw)

    def delete_share(self, *a, **kw):
        return self.layout.delete_share(*a, **kw)

    def delete_snapshot(self, *a, **kw):
        return self.layout.delete_snapshot(*a, **kw)

    def ensure_share(self, *a, **kw):
        return self.layout.ensure_share(*a, **kw)

    def manage_existing(self, *a, **kw):
        return self.layout.manage_existing(*a, **kw)

    def unmanage(self, *a, **kw):
        return self.layout.unmanage(*a, **kw)

    def extend_share(self, *a, **kw):
        return self.layout.extend_share(*a, **kw)

    def shrink_share(self, *a, **kw):
        return self.layout.shrink_share(*a, **kw)

    def _update_share_stats(self, data={}):
        try:
            data.update(self.layout._update_share_stats())
        except NotImplementedError:
            pass
        super(GlusterfsShareDriverBase, self)._update_share_stats(data)


@six.add_metaclass(abc.ABCMeta)
class GlusterfsShareLayoutBase(object):
    """Base class for share layouts."""

    def __init__(self, driver, *args, **kwargs):
        self.driver = driver
        self.configuration = kwargs.get('configuration')

    def _check_mount_glusterfs(self):
        """Checks if mount.glusterfs(8) is available."""
        try:
            self.driver._execute('mount.glusterfs', check_exit_code=False)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                raise exception.GlusterfsException(
                    _('mount.glusterfs is not installed.'))
            else:
                raise

    @abc.abstractmethod
    def _share_manager(self, share):
        """Return GlusterManager object representing share's backend."""

    @abc.abstractmethod
    def do_setup(self, context):
        """Any initialization the share driver does while starting."""

    @abc.abstractmethod
    def create_share(self, context, share, share_server=None):
        """Is called to create share."""

    @abc.abstractmethod
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""

    @abc.abstractmethod
    def create_snapshot(self, context, snapshot, share_server=None):
        """Is called to create snapshot."""

    @abc.abstractmethod
    def delete_share(self, context, share, share_server=None):
        """Is called to remove share."""

    @abc.abstractmethod
    def delete_snapshot(self, context, snapshot, share_server=None):
        """Is called to remove snapshot."""

    @abc.abstractmethod
    def ensure_share(self, context, share, share_server=None):
        """Invoked to ensure that share is exported."""

    @abc.abstractmethod
    def manage_existing(self, share, driver_options):
        """Brings an existing share under Manila management."""

    @abc.abstractmethod
    def unmanage(self, share):
        """Removes the specified share from Manila management."""

    @abc.abstractmethod
    def extend_share(self, share, new_size, share_server=None):
        """Extends size of existing share."""

    @abc.abstractmethod
    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks size of existing share."""

    def _update_share_stats(self):
        raise NotImplementedError()
