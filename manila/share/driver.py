# Copyright 2012 NetApp
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
"""
Drivers for shares.

"""

import time

from oslo.config import cfg
import six

from manila.common import constants
from manila import exception
from manila.i18n import _LE
from manila import network
from manila.openstack.common import log as logging
from manila import utils

LOG = logging.getLogger(__name__)

share_opts = [
    # NOTE(rushiagr): Reasonable to define this option at only one place.
    cfg.IntOpt(
        'num_shell_tries',
        default=3,
        help='Number of times to attempt to run flakey shell commands.'),
    cfg.IntOpt(
        'reserved_share_percentage',
        default=0,
        help='The percentage of backend capacity reserved.'),
    cfg.StrOpt(
        'share_backend_name',
        default=None,
        help='The backend name for a given driver implementation.'),
    cfg.StrOpt(
        'network_config_group',
        default=None,
        help="Name of the configuration group in the Manila conf file "
             "to look for network config options."
             "If not set, the share backend's config group will be used."
             "If an option is not found within provided group, then"
             "'DEFAULT' group will be used for search of option."),
    cfg.StrOpt(
        'share_driver_mode',
        default=None,
        help="One specific mode for driver to use. Available values: "
             "%s. What modes are supported and can be used is "
             "up to driver. If set None then default will be used." %
             six.text_type(constants.VALID_SHARE_DRIVER_MODES)),
]

ssh_opts = [
    cfg.IntOpt(
        'ssh_conn_timeout',
        default=60,
        help='Backend server SSH connection timeout.'),
    cfg.IntOpt(
        'ssh_min_pool_conn',
        default=1,
        help='Minimum number of connections in the SSH pool.'),
    cfg.IntOpt(
        'ssh_max_pool_conn',
        default=10,
        help='Maximum number of connections in the SSH pool.'),
]

ganesha_opts = [
    cfg.StrOpt('ganesha_config_dir',
               default='/etc/ganesha',
               help='Directory where Ganesha config files are stored.'),
    cfg.StrOpt('ganesha_config_path',
               default='$ganesha_config_dir/ganesha.conf',
               help='Path to main Ganesha config file.'),
    cfg.StrOpt('ganesha_nfs_export_options',
               default='maxread = 65536, prefread = 65536',
               help='Options to use when exporting a share using ganesha '
                    'NFS server. Note that these defaults can be overridden '
                    'when a share is created by passing metadata with key '
                    'name export_options.  Also note the complete set of '
                    'default ganesha export options is specified in '
                    'ganesha_utils. (GPFS only.)'),
    cfg.StrOpt('ganesha_service_name',
               default='ganesha.nfsd',
               help='Name of the ganesha nfs service.'),
    cfg.StrOpt('ganesha_db_path',
               default='$state_path/manila-ganesha.db',
               help='Location of Ganesha database file. '
                    '(Ganesha module only.)'),
    cfg.StrOpt('ganesha_export_dir',
               default='$ganesha_config_dir/export.d',
               help='Path to Ganesha export template. (Ganesha module only.)'),
    cfg.StrOpt('ganesha_export_template_dir',
               default='/etc/manila/ganesha-export-templ.d',
               help='Path to Ganesha export template. (Ganesha module only.)'),
]

CONF = cfg.CONF
CONF.register_opts(share_opts)
CONF.register_opts(ssh_opts)
CONF.register_opts(ganesha_opts)


class ExecuteMixin(object):
    """Provides an executable functionality to a driver class."""

    def init_execute_mixin(self, *args, **kwargs):
        if self.configuration:
            self.configuration.append_config_values(ssh_opts)
        self.set_execute(kwargs.pop('execute', utils.execute))

    def set_execute(self, execute):
        self._execute = execute

    def _try_execute(self, *command, **kwargs):
        # NOTE(vish): Volume commands can partially fail due to timing, but
        #             running them a second time on failure will usually
        #             recover nicely.
        tries = 0
        while True:
            try:
                self._execute(*command, **kwargs)
                return True
            except exception.ProcessExecutionError:
                tries += 1
                if tries >= self.configuration.num_shell_tries:
                    raise
                LOG.exception(_LE("Recovering from a failed execute. "
                                  "Try number %s"), tries)
                time.sleep(tries ** 2)


class GaneshaMixin(object):
    """Augment derived classes with Ganesha configuration."""

    def init_ganesha_mixin(self, *args, **kwargs):
        if self.configuration:
            self.configuration.append_config_values(ganesha_opts)


class ShareDriver(object):
    """Class defines interface of NAS driver."""

    def __init__(self, *args, **kwargs):
        super(ShareDriver, self).__init__()
        self.configuration = kwargs.get('configuration', None)
        if self.configuration:
            self.configuration.append_config_values(share_opts)
            network_config_group = (self.configuration.network_config_group or
                                    self.configuration.config_group)
            self.mode = self.configuration.safe_get('share_driver_mode')
        else:
            network_config_group = None
            self.mode = CONF.share_driver_mode

        if hasattr(self, 'init_execute_mixin'):
            # Instance with 'ExecuteMixin'
            self.init_execute_mixin(*args, **kwargs)  # pylint: disable=E1101
        if hasattr(self, 'init_ganesha_mixin'):
            # Instance with 'GaneshaMixin'
            self.init_execute_mixin(*args, **kwargs)  # pylint: disable=E1101
        self.network_api = network.API(config_group_name=network_config_group)

    def _validate_driver_mode(self, mode):
        valid = constants.VALID_SHARE_DRIVER_MODES
        if mode not in valid:
            data = {'mode': mode, 'valid': valid}
            msg = ("Provided unsupported driver mode '%(mode)s'. List of "
                   "valid driver modes is %(valid)s." % data)
            LOG.error(msg)
            raise exception.InvalidParameterValue(msg)
        return mode

    def get_driver_mode(self, supported_driver_modes):
        """Verify and return driver mode.

        Call this method within share driver to get value for 'mode' attr,

        :param supported_driver_modes: text value or list/tuple of text values
            with supported modes by share driver, see list of available values
            in manila.common.constants.VALID_SHARE_DRIVER_MODES
        :returns: text_type -- name of enabled driver mode.
        :raises: exception.InvalidParameterValue
        """
        msg = None

        if isinstance(supported_driver_modes, six.string_types):
            supported_driver_modes = [supported_driver_modes, ]

        if not isinstance(supported_driver_modes, (tuple, list)):
            msg = ("Provided param 'supported_driver_modes' has unexpected "
                   "type - '%s'." % type(supported_driver_modes))
        elif not len(supported_driver_modes):
            msg = "At least one mode should be supported by share driver."
        elif self.mode:
            if self.mode not in supported_driver_modes:
                data = {'mode': self.mode, 'supported': supported_driver_modes}
                msg = ("Unsupported driver mode '%(mode)s' is provided. "
                       "List of supported is %(supported)s." % data)
            else:
                return self._validate_driver_mode(self.mode)
        elif len(supported_driver_modes) > 1:
            msg = ("Driver mode was not specified explicitly and amount of "
                   "supported driver modes %s is bigger than one, please "
                   "specify it using config option 'share_driver_mode'." %
                   six.text_type(supported_driver_modes))

        if msg:
            LOG.error(msg)
            raise exception.InvalidParameterValue(msg)

        return self._validate_driver_mode(supported_driver_modes[0])

    def create_share(self, context, share, share_server=None):
        """Is called to create share."""
        raise NotImplementedError()

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""
        raise NotImplementedError()

    def create_snapshot(self, context, snapshot, share_server=None):
        """Is called to create snapshot."""
        raise NotImplementedError()

    def delete_share(self, context, share, share_server=None):
        """Is called to remove share."""
        raise NotImplementedError()

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Is called to remove snapshot."""
        raise NotImplementedError()

    def ensure_share(self, context, share, share_server=None):
        """Invoked to sure that share is exported."""
        raise NotImplementedError()

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""
        raise NotImplementedError()

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        raise NotImplementedError()

    def check_for_setup_error(self):
        """Check for setup error."""
        pass

    def do_setup(self, context):
        """Any initialization the share driver does while starting."""
        pass

    def get_share_stats(self, refresh=False):
        """Get share status.

        If 'refresh' is True, run update the stats first.
        """
        if refresh:
            self._update_share_stats()

        return self._stats

    def get_network_allocations_number(self):
        """Returns number of network allocations for creating VIFs.

        Drivers that use Nova for share servers should return zero (0) here
        same as Generic driver does.
        Because Nova will handle network resources allocation.
        Drivers that handle networking itself should calculate it according
        to their own requirements. It can have 1+ network interfaces.
        """
        raise NotImplementedError()

    def allocate_network(self, context, share_server, share_network,
                         count=None, **kwargs):
        """Allocate network resources using given network information."""
        if count is None:
            count = self.get_network_allocations_number()
        if count:
            kwargs.update(count=count)
            self.network_api.allocate_network(
                context, share_server, share_network, **kwargs)

    def deallocate_network(self, context, share_server_id):
        """Deallocate network resources for the given share server."""
        if self.get_network_allocations_number():
            self.network_api.deallocate_network(context, share_server_id)

    def setup_server(self, network_info, metadata=None):
        """Set up and configures share server with given network parameters."""
        pass

    def teardown_server(self, server_details, security_services=None):
        """Teardown share server."""
        pass

    def _update_share_stats(self):
        """Retrieve stats info from share group."""

        LOG.debug("Updating share stats")
        data = {}
        backend_name = self.configuration.safe_get('share_backend_name')
        # Note(zhiteng): These information are driver/backend specific,
        # each driver may define these values in its own config options
        # or fetch from driver specific configuration file.
        data["share_backend_name"] = backend_name or 'Generic_NFS'
        data["share_driver_mode"] = self.mode
        data["vendor_name"] = 'Open Source'
        data["driver_version"] = '1.0'
        data["storage_protocol"] = None

        data['total_capacity_gb'] = 'infinite'
        data['free_capacity_gb'] = 'infinite'
        data['reserved_percentage'] = 0
        data['QoS_support'] = False
        self._stats = data
