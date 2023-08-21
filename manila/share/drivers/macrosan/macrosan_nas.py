# Copyright (c) 2022 MacroSAN Technologies Co., Ltd.
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
Share driver for Macrosan Storage Array.
"""

import functools
from oslo_config import cfg
from oslo_log import log

from manila.share import driver
from manila.share.drivers.macrosan import macrosan_helper

macrosan_opts = [
    cfg.HostAddressOpt('macrosan_nas_ip',
                       required=True,
                       help='IP address for the Macrosan NAS server.'),
    cfg.PortOpt('macrosan_nas_port',
                default=8443,
                help='Port number for the Macrosan NAS server.'),
    cfg.StrOpt('macrosan_nas_username',
               default='manila',
               help='Username for the Macrosan NAS server.'),
    cfg.StrOpt('macrosan_nas_password',
               default=None,
               secret=True,
               help='Password for the Macrosan NAS server.'),
    cfg.StrOpt('macrosan_nas_http_protocol',
               default='https',
               choices=['http', 'https'],
               help='Http protocol for the Macrosan NAS server.'),
    cfg.BoolOpt('macrosan_ssl_cert_verify',
                default=False,
                help='Defines whether the driver should check ssl cert.'),
    cfg.StrOpt('macrosan_nas_prefix',
               default='nas',
               help='Url prefix for the Macrosan NAS server.'),
    cfg.ListOpt('macrosan_share_pools',
                required=True,
                help='Comma separated list of Macrosan NAS pools.'),
    cfg.IntOpt('macrosan_timeout',
               default=60,
               help='request timeout in seconds.')
]

CONF = cfg.CONF
CONF.register_opts(macrosan_opts)
LOG = log.getLogger(__name__)


def debug_trace(func):
    """Log the dirver invoke method start and leave information

    Used in the MacrosanNasDriver class methods.
    Ensure func have 'self' argument.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        driver = args[0]
        method_name = "%(class_name)s.%(method)s" \
                      % {"class_name": driver.__class__.__name__,
                         "method": func.__name__}
        backend_name = driver.configuration.share_backend_name
        LOG.debug("[%(backend_name)s]:Start %(method_name)s",
                  {"backend_name": backend_name, "method_name": method_name})
        result = func(*args, **kwargs)
        LOG.debug("[%(backend_name)s]:Leave %(method_name)s",
                  {"backend_name": backend_name, "method_name": method_name})
        return result

    return wrapper


class MacrosanNasDriver(driver.ShareDriver):
    """Macrosan Share Driver

        Driver version history:
        V1.0.0:    Initial version
                   Driver support:
                       share create/delete,
                       extend size,
                       shrink size,
                       update_access.
                       protocol: NFS/CIFS

    """

    VENDOR = 'Macrosan'
    VERSION = '1.0.0'
    PROTOCOL = 'NFS_CIFS'

    def __init__(self, *args, **kwargs):
        super(MacrosanNasDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(macrosan_opts)

        self.helper = macrosan_helper.MacrosanHelper(self.configuration)

    @debug_trace
    def do_setup(self, context):
        """initialization the driver when start"""
        self.helper.do_setup()

    @debug_trace
    def check_for_setup_error(self):
        """Check prerequisites"""
        self.helper.check_share_service()

    @debug_trace
    def create_share(self, context, share, share_server=None):
        """Create a share"""
        return self.helper.create_share(share, share_server)

    @debug_trace
    def delete_share(self, context, share, share_server=None):
        """Delete a share."""
        self.helper.delete_share(share, share_server)

    @debug_trace
    def extend_share(self, share, new_size, share_server=None):
        """Extend share capacity"""
        self.helper.extend_share(share, new_size, share_server)

    @debug_trace
    def shrink_share(self, share, new_size, share_server=None):
        """Shrink share capacity"""
        self.helper.shrink_share(share, new_size, share_server)

    @debug_trace
    def ensure_share(self, context, share, share_server=None):
        """Enusre that share is exported."""
        return self.helper.ensure_share(share, share_server)

    @debug_trace
    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules list.

        :param context: Current context
        :param share: Share model with share data.
        :param access_rules: All access rules for given share
        :param add_rules: Empty List or List of access rules which should be
               added. access_rules already contains these rules.
        :param delete_rules: Empty List or List of access rules which should be
               removed. access_rules doesn't contain these rules.
        :param share_server: Not used by this driver.

        :returns: None, or a dictionary of ``access_id``, ``access_key`` as
                  key: value pairs for the rules added, where, ``access_id``
                  is the UUID (string) of the access rule, and ``access_key``
                  is the credential (string) of the entity granted access.
                  During recovery after error, the returned dictionary must
                  contain ``access_id``, ``access_key`` for all the rules that
                  the driver is ordered to resync, i.e. rules in the
                  ``access_rules`` parameter.
        """
        return self.helper.update_access(share, access_rules,
                                         add_rules, delete_rules,
                                         share_server)

    @debug_trace
    def _update_share_stats(self):
        """Update backend status ,include driver and pools"""

        data = {
            'vendor_name': self.VENDOR,
            'driver_version': self.VERSION,
            'storage_protocol': self.PROTOCOL,
            'share_backend_name':
                self.configuration.safe_get('share_backend_name'),
        }
        self.helper.update_share_stats(data)
        super(MacrosanNasDriver, self)._update_share_stats(data)
