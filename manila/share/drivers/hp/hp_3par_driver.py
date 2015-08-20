# Copyright 2015 Hewlett Packard Development Company, L.P.
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

"""HP 3PAR Driver for OpenStack Manila."""

import datetime
import hashlib
import inspect
import logging
import os
import re

from oslo_config import cfg
from oslo_log import log
import six

from manila import exception
from manila.i18n import _
from manila.i18n import _LI
from manila.share import driver
from manila.share.drivers.hp import hp_3par_mediator
from manila.share import share_types

HP3PAR_OPTS = [
    cfg.StrOpt('hp3par_api_url',
               default='',
               help="3PAR WSAPI Server Url like "
                    "https://<3par ip>:8080/api/v1"),
    cfg.StrOpt('hp3par_username',
               default='',
               help="3PAR username with the 'edit' role"),
    cfg.StrOpt('hp3par_password',
               default='',
               help="3PAR password for the user specified in hp3par_username",
               secret=True),
    cfg.StrOpt('hp3par_san_ip',
               default='',
               help="IP address of SAN controller"),
    cfg.StrOpt('hp3par_san_login',
               default='',
               help="Username for SAN controller"),
    cfg.StrOpt('hp3par_san_password',
               default='',
               help="Password for SAN controller",
               secret=True),
    cfg.IntOpt('hp3par_san_ssh_port',
               default=22,
               help='SSH port to use with SAN'),
    cfg.StrOpt('hp3par_fpg',
               default="OpenStack",
               help="The File Provisioning Group (FPG) to use"),
    cfg.StrOpt('hp3par_share_ip_address',
               default='',
               help="The IP address for shares not using a share server"),
    cfg.BoolOpt('hp3par_fstore_per_share',
                default=False,
                help="Use one filestore per share"),
    cfg.BoolOpt('hp3par_debug',
                default=False,
                help="Enable HTTP debugging to 3PAR"),
]

CONF = cfg.CONF
CONF.register_opts(HP3PAR_OPTS)

LOG = log.getLogger(__name__)


class HP3ParShareDriver(driver.ShareDriver):
    """HP 3PAR driver for Manila.

     Supports NFS and CIFS protocols on arrays with File Persona.
     """

    VERSION = "1.0.01"

    def __init__(self, *args, **kwargs):
        super(HP3ParShareDriver, self).__init__(False, *args, **kwargs)

        self.configuration = kwargs.get('configuration', None)
        self.configuration.append_config_values(HP3PAR_OPTS)
        self.configuration.append_config_values(driver.ssh_opts)
        self.fpg = None
        self.vfs = None
        self.share_ip_address = None
        self._hp3par = None  # mediator between driver and client

    def do_setup(self, context):
        """Any initialization the share driver does while starting."""

        LOG.info(_LI("Starting share driver %(driver_name)s (%(version)s)"),
                 {'driver_name': self.__class__.__name__,
                  'version': self.VERSION})

        self.share_ip_address = self.configuration.hp3par_share_ip_address
        if not self.share_ip_address:
            raise exception.HP3ParInvalid(
                _("Unsupported configuration.  "
                  "hp3par_share_ip_address is not set."))

        mediator = hp_3par_mediator.HP3ParMediator(
            hp3par_username=self.configuration.hp3par_username,
            hp3par_password=self.configuration.hp3par_password,
            hp3par_api_url=self.configuration.hp3par_api_url,
            hp3par_debug=self.configuration.hp3par_debug,
            hp3par_san_ip=self.configuration.hp3par_san_ip,
            hp3par_san_login=self.configuration.hp3par_san_login,
            hp3par_san_password=self.configuration.hp3par_san_password,
            hp3par_san_ssh_port=self.configuration.hp3par_san_ssh_port,
            hp3par_fstore_per_share=self.configuration.hp3par_fstore_per_share,
            ssh_conn_timeout=self.configuration.ssh_conn_timeout,
        )

        mediator.do_setup()

        # FPG must be configured and must exist.
        self.fpg = self.configuration.safe_get('hp3par_fpg')
        # Validate the FPG and discover the VFS
        # This also validates the client, connection, firmware, WSAPI, FPG...
        self.vfs = mediator.get_vfs_name(self.fpg)

        # Don't set _hp3par until it is ready. Otherwise _update_stats fails.
        self._hp3par = mediator

    def check_for_setup_error(self):

        try:
            # Log the source SHA for support.  Only do this with DEBUG.
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug('HP3ParShareDriver SHA1: %s',
                          self.sha1_hash(HP3ParShareDriver))
                LOG.debug('HP3ParMediator SHA1: %s',
                          self.sha1_hash(hp_3par_mediator.HP3ParMediator))
        except Exception as e:
            # Don't let any exceptions during the SHA1 logging interfere
            # with startup.  This is just debug info to identify the source
            # code.  If it doesn't work, just log a debug message.
            LOG.debug('Source code SHA1 not logged due to: %s',
                      six.text_type(e))

    @staticmethod
    def sha1_hash(clazz):
        """Get the SHA1 hash for the source of a class."""
        source_file = inspect.getsourcefile(clazz)
        file_size = os.path.getsize(source_file)

        sha1 = hashlib.sha1()
        sha1.update(("blob %u\0" % file_size).encode('utf-8'))

        with open(source_file, 'rb') as f:
            sha1.update(f.read())

        return sha1.hexdigest()

    @staticmethod
    def _build_export_location(protocol, ip, path):
        if protocol == 'NFS':
            location = ':'.join((ip, path))
        elif protocol == 'CIFS':
            location = '\\\\%s\%s' % (ip, path)
        else:
            message = _('Invalid protocol. Expected NFS or CIFS. '
                        'Got %s.') % protocol
            raise exception.InvalidInput(message)
        return location

    @staticmethod
    def build_share_comment(share):
        """Create an informational only comment to help admins and testers."""

        info = {
            'name': share['display_name'],
            'host': share['host'],
            'now': datetime.datetime.now().strftime('%H%M%S'),
        }

        acceptable = re.compile('[^a-zA-Z0-9_=:@# \-]+', re.UNICODE)
        comment = ("OpenStack Manila - host=%(host)s  orig_name=%(name)s "
                   "created=%(now)s" % info)

        return acceptable.sub('_', comment)[:254]  # clean and truncate

    def create_share(self, context, share, share_server=None):
        """Is called to create share."""

        ip = self.share_ip_address

        protocol = share['share_proto']
        extra_specs = share_types.get_extra_specs_from_share(share)

        path = self._hp3par.create_share(
            share['project_id'],
            share['id'],
            protocol,
            extra_specs,
            self.fpg, self.vfs,
            size=share['size'],
            comment=self.build_share_comment(share)
        )

        return self._build_export_location(protocol, ip, path)

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None):
        """Is called to create share from snapshot."""

        ip = self.share_ip_address

        protocol = share['share_proto']
        extra_specs = share_types.get_extra_specs_from_share(share)

        path = self._hp3par.create_share_from_snapshot(
            share['id'],
            protocol,
            extra_specs,
            snapshot['share']['project_id'],
            snapshot['share']['id'],
            snapshot['share']['share_proto'],
            snapshot['id'],
            self.fpg,
            self.vfs,
            comment=self.build_share_comment(share)
        )

        return self._build_export_location(protocol, ip, path)

    def delete_share(self, context, share, share_server=None):
        """Deletes share and its fstore."""

        self._hp3par.delete_share(share['project_id'],
                                  share['id'],
                                  share['share_proto'],
                                  self.fpg,
                                  self.vfs)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot of a share."""

        self._hp3par.create_snapshot(snapshot['share']['project_id'],
                                     snapshot['share']['id'],
                                     snapshot['share']['share_proto'],
                                     snapshot['id'],
                                     self.fpg,
                                     self.vfs)

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot of a share."""

        self._hp3par.delete_snapshot(snapshot['share']['project_id'],
                                     snapshot['share']['id'],
                                     snapshot['share']['share_proto'],
                                     snapshot['id'],
                                     self.fpg,
                                     self.vfs)

    def ensure_share(self, context, share, share_server=None):
        pass

    def allow_access(self, context, share, access, share_server=None):
        """Allow access to the share."""
        self._hp3par.allow_access(share['project_id'],
                                  share['id'],
                                  share['share_proto'],
                                  access['access_type'],
                                  access['access_to'],
                                  self.fpg,
                                  self.vfs)

    def deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""
        self._hp3par.deny_access(share['project_id'],
                                 share['id'],
                                 share['share_proto'],
                                 access['access_type'],
                                 access['access_to'],
                                 self.fpg,
                                 self.vfs)

    def _update_share_stats(self):
        """Retrieve stats info from share group."""

        backend_name = self.configuration.safe_get(
            'share_backend_name') or "HP_3PAR"

        max_over_subscription_ratio = self.configuration.safe_get(
            'max_over_subscription_ratio')

        reserved_share_percentage = self.configuration.safe_get(
            'reserved_share_percentage')
        if reserved_share_percentage is None:
            reserved_share_percentage = 0

        stats = {
            'share_backend_name': backend_name,
            'driver_handles_share_servers': self.driver_handles_share_servers,
            'vendor_name': 'HP',
            'driver_version': self.VERSION,
            'storage_protocol': 'NFS_CIFS',
            'total_capacity_gb': 0,
            'free_capacity_gb': 0,
            'provisioned_capacity_gb': 0,
            'reserved_percentage': reserved_share_percentage,
            'max_over_subscription_ratio': max_over_subscription_ratio,
            'QoS_support': False,
            'thin_provisioning': True,  # 3PAR default is thin
        }

        if not self._hp3par:
            LOG.info(
                _LI("Skipping capacity and capabilities update. Setup has not "
                    "completed."))
        else:
            fpg_status = self._hp3par.get_fpg_status(self.fpg)
            LOG.debug("FPG status = %s.", fpg_status)
            stats.update(fpg_status)

        super(HP3ParShareDriver, self)._update_share_stats(stats)
