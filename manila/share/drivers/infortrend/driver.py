# Copyright (c) 2019 Infortrend Technology, Inc.
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

from oslo_config import cfg
from oslo_log import log

from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share.drivers.infortrend import infortrend_nas

LOG = log.getLogger(__name__)

infortrend_nas_opts = [
    cfg.HostAddressOpt('infortrend_nas_ip',
                       required=True,
                       help='Infortrend NAS IP for management.'),
    cfg.StrOpt('infortrend_nas_user',
               default='manila',
               help='User for the Infortrend NAS server.'),
    cfg.StrOpt('infortrend_nas_password',
               default=None,
               secret=True,
               help='Password for the Infortrend NAS server. '
               'This is not necessary '
               'if infortrend_nas_ssh_key is set.'),
    cfg.StrOpt('infortrend_nas_ssh_key',
               default=None,
               help='SSH key for the Infortrend NAS server. '
               'This is not necessary '
               'if infortrend_nas_password is set.'),
    cfg.ListOpt('infortrend_share_pools',
                required=True,
                help='Comma separated list of Infortrend NAS pools.'),
    cfg.ListOpt('infortrend_share_channels',
                required=True,
                help='Comma separated list of Infortrend channels.'),
    cfg.IntOpt('infortrend_ssh_timeout',
               default=30,
               help='SSH timeout in seconds.'),
]

CONF = cfg.CONF
CONF.register_opts(infortrend_nas_opts)


class InfortrendNASDriver(driver.ShareDriver):

    """Infortrend Share Driver for GS/GSe Family using NASCLI.

    Version history:
        1.0.0 - Initial driver
    """

    VERSION = "1.0.0"
    PROTOCOL = "NFS_CIFS"

    def __init__(self, *args, **kwargs):
        super(InfortrendNASDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(infortrend_nas_opts)

        nas_ip = self.configuration.safe_get('infortrend_nas_ip')
        username = self.configuration.safe_get('infortrend_nas_user')
        password = self.configuration.safe_get('infortrend_nas_password')
        ssh_key = self.configuration.safe_get('infortrend_nas_ssh_key')
        timeout = self.configuration.safe_get('infortrend_ssh_timeout')
        self.backend_name = self.configuration.safe_get('share_backend_name')

        if not (password or ssh_key):
            msg = _('Either infortrend_nas_password or infortrend_nas_ssh_key '
                    'should be set.')
            raise exception.InvalidParameterValue(err=msg)

        pool_dict = self._init_pool_dict()
        channel_dict = self._init_channel_dict()
        self.ift_nas = infortrend_nas.InfortrendNAS(nas_ip, username, password,
                                                    ssh_key, timeout,
                                                    pool_dict, channel_dict)

    def _init_pool_dict(self):
        pools_names = self.configuration.safe_get('infortrend_share_pools')

        return {el: {} for el in pools_names}

    def _init_channel_dict(self):
        channels = self.configuration.safe_get('infortrend_share_channels')

        return {el: '' for el in channels}

    def do_setup(self, context):
        """Any initialization the share driver does while starting."""
        LOG.debug('Infortrend NAS do_setup start.')
        self.ift_nas.do_setup()

    def check_for_setup_error(self):
        """Check for setup error."""
        LOG.debug('Infortrend NAS check_for_setup_error start.')
        self.ift_nas.check_for_setup_error()

    def _update_share_stats(self):
        """Retrieve stats info from share group."""

        LOG.debug('Updating Infortrend backend [%s].', self.backend_name)

        data = dict(
            share_backend_name=self.backend_name,
            vendor_name='Infortrend',
            driver_version=self.VERSION,
            storage_protocol=self.PROTOCOL,
            reserved_percentage=self.configuration.reserved_share_percentage,
            reserved_snapshot_percentage=(
                self.configuration.reserved_share_from_snapshot_percentage
                or self.configuration.reserved_share_percentage),
            reserved_share_extend_percentage=(
                self.configuration.reserved_share_extend_percentage
                or self.configuration.reserved_share_percentage),
            pools=self.ift_nas.update_pools_stats())
        LOG.debug('Infortrend pools status: %s', data['pools'])

        super(InfortrendNASDriver, self)._update_share_stats(data)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access rules for given share.

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

        return self.ift_nas.update_access(share, access_rules, add_rules,
                                          delete_rules, share_server)

    def create_share(self, context, share, share_server=None):
        """Create a share."""

        LOG.debug('Creating share: %s.', share['id'])

        return self.ift_nas.create_share(share, share_server)

    def delete_share(self, context, share, share_server=None):
        """Remove a share."""

        LOG.debug('Deleting share: %s.', share['id'])

        return self.ift_nas.delete_share(share, share_server)

    def get_pool(self, share):
        """Return pool name where the share resides on.

        :param share: The share hosted by the driver.
        """
        return self.ift_nas.get_pool(share)

    def ensure_share(self, context, share, share_server=None):
        """Invoked to ensure that share is exported.

        Driver can use this method to update the list of export locations of
        the share if it changes. To do that, you should return list with
        export locations.

        :return None or list with export locations
        """
        return self.ift_nas.ensure_share(share, share_server)

    def manage_existing(self, share, driver_options):
        """Brings an existing share under Manila management.

        If the provided share is not valid, then raise a
        ManageInvalidShare exception, specifying a reason for the failure.

        If the provided share is not in a state that can be managed, such as
        being replicated on the backend, the driver *MUST* raise
        ManageInvalidShare exception with an appropriate message.

        The share has a share_type, and the driver can inspect that and
        compare against the properties of the referenced backend share.
        If they are incompatible, raise a
        ManageExistingShareTypeMismatch, specifying a reason for the failure.

        :param share: Share model
        :param driver_options: Driver-specific options provided by admin.
        :return: share_update dictionary with required key 'size',
                 which should contain size of the share.
        """
        LOG.debug(
            'Manage existing for share: %(share)s,', {
                'share': share['share_id'],
            })
        return self.ift_nas.manage_existing(share, driver_options)

    def unmanage(self, share):
        """Removes the specified share from Manila management.

        Does not delete the underlying backend share.

        For most drivers, this will not need to do anything.  However, some
        drivers might use this call as an opportunity to clean up any
        Manila-specific configuration that they have associated with the
        backend share.

        If provided share cannot be unmanaged, then raise an
        UnmanageInvalidShare exception, specifying a reason for the failure.

        This method is invoked when the share is being unmanaged with
        a share type that has ``driver_handles_share_servers``
        extra-spec set to False.
        """
        LOG.debug(
            'Unmanage share: %(share)s', {
                'share': share['share_id'],
            })
        return self.ift_nas.unmanage(share)

    def extend_share(self, share, new_size, share_server=None):
        """Extends size of existing share.

        :param share: Share model
        :param new_size: New size of share (new_size > share['size'])
        :param share_server: Optional -- Share server model
        """
        return self.ift_nas.extend_share(share, new_size, share_server)

    def shrink_share(self, share, new_size, share_server=None):
        """Shrinks size of existing share.

        If consumed space on share larger than new_size driver should raise
        ShareShrinkingPossibleDataLoss exception:
        raise ShareShrinkingPossibleDataLoss(share_id=share['id'])

        :param share: Share model
        :param new_size: New size of share (new_size < share['size'])
        :param share_server: Optional -- Share server model

        :raises ShareShrinkingPossibleDataLoss, NotImplementedError
        """
        return self.ift_nas.shrink_share(share, new_size, share_server)
