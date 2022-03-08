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
Shared File system services driver for Zadara
Virtual Private Storage Array (VPSA).
"""

import socket

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import strutils

from manila import exception as manila_exception
from manila.i18n import _
from manila.share import api
from manila.share import driver
from manila.share.drivers.zadara import common

CONF = cfg.CONF
CONF.register_opts(common.zadara_opts)

LOG = logging.getLogger(__name__)

manila_opts = [
    cfg.StrOpt('zadara_share_name_template',
               default='OS_share-%s',
               help='VPSA - Default template for VPSA share names'),
    cfg.StrOpt('zadara_share_snap_name_template',
               default='OS_share-snapshot-%s',
               help='VPSA - Default template for VPSA share names'),
    cfg.StrOpt('zadara_driver_ssl_cert_path',
               default=None,
               help='Can be used to specify a non default path to a '
                    'CA_BUNDLE file or directory with certificates '
                    'of trusted CAs, which will be used to validate '
                    'the backend')]


class ZadaraVPSAShareDriver(driver.ShareDriver):
    """Zadara VPSA Share driver.

    Version history::

        20.12-01 - Driver changes intended and aligned with
                   openstack latest release.
        20.12-02 - Fixed #18723 - Manila: Parsing the export location in a
                   more generic way while managing the vpsa share
        20.12-03 - Adding the metadata support while creating share to
                   configure vpsa.
        20.12-20 - IPv6 connectivity support for Manila driver
        20.12-21 - Adding unit tests and fixing review comments from the
                   openstack community.
        20.12-22 - Addressing review comments from the manila community.
        20.12-23 - Addressing review comments from the manila community.
        20.12-24 - Addressing review comments from the manila community.
        20.12-25 - Support host assisted share migration
    """

    VERSION = '20.12-25'

    # ThirdPartySystems wiki page
    CI_WIKI_NAME = "ZadaraStorage_VPSA_CI"

    def __init__(self, *args, **kwargs):
        """Do initialization."""
        super(ZadaraVPSAShareDriver, self).__init__(False, *args, **kwargs)
        self.vpsa = None
        self.configuration.append_config_values(common.zadara_opts)
        self.configuration.append_config_values(manila_opts)
        self.api = api.API()
        # The valid list of share options that can be specified
        # as the metadata while creating manila share
        self.share_options = ['smbguest', 'smbonly', 'smbwindowsacl',
                              'smbfilecreatemask', 'smbbrowseable',
                              'smbhiddenfiles', 'smbhideunreadable',
                              'smbhideunwriteable', 'smbhidedotfiles',
                              'smbstoredosattributes', 'smbdircreatemask',
                              'smbmaparchive', 'smbencryptionmode',
                              'smbenableoplocks', 'smbaiosize',
                              'nfsrootsquash', 'nfsallsquash',
                              'nfsanongid', 'nfsanonuid',
                              'atimeupdate', 'readaheadkb', 'crypt',
                              'compress', 'dedupe', 'attachpolicies']

    def _check_access_key_validity(self):
        try:
            self.vpsa._check_access_key_validity()
        except common.exception.ZadaraInvalidAccessKey:
            raise manila_exception.ZadaraManilaInvalidAccessKey()

    def do_setup(self, context):
        """Any initialization the share driver does while starting.

        Establishes initial connection with VPSA and retrieves access_key.
        Need to pass driver_ssl_cert_path here (and not fetch it from the
        config opts directly in common code), because this config option is
        different for different drivers and so cannot be figured in the
        common code.
        """
        driver_ssl_cert_path = self.configuration.zadara_driver_ssl_cert_path
        self.vpsa = common.ZadaraVPSAConnection(self.configuration,
                                                driver_ssl_cert_path, False)

    def check_for_setup_error(self):
        """Returns an error (exception) if prerequisites aren't met."""
        self._check_access_key_validity()

    def vpsa_send_cmd(self, cmd, **kwargs):
        try:
            response = self.vpsa.send_cmd(cmd, **kwargs)
        except common.exception.UnknownCmd as e:
            raise manila_exception.ZadaraUnknownCmd(cmd=e.cmd)
        except common.exception.SessionRequestException as e:
            raise manila_exception.ZadaraSessionRequestException(msg=e.msg)
        except common.exception.BadHTTPResponseStatus as e:
            raise manila_exception.ZadaraBadHTTPResponseStatus(status=e.status)
        except common.exception.FailedCmdWithDump as e:
            raise manila_exception.ZadaraFailedCmdWithDump(status=e.status,
                                                           data=e.data)
        except common.exception.ZadaraInvalidAccessKey:
            raise manila_exception.ZadaraManilaInvalidAccessKey()
        return response

    def _get_zadara_share_template_name(self, share_id):
        return self.configuration.zadara_share_name_template % share_id

    def _get_share_export_location(self, share):
        export_location = ''
        share_proto = share['share_proto'].upper()

        share_name = self._get_zadara_share_template_name(share['id'])
        vpsa_volume = self.vpsa._get_vpsa_volume(share_name)
        if not vpsa_volume:
            msg = (_('VPSA volume for share %s '
                     'could not be found.') % share['id'])
            LOG.error(msg)
            raise manila_exception.ZadaraShareNotFound(name=share['id'])

        if share_proto == 'NFS':
            export_location = vpsa_volume['nfs_export_path']
        if share_proto == 'CIFS':
            export_location = vpsa_volume['smb_export_path']
        return export_location

    def _check_share_protocol(self, share):
        share_proto = share['share_proto'].upper()
        if share_proto not in ('NFS', 'CIFS'):
            msg = _("Only NFS or CIFS protocol are currently supported. "
                    "Share provided %(share)s with protocol "
                    "%(proto)s.") % {'share': share['id'],
                                     'proto': share['share_proto']}
            LOG.error(msg)
            raise manila_exception.ZadaraInvalidProtocol(
                protocol_type=share_proto)

    def is_valid_metadata(self, metadata):
        LOG.debug('Metadata while creating share: %(metadata)s',
                  {'metadata': metadata})
        for key, value in metadata.items():
            if key in self.share_options:
                # Check for the values allowed with provided metadata
                if key in ['smbguest', 'smbonly', 'smbwindowsacl',
                           'smbbrowseable', 'smbhideunreadable',
                           'smbhideunwriteable', 'smbhidedotfiles',
                           'smbstoredosattributes', 'smbmaparchive',
                           'smbenableoplocks', 'nfsrootsquash',
                           'nfsallsquash', 'atimeupdate', 'crypt',
                           'compress', 'dedupe', 'attachpolicies']:
                    if value in ['YES', 'NO']:
                        continue
                    else:
                        return False
                if key in ['smbfilecreatemask', 'smbdircreatemask']:
                    if value.isdigit():
                        # The valid permissions should be for user,group,other
                        # with another special digit for attributes. Ex:0755
                        if len(value) != 4:
                            return False
                        # No special permission bits for suid,sgid,
                        # stickybit are allowed for vpsa share.
                        if int(value[0]) != 0:
                            return False
                        # The permissions are always specified in octal
                        for i in range(1, len(value)):
                            if int(value[i]) > 7:
                                return False
                        continue
                    else:
                        return False
                if key == 'smbaiosize':
                    if value.isdigit() and value in ['16384', '1']:
                        continue
                    else:
                        return False
                if key == 'smbencryptionmode':
                    if value in ['off', 'desired', 'required']:
                        continue
                    else:
                        return False
                if key in ['nfsanongid', 'nfsanonuid']:
                    if value.isdigit() and int(value) != 0:
                        continue
                    else:
                        return False
                if key == 'readaheadkb':
                    if value in ['16', '64', '128', '256', '512']:
                        continue
                    else:
                        return False
        return True

    def create_share(self, context, share, share_server=None):
        """Create a Zadara share and export it.

        :param context: A RequestContext.
        :param share: A Share.
        :param share_server: Not used currently
        :return: The export locations dictionary.
        """
        # Check share's protocol.
        # Throw an exception immediately if it is an invalid protocol.
        self._check_share_protocol(share)
        share_name = self._get_zadara_share_template_name(share['id'])

        # Collect the share metadata provided and validate it
        metadata = self.api.get_share_metadata(context,
                                               {'id': share['share_id']})
        if not self.is_valid_metadata(metadata):
            raise manila_exception.ManilaException(_(
                "Not a valid metadata provided for the share %s")
                % share['id'])

        data = self.vpsa_send_cmd('create_volume',
                                  name=share_name,
                                  size=share['size'],
                                  metadata=metadata)
        if data['status'] != 0:
            raise manila_exception.ZadaraVPSAVolumeShareFailed(
                error=data['status'])

        export_location = self._get_share_export_location(share)
        return {'path': export_location}

    def _allow_access(self, context, share, access):
        """Allow access to the share."""
        access_type = access['access_type']
        share_proto = share['share_proto'].upper()
        if share_proto == 'CIFS':
            share_proto = 'SMB'

        if access_type != 'ip':
            raise manila_exception.ZadaraInvalidShareAccessType()
        access_ip = access['access_to']
        access_level = 'YES'
        if access['access_level'] == 'rw':
            access_level = 'NO'

        # First: Check Active controller: if not valid, raise exception
        ctrl = self.vpsa._get_active_controller_details()
        if not ctrl:
            raise manila_exception.ZadaraVPSANoActiveController()

        # Get volume name
        vol_name = self._get_zadara_share_template_name(share['id'])
        vpsa_volume = self.vpsa._get_vpsa_volume(vol_name)

        if not vpsa_volume:
            msg = (_('VPSA volume for share %s '
                     'could not be found.') % share['id'])
            LOG.error(msg)
            raise manila_exception.ZadaraShareNotFound(name=share['id'])

        # Get/Create server name for given IP
        vpsa_srv = self.vpsa._create_vpsa_server(iscsi_ip=access_ip)
        if not vpsa_srv:
            raise manila_exception.ZadaraServerCreateFailure(name=access_ip)

        servers = self.vpsa._get_servers_attached_to_volume(vpsa_volume)
        attach = None
        for server in servers:
            if server == vpsa_srv:
                attach = server
                break
        # Attach volume to server
        if attach is None:
            self.vpsa_send_cmd('attach_volume',
                               vpsa_srv=vpsa_srv,
                               vpsa_vol=vpsa_volume['name'],
                               share_proto=share_proto,
                               read_only=access_level)

        data = self.vpsa_send_cmd('list_vol_attachments',
                                  vpsa_vol=vpsa_volume['name'])
        server = None
        servers = data.get('servers', [])
        for srv in servers:
            if srv['iscsi_ip'] == access_ip:
                server = srv
                break

        if server is None:
            raise manila_exception.ZadaraAttachmentsNotFound(
                name=vpsa_volume['name'])

        ctrl_ip = self.vpsa._get_target_host(ctrl['ip'])
        properties = {'target_discovered': False,
                      'target_portal': (('%s:%s') % (ctrl_ip, '3260')),
                      'target_ip': server['iscsi_ip'],
                      'id': share['id'],
                      'auth_method': 'CHAP',
                      'auth_username': ctrl['chap_user'],
                      'auth_password': ctrl['chap_passwd']}

        LOG.debug('Attach properties: %(properties)s',
                  {'properties': strutils.mask_password(properties)})
        return {'driver_volume_type': share['share_proto'], 'data': properties}

    def delete_share(self, context, share, share_server=None):
        """Delete share. Auto detach from all servers.

        """
        # Get share name
        share_name = self._get_zadara_share_template_name(share['id'])
        volume = self.vpsa._get_vpsa_volume(share_name)
        if not volume:
            LOG.warning('Volume %s could not be found. '
                        'It might be already deleted', share['id'])
            return

        self.vpsa._detach_vpsa_volume(vpsa_vol=volume)

        # Delete volume associate with the share
        self.vpsa_send_cmd('delete_volume', vpsa_vol=volume['name'])

    def _deny_access(self, context, share, access, share_server=None):
        """Deny access to the share from the host.

        """
        access_type = access['access_type']
        if access_type != 'ip':
            LOG.warning('Only ip access type is allowed for zadara vpsa.')
            return
        access_ip = access['access_to']

        # First: Check Active controller: if not valid, raise exception
        ctrl = self.vpsa._get_active_controller_details()
        if not ctrl:
            raise manila_exception.ZadaraVPSANoActiveController()

        # Get share name
        share_name = self._get_zadara_share_template_name(share['id'])
        volume = self.vpsa._get_vpsa_volume(share_name)
        if not volume:
            LOG.warning('Volume %s could not be found. '
                        'It might be already deleted', share['id'])
            return

        vpsa_srv = self.vpsa._get_server_name(access_ip, True)
        if not vpsa_srv:
            LOG.warning('VPSA server %s could not be found.', access_ip)
            return

        servers_list = self.vpsa._get_servers_attached_to_volume(volume)
        if vpsa_srv not in servers_list:
            LOG.warning('VPSA server %(access_ip)s not attached '
                        'to volume %(volume)s.',
                        {'access_ip': access_ip, 'volume': share['id']})
            return

        self.vpsa._detach_vpsa_volume(vpsa_vol=volume,
                                      vpsa_srv=vpsa_srv)

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        access_updates = {}
        if not (add_rules or delete_rules):
            # add_rules and delete_rules can be empty lists, in cases
            # like share migration for zadara driver, when the access
            # level is to be changed for all existing rules. For zadara
            # backend, we delete and re-add all the existing rules.
            for access_rule in access_rules:
                self._deny_access(context, share, access_rule)
                try:
                    self._allow_access(context, share, access_rule)
                except manila_exception.ZadaraInvalidShareAccessType:
                    LOG.error("Only ip access type allowed for Zadara share. "
                              "Failed to allow %(access_level)s access to "
                              "%(access_to)s for rule %(id)s. Setting rule "
                              "to 'error' state.",
                              {'access_level': access_rule['access_level'],
                               'access_to': access_rule['access_to'],
                               'id': access_rule['access_id']})
                    access_updates.update(
                        {access_rule['access_id']: {'state': 'error'}})
        else:
            if add_rules:
                # Add rules for accessing share
                for access_rule in add_rules:
                    try:
                        self._allow_access(context, share, access_rule)
                    except manila_exception.ZadaraInvalidShareAccessType:
                        LOG.error("Only ip access type allowed for Zadara "
                                  "share. Failed to allow %(access_level)s "
                                  "access to %(access_to)s for rule %(id)s. "
                                  "Setting rule to 'error' state.",
                                  {'access_level': access_rule['access_level'],
                                   'access_to': access_rule['access_to'],
                                   'id': access_rule['access_id']})
                        access_updates.update(
                            {access_rule['access_id']: {'state': 'error'}})
            if delete_rules:
                # Delete access rules for provided share
                for access_rule in delete_rules:
                    self._deny_access(context, share, access_rule)
        return access_updates

    def extend_share(self, share, new_size, share_server=None):
        """Extend an existing share.

        """
        # Get the backend volume name for the share
        share_name = self._get_zadara_share_template_name(share['id'])
        vpsa_volume = self.vpsa._get_vpsa_volume(share_name)
        if not vpsa_volume:
            msg = (_('VPSA volume for share %s '
                     'could not be found.') % share['id'])
            LOG.error(msg)
            raise manila_exception.ZadaraShareNotFound(name=share['id'])

        size = vpsa_volume['virtual_capacity']
        expand_size = new_size - size
        data = self.vpsa_send_cmd('expand_volume',
                                  vpsa_vol=vpsa_volume['name'],
                                  size=expand_size)
        if data['status'] != 0:
            raise manila_exception.ZadaraExtendShareFailed(
                error=data['status'])

    def _ensure_share(self, context, share, share_server=None):
        """Ensure that the share has a backend volume and it is exported.

        """
        # Get the backend volume name for the share
        share_name = self._get_zadara_share_template_name(share['id'])
        vpsa_volume = self.vpsa._get_vpsa_volume(share_name)
        if not vpsa_volume:
            msg = (_('VPSA volume for share %s '
                     'could not be found.') % share['id'])
            LOG.error(msg)
            raise manila_exception.ZadaraShareNotFound(name=share['id'])

        export_locations = share['export_locations']
        if export_locations:
            return export_locations
        else:
            servers_list = (self.vpsa._get_servers_attached_to_volume(
                            vpsa_volume))
            if len(servers_list) != 0:
                msg = (_('Servers attached to the VPSA volume %s without '
                         'any locations exported.') % vpsa_volume['name'])
                LOG.error(msg)
                raise manila_exception.ZadaraShareNotValid(
                    name=share['id'])

    def _update_share_stats(self):

        backend_name = self.configuration.share_backend_name
        dhss = self.configuration.driver_handles_share_servers
        vpsa_poolname = self.configuration.zadara_vpsa_poolname
        (total, free, provisioned) = (
            self.vpsa._get_pool_capacity(vpsa_poolname))
        ctrl = self.vpsa._get_active_controller_details()
        if not ctrl:
            raise manila_exception.ZadaraVPSANoActiveController()
        ipv4_support = False if ':' in ctrl['ip'] else True

        # VPSA backend pool
        single_pool = dict(
            pool_name=vpsa_poolname,
            total_capacity_gb=total,
            free_capacity_gb=free,
            allocated_capacity_gb=(total - free),
            provisioned_capacity_gb=provisioned,
            reserved_percentage=self.configuration.reserved_share_percentage,
            reserved_snapshot_percentage=(
                self.configuration.reserved_share_from_snapshot_percentage
                or self.configuration.reserved_share_percentage),
            reserved_share_extend_percentage=(
                self.configuration.reserved_share_extend_percentage
                or self.configuration.reserved_share_percentage),
            compression=[True, False],
            dedupe=[True, False],
            thin_provisioning=True
        )

        data = dict(
            share_backend_name=backend_name,
            driver_handles_share_servers=dhss,
            vendor_name='Zadara Storage',
            driver_version=self.VERSION,
            storage_protocol='NFS_CIFS',
            pools=[single_pool],
            snapshot_support=True,
            create_share_from_snapshot_support=True,
            revert_to_snapshot_support=False,
            mount_snapshot_support=False,
            ipv4_support=ipv4_support,
            ipv6_support=not ipv4_support
        )
        super(ZadaraVPSAShareDriver, self)._update_share_stats(data)

    def create_snapshot(self, context, snapshot, share_server=None):
        """Creates a snapshot."""
        LOG.debug('Create snapshot: %s', snapshot['id'])

        # Retrieve the CG name for the base volume
        share = snapshot['share']
        volume_name = self._get_zadara_share_template_name(share['id'])
        cg_name = self.vpsa._get_volume_cg_name(volume_name)
        if not cg_name:
            msg = (_('VPSA volume for share %s '
                     'could not be found.') % share['id'])
            LOG.error(msg)
            raise manila_exception.ZadaraShareNotFound(name=share['id'])

        snap_name = (self.configuration.zadara_share_snap_name_template
                     % snapshot['id'])
        data = self.vpsa_send_cmd('create_snapshot',
                                  cg_name=cg_name,
                                  snap_name=snap_name)
        if data['status'] != 0:
            raise manila_exception.ZadaraVPSASnapshotCreateFailed(
                name=share['id'], error=data['status'])

        return {'provider_location': data['snapshot_name']}

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot."""
        LOG.debug('Delete snapshot: %s', snapshot['id'])

        # Retrieve the CG name for the base volume
        share = snapshot['share']
        volume_name = self._get_zadara_share_template_name(share['id'])
        cg_name = self.vpsa._get_volume_cg_name(volume_name)
        if not cg_name:
            # If the volume isn't present, then don't attempt to delete
            LOG.warning('snapshot: original volume %s not found, '
                        'skipping delete operation',
                        volume_name)
            return

        snap_name = (self.configuration.zadara_share_snap_name_template
                     % snapshot['id'])
        snap_id = self.vpsa._get_snap_id(cg_name, snap_name)
        if not snap_id:
            # If the snapshot isn't present, then don't attempt to delete
            LOG.warning('snapshot: snapshot %s not found, '
                        'skipping delete operation', snap_name)
            return

        self.vpsa_send_cmd('delete_snapshot',
                           snap_id=snap_id)

    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None, parent_share=None):
        """Creates a share from a snapshot.

        """
        LOG.debug('Creating share from snapshot: %s', snapshot['id'])

        # Retrieve the CG name for the base volume
        volume_name = (self._get_zadara_share_template_name(
                       snapshot['share_instance_id']))
        cg_name = self.vpsa._get_volume_cg_name(volume_name)
        if not cg_name:
            msg = (_('VPSA volume for share %s '
                     'could not be found.') % share['id'])
            LOG.error(msg)
            raise manila_exception.ZadaraShareNotFound(name=share['id'])

        snap_name = (self.configuration.zadara_share_snap_name_template
                     % snapshot['id'])
        snap_id = self.vpsa._get_snap_id(cg_name, snap_name)
        if not snap_id:
            msg = _('Snapshot %(name)s not found') % {'name': snap_name}
            LOG.error(msg)
            raise manila_exception.ShareSnapshotNotFound(
                snapshot_id=snap_name)

        self._check_share_protocol(share)

        share_name = self._get_zadara_share_template_name(share['id'])
        self.vpsa_send_cmd('create_clone_from_snap',
                           cg_name=cg_name,
                           name=share_name,
                           snap_id=snap_id)

        if share['size'] > snapshot['size']:
            self.extend_share(share, share['size'])

        export_location = self._get_share_export_location(share)
        return [{'path': export_location}]

    def _get_export_name_from_export_path(self, proto, export_path):
        if proto == 'nfs' and '\\' in export_path:
            return None
        if proto == 'cifs' and '/' in export_path:
            return None

        # Extract the export name from the provided export path
        if proto == 'nfs':
            separator = '/'
            export_location = export_path.strip(separator)
            export_name = export_location.split(separator)[-1]
        else:
            separator = '\\'
            export_location = export_path.strip(separator)
            export_name = export_location.split(separator)[-1]
        return export_name

    def _extract_vpsa_volume_from_share(self, share):
        """Returns a vpsa volume based on the export location"""
        if not share['export_locations'][0]['path']:
            return None

        share_proto = share['share_proto'].lower()
        export_path = share['export_locations'][0]['path']
        export_name = self._get_export_name_from_export_path(share_proto,
                                                             export_path)
        if export_name is None:
            msg = (_('Please verify the specifed protocol and export path.'))
            LOG.error(msg)
            raise manila_exception.ManilaException(msg)

        volume = None
        volumes = self.vpsa._get_all_vpsa_volumes()
        # Find the volume with the corresponding export name
        for vol in volumes:
            if share_proto == 'nfs':
                vol_export_path = vol.get('nfs_export_path', None)
            else:
                vol_export_path = vol.get('smb_export_path', None)

            vol_export_name = self._get_export_name_from_export_path(
                share_proto, vol_export_path)
            if export_name == vol_export_name:
                volume = vol
                break

            # Check the additional smb export paths of the volume
            if (share_proto == 'cifs' and
                    vol['additional_smb_export_paths_count'] > 0):
                for additional_path in vol['additional_smb_export_paths']:
                    vol_export_name = self._get_export_name_from_export_path(
                        share_proto, additional_path)
                    if export_name == vol_export_name:
                        volume = vol
                        break
        if volume:
            return volume
        else:
            msg = (_('Manage backend share could not be found. It might be '
                     'deleted or please verify the specifed protocol and '
                     'export path.'))
            LOG.error(msg)
            raise manila_exception.ManilaException(msg)

    def manage_existing(self, share, driver_options):
        # Check whether the specified protocol is supported or not.
        self._check_share_protocol(share)

        LOG.info("Share %(shr_path)s will be managed with share %(shr_name)s.",
                 {'shr_path': share['export_locations'][0]['path'],
                  'shr_name': share['id']})

        # Find the backend vpsa volume for the provided export location
        vpsa_volume = self._extract_vpsa_volume_from_share(share)

        # Check if the volume is available
        if vpsa_volume['status'] != 'Available':
            msg = (_('Existing share %(name)s is not available')
                   % {'name': vpsa_volume['name']})
            LOG.error(msg)
            raise manila_exception.ManilaException(msg)

        new_share_name = self._get_zadara_share_template_name(share['id'])
        new_vpsa_share = self.vpsa._get_vpsa_volume(new_share_name)
        if new_vpsa_share:
            msg = (_('Share %(new_name)s already exists')
                   % {'new_name': new_share_name})
            LOG.error(msg)
            raise manila_exception.ManilaException(msg)

        # Rename the volume to the manila share specified name
        data = self.vpsa_send_cmd('rename_volume',
                                  vpsa_vol=vpsa_volume['name'],
                                  new_name=new_share_name)
        if data['status'] != 0:
            msg = (_('Renaming volume %(old_name)s to %(new_name)s '
                     'has failed.') % {'old_name': vpsa_volume['name'],
                                       'new_name': new_share_name})
            LOG.error(msg)
            raise manila_exception.ManilaException(msg)

        return {'size': vpsa_volume['provisioned_capacity'],
                'export_locations': share['export_locations'][0]['path']}

    def unmanage(self, share):
        """Removes the specified volume from Manila management"""
        pass

    def manage_existing_snapshot(self, snapshot, driver_options):
        share = snapshot['share']
        share_name = self._get_zadara_share_template_name(share['id'])

        vpsa_volume = self.vpsa._get_vpsa_volume(share_name)
        if not vpsa_volume:
            msg = (_('Volume %(name)s could not be found. '
                     'It might be already deleted') % {'name': share_name})
            LOG.error(msg)
            raise manila_exception.ZadaraShareNotFound(name=share['id'])

        # Check if the provider_location is specified
        if not snapshot['provider_location']:
            msg = (_('Provider location as snap id of the VPSA backend '
                     'should be provided'))
            LOG.error(msg)
            raise manila_exception.ManilaException(msg)

        new_name = (self.configuration.zadara_share_snap_name_template
                    % snapshot['id'])
        new_snap_id = self.vpsa._get_snap_id(vpsa_volume['cg_name'],
                                             new_name)
        if new_snap_id:
            msg = (_('Snapshot with name %s already exists') % new_name)
            LOG.debug(msg)
            return

        data = self.vpsa_send_cmd('rename_snapshot',
                                  snap_id=snapshot['provider_location'],
                                  new_name=new_name)
        if data['status'] != 0:
            raise manila_exception.ZadaraVPSASnapshotManageFailed(
                snap_id=snapshot['provider_location'],
                error=data['status'])

    def unmanage_snapshot(self, snapshot):
        """Removes the specified snapshot from Manila management"""
        pass

    def get_configured_ip_versions(self):
        """"Get allowed IP versions.

        The shares created should have export location as per the
        IP version. Currently, zadara backend doesn't support both
        ipv4 and ipv6. Collect the supported IP version from the
        vpsa's active controller
        """
        ctrl = self.vpsa._get_active_controller_details()
        if not ctrl:
            raise manila_exception.ZadaraVPSANoActiveController()

        if ':' in ctrl['ip']:
            return [6]
        else:
            return [4]

    def get_backend_info(self, context):
        return {
            'version': self.VERSION,
            'vsa_feip': socket.gethostbyname(self.vpsa.conf.zadara_vpsa_host),
            'vsa_port': self.vpsa.conf.zadara_vpsa_port
        }

    def ensure_shares(self, context, shares):
        updates = {}
        for share in shares:
            updates[share['id']] = {
                'export_locations': self._ensure_share(context, share)}
        return updates
