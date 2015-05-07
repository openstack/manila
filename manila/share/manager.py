# Copyright (c) 2014 NetApp Inc.
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
"""NAS share manager managers creating shares and access rights.

**Related Flags**

:share_driver: Used by :class:`ShareManager`.
"""

import datetime

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import timeutils
import six

from manila.common import constants
from manila import context
from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LI
from manila.i18n import _LW
from manila import manager
from manila import quota
import manila.share.configuration
from manila.share import utils as share_utils
from manila import utils

LOG = log.getLogger(__name__)

share_manager_opts = [
    cfg.StrOpt('share_driver',
               default='manila.share.drivers.generic.GenericShareDriver',
               help='Driver to use for share creation.'),
    cfg.BoolOpt('delete_share_server_with_last_share',
                default=False,
                help='Whether share servers will '
                     'be deleted on deletion of the last share.'),
    cfg.BoolOpt('unmanage_remove_access_rules',
                default=False,
                help='If set to True, then manila will deny access and remove '
                     'all access rules on share unmanage.'
                     'If set to False - nothing will be changed.'),
    cfg.BoolOpt('automatic_share_server_cleanup',
                default=True,
                help='If set to True, then Manila will delete all share '
                     'servers which were unused more than specified time .'
                     'If set to False - automatic deletion of share servers '
                     'will be disabled.',
                deprecated_group='DEFAULT'),
    cfg.IntOpt('unused_share_server_cleanup_interval',
               default=10,
               help='Unallocated share servers reclamation time interval '
                    '(minutes). Minimum value is 10 minutes, maximum is 60 '
                    'minutes. The reclamation function is run every '
                    '10 minutes and delete share servers which were unused '
                    'more than unused_share_server_cleanup_interval option '
                    'defines. This value reflects the shortest time Manila '
                    'will wait for a share server to go unutilized before '
                    'deleting it.',
               deprecated_group='DEFAULT'),
]

CONF = cfg.CONF
CONF.register_opts(share_manager_opts)

# Drivers that need to change module paths or class names can add their
# old/new path here to maintain backward compatibility.
MAPPING = {
    'manila.share.drivers.netapp.cluster_mode.NetAppClusteredShareDriver':
    'manila.share.drivers.netapp.common.NetAppDriver', }

QUOTAS = quota.QUOTAS


class ShareManager(manager.SchedulerDependentManager):
    """Manages NAS storages."""

    RPC_API_VERSION = '1.1'

    def __init__(self, share_driver=None, service_name=None, *args, **kwargs):
        """Load the driver from args, or from flags."""
        self.configuration = manila.share.configuration.Configuration(
            share_manager_opts,
            config_group=service_name)
        self._verify_unused_share_server_cleanup_interval()
        super(ShareManager, self).__init__(service_name='share',
                                           *args, **kwargs)

        if not share_driver:
            share_driver = self.configuration.share_driver
        if share_driver in MAPPING:
            msg_args = {'old': share_driver, 'new': MAPPING[share_driver]}
            LOG.warning(_LW("Driver path %(old)s is deprecated, update your "
                            "configuration to the new path %(new)s"),
                        msg_args)
            share_driver = MAPPING[share_driver]

        self.driver = importutils.import_object(
            share_driver, configuration=self.configuration)

    def _ensure_share_has_pool(self, ctxt, share):
        pool = share_utils.extract_host(share['host'], 'pool')
        if pool is None:
            # No pool name encoded in host, so this is a legacy
            # share created before pool is introduced, ask
            # driver to provide pool info if it has such
            # knowledge and update the DB.
            try:
                pool = self.driver.get_pool(share)
            except Exception as err:
                LOG.error(_LE("Failed to fetch pool name for share: "
                              "%(share)s. Error: %(error)s."),
                          {'share': share['id'], 'error': err})
                return

            if pool:
                new_host = share_utils.append_host(share['host'], pool)
                self.db.share_update(ctxt, share['id'], {'host': new_host})

        return pool

    def init_host(self):
        """Initialization for a standalone service."""

        ctxt = context.get_admin_context()
        self.driver.do_setup(ctxt)
        self.driver.check_for_setup_error()

        shares = self.db.share_get_all_by_host(ctxt, self.host)
        LOG.debug("Re-exporting %s shares", len(shares))
        for share in shares:
            if share['status'] != 'available':
                LOG.info(
                    _LI("Share %(name)s: skipping export, because it has "
                        "'%(status)s' status."),
                    {'name': share['name'], 'status': share['status']},
                )
                continue

            self._ensure_share_has_pool(ctxt, share)
            share_server = self._get_share_server(ctxt, share)
            try:
                export_locations = self.driver.ensure_share(
                    ctxt, share, share_server=share_server)
            except Exception as e:
                LOG.error(
                    _LE("Caught exception trying ensure share '%(s_id)s'. "
                        "Exception: \n%(e)s."),
                    {'s_id': share['id'], 'e': six.text_type(e)},
                )
                continue

            if export_locations:
                self.db.share_export_locations_update(
                    ctxt, share['id'], export_locations)

            rules = self.db.share_access_get_all_for_share(ctxt, share['id'])
            for access_ref in rules:
                if access_ref['state'] != access_ref.STATE_ACTIVE:
                    continue

                try:
                    self.driver.allow_access(ctxt, share, access_ref,
                                             share_server=share_server)
                except exception.ShareAccessExists:
                    pass
                except Exception as e:
                    LOG.error(
                        _LE("Unexpected exception during share access"
                            " allow operation. Share id is '%(s_id)s'"
                            ", access rule type is '%(ar_type)s', "
                            "access rule id is '%(ar_id)s', exception"
                            " is '%(e)s'."),
                        {'s_id': share['id'],
                         'ar_type': access_ref['access_type'],
                         'ar_id': access_ref['id'],
                         'e': six.text_type(e)},
                    )

        self.publish_service_capabilities(ctxt)

    def _provide_share_server_for_share(self, context, share_network_id,
                                        share_id):
        """Gets or creates share_server and updates share with its id.

        Active share_server can be deleted if there are no dependent shares
        on it.
        So we need avoid possibility to delete share_server in time gap
        between reaching active state for share_server and setting up
        share_server_id for share. It is possible, for example, with first
        share creation, which starts share_server creation.
        For this purpose used shared lock between this method and the one
        with deletion of share_server.

        :returns: dict, dict -- first value is share_server, that
                  has been chosen for share schedule. Second value is
                  share updated with share_server_id.
        """

        @utils.synchronized("share_manager_%s" % share_network_id)
        def _provide_share_server_for_share():
            exist = False
            try:
                share_server = \
                    self.db.share_server_get_by_host_and_share_net_valid(
                        context, self.host, share_network_id)
                exist = True
            except exception.ShareServerNotFound:
                share_server = self.db.share_server_create(
                    context,
                    {
                        'host': self.host,
                        'share_network_id': share_network_id,
                        'status': constants.STATUS_CREATING
                    }
                )

            LOG.debug("Using share_server %s for share %s" % (
                share_server['id'], share_id))
            share_ref = self.db.share_update(
                context,
                share_id,
                {'share_server_id': share_server['id']},
            )

            if not exist:
                # Create share server on backend with data from db
                share_server = self._setup_server(context, share_server)
                LOG.info(_LI("Share server created successfully."))
            else:
                LOG.info(_LI("Used already existed share server "
                             "'%(share_server_id)s'"),
                         {'share_server_id': share_server['id']})
            return share_server, share_ref

        return _provide_share_server_for_share()

    def _get_share_server(self, context, share):
        if share['share_server_id']:
            return self.db.share_server_get(
                context, share['share_server_id'])
        else:
            return None

    def create_share(self, context, share_id, request_spec=None,
                     filter_properties=None, snapshot_id=None):
        """Creates a share."""
        context = context.elevated()
        if filter_properties is None:
            filter_properties = {}

        share_ref = self.db.share_get(context, share_id)
        share_network_id = share_ref.get('share_network_id', None)

        if share_network_id and not self.driver.driver_handles_share_servers:
            self.db.share_update(context, share_id, {'status': 'error'})
            raise exception.ManilaException(
                "Driver does not expect share-network to be provided "
                "with current configuration.")

        if snapshot_id is not None:
            snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)
            parent_share_server_id = snapshot_ref['share']['share_server_id']
        else:
            snapshot_ref = None
            parent_share_server_id = None

        if parent_share_server_id:
            try:
                share_server = self.db.share_server_get(context,
                                                        parent_share_server_id)
                LOG.debug("Using share_server "
                          "%s for share %s" % (share_server['id'], share_id))
                share_ref = self.db.share_update(
                    context, share_id, {'share_server_id': share_server['id']})
            except exception.ShareServerNotFound:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Share server %s does not exist."),
                              parent_share_server_id)
                    self.db.share_update(context, share_id,
                                         {'status': 'error'})
        elif share_network_id:
            try:
                share_server, share_ref = self._provide_share_server_for_share(
                    context, share_network_id, share_id)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Failed to get share server"
                                  " for share creation."))
                    self.db.share_update(context, share_id,
                                         {'status': 'error'})
        else:
            share_server = None

        try:
            if snapshot_ref:
                export_locations = self.driver.create_share_from_snapshot(
                    context, share_ref, snapshot_ref,
                    share_server=share_server)
            else:
                export_locations = self.driver.create_share(
                    context, share_ref, share_server=share_server)

            self.db.share_export_locations_update(context, share_id,
                                                  export_locations)

        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Share %s failed on creation."), share_id)
                detail_data = getattr(e, 'detail_data', {})

                def get_export_location(details):
                    if not isinstance(details, dict):
                        return None
                    return details.get('export_locations',
                                       details.get('export_location'))

                export_locations = get_export_location(detail_data)

                if export_locations:
                    self.db.share_export_locations_update(
                        context, share_id, export_locations)
                else:
                    LOG.warning(_LW('Share information in exception '
                                    'can not be written to db because it '
                                    'contains %s and it is not a dictionary.'),
                                detail_data)
                self.db.share_update(context, share_id, {'status': 'error'})
        else:
            LOG.info(_LI("Share created successfully."))
            self.db.share_update(context, share_id,
                                 {'status': 'available',
                                  'launched_at': timeutils.utcnow()})

    def manage_share(self, context, share_id, driver_options):
        context = context.elevated()
        share_ref = self.db.share_get(context, share_id)
        project_id = share_ref['project_id']

        try:
            if self.driver.driver_handles_share_servers:
                msg = _("Manage share is not supported for "
                        "driver_handles_share_servers=True mode.")
                raise exception.InvalidShare(reason=msg)

            share_update = (
                self.driver.manage_existing(share_ref, driver_options) or {})

            if not share_update.get('size'):
                msg = _("Driver cannot calculate share size.")
                raise exception.InvalidShare(reason=msg)

            self._update_quota_usages(context, project_id, {
                "shares": 1,
                "gigabytes": share_update['size'],
            })

            share_update.update({
                'status': 'available',
                'launched_at': timeutils.utcnow(),
            })

            # NOTE(vponomaryov): we should keep only those export locations
            # that driver has calculated to avoid incompatibilities with one
            # provided by user.
            if 'export_locations' in share_update:
                self.db.share_export_locations_update(
                    context, share_id, share_update.pop('export_locations'),
                    delete=True)

            self.db.share_update(context, share_id, share_update)
        except Exception:
            # NOTE(vponomaryov): set size as 1 because design expects size
            # to be set, it also will allow us to handle delete/unmanage
            # operations properly with this errored share according to quotas.
            self.db.share_update(
                context, share_id,
                {'status': constants.STATUS_MANAGE_ERROR, 'size': 1})
            raise

    def _update_quota_usages(self, context, project_id, usages):
        user_id = context.user_id
        for resource, usage in six.iteritems(usages):
            try:
                current_usage = self.db.quota_usage_get(
                    context, project_id, resource, user_id)
                self.db.quota_usage_update(
                    context, project_id, user_id, resource,
                    in_use=current_usage['in_use'] + usage)
            except exception.QuotaUsageNotFound:
                self.db.quota_usage_create(context, project_id,
                                           user_id, resource, usage)

    def unmanage_share(self, context, share_id):
        context = context.elevated()
        share_ref = self.db.share_get(context, share_id)
        share_server = self._get_share_server(context, share_ref)
        project_id = share_ref['project_id']

        def share_manage_set_error_status(msg, exception):
            status = {'status': constants.STATUS_UNMANAGE_ERROR}
            self.db.share_update(context, share_id, status)
            LOG.error(msg, six.text_type(exception))

        try:
            if self.driver.driver_handles_share_servers:
                msg = _("Unmanage share is not supported for "
                        "driver_handles_share_servers=True mode.")
                raise exception.InvalidShare(reason=msg)

            if share_server:
                msg = _("Unmanage share is not supported for "
                        "shares with share servers.")
                raise exception.InvalidShare(reason=msg)

            self.driver.unmanage(share_ref)

        except exception.InvalidShare as e:
            share_manage_set_error_status(
                _LE("Share can not be unmanaged: %s."), e)
            return

        try:
            reservations = QUOTAS.reserve(context,
                                          project_id=project_id,
                                          shares=-1,
                                          gigabytes=-share_ref['size'])
            QUOTAS.commit(context, reservations, project_id=project_id)
        except Exception as e:
            # Note(imalinovskiy):
            # Quota reservation errors here are not fatal, because
            # unmanage is administrator API and he/she could update user
            # quota usages later if it's required.
            LOG.warning(_LE("Failed to update quota usages: %s."),
                        six.text_type(e))

        if self.configuration.safe_get('unmanage_remove_access_rules'):
            try:
                self._remove_share_access_rules(context, share_ref,
                                                share_server)
            except Exception as e:
                share_manage_set_error_status(
                    _LE("Can not remove access rules of share: %s."), e)
                return

        self.db.share_update(context, share_id,
                             {'status': constants.STATUS_UNMANAGED,
                              'deleted': True})

    def delete_share(self, context, share_id):
        """Delete a share."""
        context = context.elevated()
        share_ref = self.db.share_get(context, share_id)
        share_server = self._get_share_server(context, share_ref)

        if context.project_id != share_ref['project_id']:
            project_id = share_ref['project_id']
        else:
            project_id = context.project_id

        try:
            self._remove_share_access_rules(context, share_ref, share_server)
            self.driver.delete_share(context, share_ref,
                                     share_server=share_server)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_update(context, share_id,
                                     {'status': 'error_deleting'})
        try:
            reservations = QUOTAS.reserve(context,
                                          project_id=project_id,
                                          shares=-1,
                                          gigabytes=-share_ref['size'])
        except Exception:
            reservations = None
            LOG.exception(_LE("Failed to update usages deleting share"))

        self.db.share_delete(context, share_id)
        LOG.info(_LI("Share %s: deleted successfully."), share_ref['name'])

        if reservations:
            QUOTAS.commit(context, reservations, project_id=project_id)

        if CONF.delete_share_server_with_last_share:
            share_server = self._get_share_server(context, share_ref)
            if share_server and not share_server.shares:
                LOG.debug("Scheduled deletion of share-server "
                          "with id '%s' automatically by "
                          "deletion of last share.", share_server['id'])
                self.delete_share_server(context, share_server)

    @manager.periodic_task(ticks_between_runs=600 / CONF.periodic_interval)
    def delete_free_share_servers(self, ctxt):
        if not (self.driver.driver_handles_share_servers and
                self.configuration.automatic_share_server_cleanup):
            return
        LOG.info(_LI("Check for unused share servers to delete."))
        updated_before = timeutils.utcnow() - datetime.timedelta(
            minutes=self.configuration.unused_share_server_cleanup_interval)
        servers = self.db.share_server_get_all_unused_deletable(ctxt,
                                                                self.host,
                                                                updated_before)
        for server in servers:
            self.delete_share_server(ctxt, server)

    def _remove_share_access_rules(self, context, share_ref, share_server):
        rules = self.db.share_access_get_all_for_share(
            context, share_ref['id'])

        for access_ref in rules:
            self._deny_access(context, access_ref, share_ref, share_server)

    def create_snapshot(self, context, share_id, snapshot_id):
        """Create snapshot for share."""
        snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)
        share_server = self._get_share_server(context,
                                              snapshot_ref['share'])
        try:
            model_update = self.driver.create_snapshot(
                context, snapshot_ref, share_server=share_server)

            if model_update:
                model_dict = model_update.to_dict()
                self.db.share_snapshot_update(context, snapshot_ref['id'],
                                              model_dict)

        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_snapshot_update(context,
                                              snapshot_ref['id'],
                                              {'status': 'error'})

        self.db.share_snapshot_update(context,
                                      snapshot_ref['id'],
                                      {'status': 'available',
                                       'progress': '100%'})
        return snapshot_id

    def delete_snapshot(self, context, snapshot_id):
        """Delete share snapshot."""
        context = context.elevated()
        snapshot_ref = self.db.share_snapshot_get(context, snapshot_id)

        share_server = self._get_share_server(context,
                                              snapshot_ref['share'])

        if context.project_id != snapshot_ref['project_id']:
            project_id = snapshot_ref['project_id']
        else:
            project_id = context.project_id

        try:
            self.driver.delete_snapshot(context, snapshot_ref,
                                        share_server=share_server)
        except exception.ShareSnapshotIsBusy:
            self.db.share_snapshot_update(context, snapshot_ref['id'],
                                          {'status': 'available'})
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_snapshot_update(context, snapshot_ref['id'],
                                              {'status': 'error_deleting'})
        else:
            self.db.share_snapshot_destroy(context, snapshot_id)
            try:
                reservations = QUOTAS.reserve(
                    context, project_id=project_id, snapshots=-1,
                    snapshot_gigabytes=-snapshot_ref['size'])
            except Exception:
                reservations = None
                LOG.exception(_LE("Failed to update usages deleting snapshot"))

            if reservations:
                QUOTAS.commit(context, reservations, project_id=project_id)

    def allow_access(self, context, access_id):
        """Allow access to some share."""
        try:
            access_ref = self.db.share_access_get(context, access_id)
            share_ref = self.db.share_get(context, access_ref['share_id'])
            share_server = self._get_share_server(context,
                                                  share_ref)
            if access_ref['state'] == access_ref.STATE_NEW:
                self.driver.allow_access(context, share_ref, access_ref,
                                         share_server=share_server)
                self.db.share_access_update(
                    context, access_id, {'state': access_ref.STATE_ACTIVE})
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_access_update(
                    context, access_id, {'state': access_ref.STATE_ERROR})

    def deny_access(self, context, access_id):
        """Deny access to some share."""
        access_ref = self.db.share_access_get(context, access_id)
        share_ref = self.db.share_get(context, access_ref['share_id'])
        share_server = self._get_share_server(context,
                                              share_ref)
        self._deny_access(context, access_ref, share_ref, share_server)

    def _deny_access(self, context, access_ref, share_ref, share_server):
        access_id = access_ref['id']
        try:
            self.driver.deny_access(context, share_ref, access_ref,
                                    share_server=share_server)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.share_access_update(
                    context, access_id, {'state': access_ref.STATE_ERROR})
        self.db.share_access_delete(context, access_id)

    @manager.periodic_task
    def _report_driver_status(self, context):
        LOG.info(_LI('Updating share status'))
        share_stats = self.driver.get_share_stats(refresh=True)
        if share_stats:
            self.update_service_capabilities(share_stats)

    def publish_service_capabilities(self, context):
        """Collect driver status and then publish it."""
        self._report_driver_status(context)
        self._publish_service_capabilities(context)

    def _form_server_setup_info(self, context, share_server, share_network):
        # Network info is used by driver for setting up share server
        # and getting server info on share creation.
        network_allocations = self.db.network_allocations_get_for_share_server(
            context, share_server['id'])
        network_info = {
            'server_id': share_server['id'],
            'segmentation_id': share_network['segmentation_id'],
            'cidr': share_network['cidr'],
            'neutron_net_id': share_network['neutron_net_id'],
            'neutron_subnet_id': share_network['neutron_subnet_id'],
            'nova_net_id': share_network['nova_net_id'],
            'security_services': share_network['security_services'],
            'network_allocations': network_allocations,
            'backend_details': share_server.get('backend_details'),
            'network_type': share_network['network_type'],
        }
        return network_info

    def _setup_server(self, context, share_server, metadata=None):
        try:
            share_network = self.db.share_network_get(
                context, share_server['share_network_id'])
            self.driver.allocate_network(context, share_server, share_network)

            # Get share_network again in case it was updated.
            share_network = self.db.share_network_get(
                context, share_server['share_network_id'])
            network_info = self._form_server_setup_info(
                context, share_server, share_network)
            self._validate_segmentation_id(network_info)

            # NOTE(vponomaryov): Save security services data to share server
            # details table to remove dependency from share network after
            # creation operation. It will allow us to delete share server and
            # share network separately without dependency on each other.
            for security_service in network_info['security_services']:
                ss_type = security_service['type']
                data = {
                    'name': security_service['name'],
                    'domain': security_service['domain'],
                    'server': security_service['server'],
                    'dns_ip': security_service['dns_ip'],
                    'user': security_service['user'],
                    'type': ss_type,
                    'password': security_service['password'],
                }
                self.db.share_server_backend_details_set(
                    context, share_server['id'],
                    {'security_service_' + ss_type: jsonutils.dumps(data)})

            server_info = self.driver.setup_server(
                network_info, metadata=metadata)

            if server_info and isinstance(server_info, dict):
                self.db.share_server_backend_details_set(
                    context, share_server['id'], server_info)
            return self.db.share_server_update(
                context, share_server['id'],
                {'status': constants.STATUS_ACTIVE})
        except Exception as e:
            with excutils.save_and_reraise_exception():
                try:
                    details = getattr(e, 'detail_data', {})
                    if not isinstance(details, dict):
                        msg = (_("Invalid detail_data '%s'")
                               % six.text_type(details))
                        raise exception.Invalid(msg)

                    server_details = details.get('server_details')

                    if not isinstance(server_details, dict):
                        msg = (_("Invalid server_details '%s'")
                               % six.text_type(server_details))
                        raise exception.Invalid(msg)

                    invalid_details = []

                    for key, value in server_details.items():
                        try:
                            self.db.share_server_backend_details_set(
                                context, share_server['id'], {key: value})
                        except Exception:
                            invalid_details.append("%(key)s: %(value)s" % {
                                'key': six.text_type(key),
                                'value': six.text_type(value)
                            })

                    if invalid_details:
                        msg = (_("Following server details are not valid:\n%s")
                               % six.text_type('\n'.join(invalid_details)))
                        raise exception.Invalid(msg)

                except Exception as e:
                    LOG.warning(_LW('Server Information in '
                                    'exception can not be written to db : %s '
                                    ), six.text_type(e))
                finally:
                    self.db.share_server_update(
                        context, share_server['id'],
                        {'status': constants.STATUS_ERROR})
                    self.driver.deallocate_network(context, share_server['id'])

    def _validate_segmentation_id(self, network_info):
        """Raises exception if the segmentation type is incorrect."""
        if (network_info['network_type'] in (None, 'flat') and
                network_info['segmentation_id']):
            msg = _('A segmentation ID %(vlan_id)s was specified but can not '
                    'be used with a network of type %(seg_type)s; the '
                    'segmentation ID option must be omitted or set to 0')
            raise exception.NetworkBadConfigurationException(
                reason=msg % {'vlan_id': network_info['segmentation_id'],
                              'seg_type': network_info['network_type']})
        elif (network_info['network_type'] == 'vlan'
              and (network_info['segmentation_id'] is None
                   or int(network_info['segmentation_id']) > 4094
                   or int(network_info['segmentation_id'] < 1))):
            msg = _('A segmentation ID %s was specified but is not valid for '
                    'a VLAN network type; the segmentation ID must be an '
                    'integer value in the range of [1,4094]')
            raise exception.NetworkBadConfigurationException(
                reason=msg % network_info['segmentation_id'])
        elif (network_info['network_type'] == 'vxlan'
              and (network_info['segmentation_id'] is None
                   or int(network_info['segmentation_id']) > 16777215
                   or int(network_info['segmentation_id'] < 1))):
            msg = _('A segmentation ID %s was specified but is not valid for '
                    'a VXLAN network type; the segmentation ID must be an '
                    'integer value in the range of [1,16777215]')
            raise exception.NetworkBadConfigurationException(
                reason=msg % network_info['segmentation_id'])
        elif (network_info['network_type'] == 'gre'
              and (network_info['segmentation_id'] is None
                   or int(network_info['segmentation_id']) > 4294967295
                   or int(network_info['segmentation_id'] < 1))):
            msg = _('A segmentation ID %s was specified but is not valid for '
                    'a GRE network type; the segmentation ID must be an '
                    'integer value in the range of [1, 4294967295]')
            raise exception.NetworkBadConfigurationException(
                reason=msg % network_info['segmentation_id'])

    def delete_share_server(self, context, share_server):

        @utils.synchronized(
            "share_manager_%s" % share_server['share_network_id'])
        def _teardown_server():
            # NOTE(vponomaryov): Verify that there are no dependent shares.
            # Without this verification we can get here exception in next case:
            # share-server-delete API was called after share creation scheduled
            # and share_server reached ACTIVE status, but before update
            # of share_server_id field for share. If so, after lock realese
            # this method starts executing when amount of dependent shares
            # has been changed.
            server_id = share_server['id']
            shares = self.db.share_get_all_by_share_server(context, server_id)

            if shares:
                raise exception.ShareServerInUse(share_server_id=server_id)

            server_details = share_server['backend_details']

            self.db.share_server_update(context, server_id,
                                        {'status': constants.STATUS_DELETING})
            try:
                LOG.debug("Deleting share server '%s'", server_id)
                security_services = []
                for ss_name in constants.SECURITY_SERVICES_ALLOWED_TYPES:
                    ss = server_details.get('security_service_' + ss_name)
                    if ss:
                        security_services.append(jsonutils.loads(ss))

                self.driver.teardown_server(
                    server_details=server_details,
                    security_services=security_services)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(
                        _LE("Share server '%s' failed on deletion."),
                        server_id)
                    self.db.share_server_update(
                        context, server_id, {'status': constants.STATUS_ERROR})
            else:
                self.db.share_server_delete(context, share_server['id'])

        _teardown_server()
        LOG.info(
            _LI("Share server '%s' has been deleted successfully."),
            share_server['id'])
        self.driver.deallocate_network(context, share_server['id'])

    def _verify_unused_share_server_cleanup_interval(self):
        if not 10 <= self.configuration.\
                unused_share_server_cleanup_interval <= 60:
            raise exception.InvalidParameterValue(
                "Option unused_share_server_cleanup_interval should be "
                "between 10 minutes and 1 hour.")
