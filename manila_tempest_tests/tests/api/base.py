# Copyright 2014 Mirantis Inc.
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

import copy
import inspect
import traceback

from oslo_concurrency import lockutils
from oslo_log import log
import six
from tempest.common import credentials_factory as common_creds
from tempest.common import dynamic_creds
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest import test

from manila_tempest_tests import clients_share as clients
from manila_tempest_tests.common import constants
from manila_tempest_tests import share_exceptions
from manila_tempest_tests import utils

CONF = config.CONF
LOG = log.getLogger(__name__)


class handle_cleanup_exceptions(object):
    """Handle exceptions raised with cleanup operations.

    Always suppress errors when exceptions.NotFound or exceptions.Forbidden
    are raised.
    Suppress all other exceptions only in case config opt
    'suppress_errors_in_cleanup' in config group 'share' is True.
    """

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if not (isinstance(exc_value,
                           (exceptions.NotFound, exceptions.Forbidden)) or
                CONF.share.suppress_errors_in_cleanup):
            return False  # Do not suppress error if any
        if exc_traceback:
            LOG.error("Suppressed cleanup error in Manila: "
                      "\n%s" % traceback.format_exc())
        return True  # Suppress error if any


def network_synchronized(f):

    def wrapped_func(self, *args, **kwargs):
        with_isolated_creds = True if len(args) > 2 else False
        no_lock_required = kwargs.get(
            "isolated_creds_client", with_isolated_creds)
        if no_lock_required:
            # Usage of not reusable network. No need in lock.
            return f(self, *args, **kwargs)

        # Use lock assuming reusage of common network.
        @lockutils.synchronized("manila_network_lock", external=True)
        def source_func(self, *args, **kwargs):
            return f(self, *args, **kwargs)

        return source_func(self, *args, **kwargs)

    return wrapped_func


skip_if_microversion_not_supported = utils.skip_if_microversion_not_supported
skip_if_microversion_lt = utils.skip_if_microversion_lt


class BaseSharesTest(test.BaseTestCase):
    """Base test case class for all Manila API tests."""

    force_tenant_isolation = False
    protocols = ["nfs", "cifs", "glusterfs", "hdfs", "cephfs"]

    # Will be cleaned up in resource_cleanup
    class_resources = []

    # Will be cleaned up in tearDown method
    method_resources = []

    # Will be cleaned up in resource_cleanup
    class_isolated_creds = []

    # Will be cleaned up in tearDown method
    method_isolated_creds = []

    def skip_if_microversion_not_supported(self, microversion):
        if not utils.is_microversion_supported(microversion):
            raise self.skipException(
                "Microversion '%s' is not supported." % microversion)

    def skip_if_microversion_lt(self, microversion):
        if utils.is_microversion_lt(CONF.share.max_api_microversion,
                                    microversion):
            raise self.skipException(
                "Microversion must be greater than or equal to '%s'." %
                microversion)

    @classmethod
    def get_client_with_isolated_creds(cls,
                                       name=None,
                                       type_of_creds="admin",
                                       cleanup_in_class=False,
                                       client_version='1'):
        """Creates isolated creds.

        :param name: name, will be used for naming ic and related stuff
        :param type_of_creds: admin, alt or primary
        :param cleanup_in_class: defines place where to delete
        :returns: SharesClient -- shares client with isolated creds.
        :returns: To client added dict attr 'creds' with
        :returns: key elements 'tenant' and 'user'.
        """
        if name is None:
            # Get name of test method
            name = inspect.stack()[1][3]
            if len(name) > 32:
                name = name[0:32]

        # Choose type of isolated creds
        ic = dynamic_creds.DynamicCredentialProvider(
            identity_version=CONF.identity.auth_version,
            name=name,
            admin_role=CONF.identity.admin_role,
            admin_creds=common_creds.get_configured_credentials(
                'identity_admin'))
        if "admin" in type_of_creds:
            creds = ic.get_admin_creds()
        elif "alt" in type_of_creds:
            creds = ic.get_alt_creds()
        else:
            creds = ic.self.get_credentials(type_of_creds)
        ic.type_of_creds = type_of_creds

        # create client with isolated creds
        os = clients.Manager(credentials=creds)
        if client_version == '1':
            client = os.shares_client
        elif client_version == '2':
            client = os.shares_v2_client

        # Set place where will be deleted isolated creds
        ic_res = {
            "method": ic.clear_creds,
            "deleted": False,
        }
        if cleanup_in_class:
            cls.class_isolated_creds.insert(0, ic_res)
        else:
            cls.method_isolated_creds.insert(0, ic_res)

        # Provide share network
        if CONF.share.multitenancy_enabled:
            if not CONF.service_available.neutron:
                raise cls.skipException("Neutron support is required")
            nc = os.networks_client
            share_network_id = cls.provide_share_network(client, nc, ic)
            client.share_network_id = share_network_id
            resource = {
                "type": "share_network",
                "id": client.share_network_id,
                "client": client,
            }
            if cleanup_in_class:
                cls.class_resources.insert(0, resource)
            else:
                cls.method_resources.insert(0, resource)
        return client

    @classmethod
    def verify_nonempty(cls, *args):
        if not all(args):
            msg = "Missing API credentials in configuration."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        if not (any(p in CONF.share.enable_protocols
                    for p in cls.protocols) and
                CONF.service_available.manila):
            skip_msg = "Manila is disabled"
            raise cls.skipException(skip_msg)
        super(BaseSharesTest, cls).resource_setup()
        if not hasattr(cls, "os"):
            cls.username = CONF.identity.username
            cls.password = CONF.identity.password
            cls.tenant_name = CONF.identity.tenant_name
            cls.verify_nonempty(cls.username, cls.password, cls.tenant_name)
            cls.os = clients.Manager()
        if CONF.share.multitenancy_enabled:
            if not CONF.service_available.neutron:
                raise cls.skipException("Neutron support is required")
            sc = cls.os.shares_client
            nc = cls.os.networks_client
            share_network_id = cls.provide_share_network(sc, nc)
            cls.os.shares_client.share_network_id = share_network_id
            cls.os.shares_v2_client.share_network_id = share_network_id
        cls.shares_client = cls.os.shares_client
        cls.shares_v2_client = cls.os.shares_v2_client

    def setUp(self):
        super(BaseSharesTest, self).setUp()
        self.addCleanup(self.clear_isolated_creds)
        self.addCleanup(self.clear_resources)

    @classmethod
    def resource_cleanup(cls):
        super(BaseSharesTest, cls).resource_cleanup()
        cls.clear_resources(cls.class_resources)
        cls.clear_isolated_creds(cls.class_isolated_creds)

    @classmethod
    @network_synchronized
    def provide_share_network(cls, shares_client, networks_client,
                              isolated_creds_client=None):
        """Used for finding/creating share network for multitenant driver.

        This method creates/gets entity share-network for one tenant. This
        share-network will be used for creation of service vm.

        :param shares_client: shares client, which requires share-network
        :param networks_client: network client from same tenant as shares
        :param isolated_creds_client: DynamicCredentialProvider instance
            If provided, then its networking will be used if needed.
            If not provided, then common network will be used if needed.
        :returns: str -- share network id for shares_client tenant
        :returns: None -- if single-tenant driver used
        """

        sc = shares_client

        if not CONF.share.multitenancy_enabled:
            # Assumed usage of a single-tenant driver
            share_network_id = None
        elif sc.share_network_id:
            # Share-network already exists, use it
            share_network_id = sc.share_network_id
        else:
            net_id = subnet_id = share_network_id = None

            if not isolated_creds_client:
                # Search for networks, created in previous runs
                search_word = "reusable"
                sn_name = "autogenerated_by_tempest_%s" % search_word
                service_net_name = "share-service"
                networks = networks_client.list_networks()
                if "networks" in networks.keys():
                    networks = networks["networks"]
                for network in networks:
                    if (service_net_name in network["name"] and
                            sc.tenant_id == network['tenant_id']):
                        net_id = network["id"]
                        if len(network["subnets"]) > 0:
                            subnet_id = network["subnets"][0]
                            break

                # Create suitable network
                if (net_id is None or subnet_id is None):
                    ic = dynamic_creds.DynamicCredentialProvider(
                        identity_version=CONF.identity.auth_version,
                        name=service_net_name,
                        admin_role=CONF.identity.admin_role,
                        admin_creds=common_creds.get_configured_credentials(
                            'identity_admin'))
                    net_data = ic._create_network_resources(sc.tenant_id)
                    network, subnet, router = net_data
                    net_id = network["id"]
                    subnet_id = subnet["id"]

                # Try get suitable share-network
                share_networks = sc.list_share_networks_with_detail()
                for sn in share_networks:
                    if (net_id == sn["neutron_net_id"] and
                            subnet_id == sn["neutron_subnet_id"] and
                            sn["name"] and search_word in sn["name"]):
                        share_network_id = sn["id"]
                        break
            else:
                sn_name = "autogenerated_by_tempest_for_isolated_creds"
                # Use precreated network and subnet from isolated creds
                net_id = isolated_creds_client.get_credentials(
                    isolated_creds_client.type_of_creds).network['id']
                subnet_id = isolated_creds_client.get_credentials(
                    isolated_creds_client.type_of_creds).subnet['id']

            # Create suitable share-network
            if share_network_id is None:
                sn_desc = "This share-network was created by tempest"
                sn = sc.create_share_network(name=sn_name,
                                             description=sn_desc,
                                             neutron_net_id=net_id,
                                             neutron_subnet_id=subnet_id)
                share_network_id = sn["id"]

        return share_network_id

    @classmethod
    def _create_share(cls, share_protocol=None, size=1, name=None,
                      snapshot_id=None, description=None, metadata=None,
                      share_network_id=None, share_type_id=None,
                      consistency_group_id=None, client=None,
                      cleanup_in_class=True, is_public=False, **kwargs):
        client = client or cls.shares_v2_client
        description = description or "Tempest's share"
        share_network_id = share_network_id or client.share_network_id or None
        metadata = metadata or {}
        kwargs.update({
            'share_protocol': share_protocol,
            'size': size,
            'name': name,
            'snapshot_id': snapshot_id,
            'description': description,
            'metadata': metadata,
            'share_network_id': share_network_id,
            'share_type_id': share_type_id,
            'is_public': is_public,
        })
        if consistency_group_id:
            kwargs['consistency_group_id'] = consistency_group_id

        share = client.create_share(**kwargs)
        resource = {"type": "share", "id": share["id"], "client": client,
                    "consistency_group_id": consistency_group_id}
        cleanup_list = (cls.class_resources if cleanup_in_class else
                        cls.method_resources)
        cleanup_list.insert(0, resource)
        return share

    @classmethod
    def migrate_share(cls, share_id, dest_host, client=None, notify=True,
                      wait_for_status='migration_success', **kwargs):
        client = client or cls.shares_v2_client
        client.migrate_share(share_id, dest_host, notify, **kwargs)
        share = client.wait_for_migration_status(
            share_id, dest_host, wait_for_status,
            version=kwargs.get('version'))
        return share

    @classmethod
    def migration_complete(cls, share_id, dest_host, client=None, **kwargs):
        client = client or cls.shares_v2_client
        client.migration_complete(share_id, **kwargs)
        share = client.wait_for_migration_status(
            share_id, dest_host, 'migration_success',
            version=kwargs.get('version'))
        return share

    @classmethod
    def create_share(cls, *args, **kwargs):
        """Create one share and wait for available state. Retry if allowed."""
        result = cls.create_shares([{"args": args, "kwargs": kwargs}])
        return result[0]

    @classmethod
    def create_shares(cls, share_data_list):
        """Creates several shares in parallel with retries.

        Use this method when you want to create more than one share at same
        time. Especially if config option 'share.share_creation_retry_number'
        has value more than zero (0).
        All shares will be expected to have 'available' status with or without
        recreation else error will be raised.

        :param share_data_list: list -- list of dictionaries with 'args' and
            'kwargs' for '_create_share' method of this base class.
            example of data:
                share_data_list=[{'args': ['quuz'], 'kwargs': {'foo': 'bar'}}}]
        :returns: list -- list of shares created using provided data.
        """

        data = [copy.deepcopy(d) for d in share_data_list]
        for d in data:
            if not isinstance(d, dict):
                raise exceptions.TempestException(
                    "Expected 'dict', got '%s'" % type(d))
            if "args" not in d:
                d["args"] = []
            if "kwargs" not in d:
                d["kwargs"] = {}
            if len(d) > 2:
                raise exceptions.TempestException(
                    "Expected only 'args' and 'kwargs' keys. "
                    "Provided %s" % list(d))
            d["kwargs"]["client"] = d["kwargs"].get(
                "client", cls.shares_v2_client)
            d["share"] = cls._create_share(*d["args"], **d["kwargs"])
            d["cnt"] = 0
            d["available"] = False

        while not all(d["available"] for d in data):
            for d in data:
                if d["available"]:
                    continue
                try:
                    d["kwargs"]["client"].wait_for_share_status(
                        d["share"]["id"], "available")
                    d["available"] = True
                except (share_exceptions.ShareBuildErrorException,
                        exceptions.TimeoutException) as e:
                    if CONF.share.share_creation_retry_number > d["cnt"]:
                        d["cnt"] += 1
                        msg = ("Share '%s' failed to be built. "
                               "Trying create another." % d["share"]["id"])
                        LOG.error(msg)
                        LOG.error(e)
                        d["share"] = cls._create_share(
                            *d["args"], **d["kwargs"])
                    else:
                        raise e

        return [d["share"] for d in data]

    @classmethod
    def create_consistency_group(cls, client=None, cleanup_in_class=True,
                                 share_network_id=None, **kwargs):
        client = client or cls.shares_v2_client
        kwargs['share_network_id'] = (share_network_id or
                                      client.share_network_id or None)
        consistency_group = client.create_consistency_group(**kwargs)
        resource = {
            "type": "consistency_group",
            "id": consistency_group["id"],
            "client": client}
        if cleanup_in_class:
            cls.class_resources.insert(0, resource)
        else:
            cls.method_resources.insert(0, resource)

        if kwargs.get('source_cgsnapshot_id'):
            new_cg_shares = client.list_shares(
                detailed=True,
                params={'consistency_group_id': consistency_group['id']})

            for share in new_cg_shares:
                resource = {"type": "share",
                            "id": share["id"],
                            "client": client,
                            "consistency_group_id": share.get(
                                'consistency_group_id')}
                if cleanup_in_class:
                    cls.class_resources.insert(0, resource)
                else:
                    cls.method_resources.insert(0, resource)

        client.wait_for_consistency_group_status(consistency_group['id'],
                                                 'available')
        return consistency_group

    @classmethod
    def create_snapshot_wait_for_active(cls, share_id, name=None,
                                        description=None, force=False,
                                        client=None, cleanup_in_class=True):
        if client is None:
            client = cls.shares_v2_client
        if description is None:
            description = "Tempest's snapshot"
        snapshot = client.create_snapshot(share_id, name, description, force)
        resource = {
            "type": "snapshot",
            "id": snapshot["id"],
            "client": client,
        }
        if cleanup_in_class:
            cls.class_resources.insert(0, resource)
        else:
            cls.method_resources.insert(0, resource)
        client.wait_for_snapshot_status(snapshot["id"], "available")
        return snapshot

    @classmethod
    def create_cgsnapshot_wait_for_active(cls, consistency_group_id,
                                          name=None, description=None,
                                          client=None, cleanup_in_class=True,
                                          **kwargs):
        client = client or cls.shares_v2_client
        if description is None:
            description = "Tempest's cgsnapshot"
        cgsnapshot = client.create_cgsnapshot(consistency_group_id,
                                              name=name,
                                              description=description,
                                              **kwargs)
        resource = {
            "type": "cgsnapshot",
            "id": cgsnapshot["id"],
            "client": client,
        }
        if cleanup_in_class:
            cls.class_resources.insert(0, resource)
        else:
            cls.method_resources.insert(0, resource)
        client.wait_for_cgsnapshot_status(cgsnapshot["id"], "available")
        return cgsnapshot

    @classmethod
    def get_availability_zones(cls, client=None):
        """List the availability zones for "manila-share" services

         that are currently in "up" state.
         """
        client = client or cls.shares_v2_client
        cls.services = client.list_services()
        zones = [service['zone'] for service in cls.services if
                 service['binary'] == "manila-share" and
                 service['state'] == 'up']
        return zones

    def get_pools_for_replication_domain(self):
        # Get the list of pools for the replication domain
        pools = self.admin_client.list_pools(detail=True)['pools']
        instance_host = self.shares[0]['host']
        host_pool = [p for p in pools if p['name'] == instance_host][0]
        rep_domain = host_pool['capabilities']['replication_domain']
        pools_in_rep_domain = [p for p in pools if p['capabilities'][
            'replication_domain'] == rep_domain]
        return rep_domain, pools_in_rep_domain

    @classmethod
    def create_share_replica(cls, share_id, availability_zone, client=None,
                             cleanup_in_class=False, cleanup=True):
        client = client or cls.shares_v2_client
        replica = client.create_share_replica(share_id, availability_zone)
        resource = {
            "type": "share_replica",
            "id": replica["id"],
            "client": client,
            "share_id": share_id,
        }
        # NOTE(Yogi1): Cleanup needs to be disabled during promotion tests.
        if cleanup:
            if cleanup_in_class:
                cls.class_resources.insert(0, resource)
            else:
                cls.method_resources.insert(0, resource)
        client.wait_for_share_replica_status(
            replica["id"], constants.STATUS_AVAILABLE)
        return replica

    @classmethod
    def delete_share_replica(cls, replica_id, client=None):
        client = client or cls.shares_v2_client
        try:
            client.delete_share_replica(replica_id)
            client.wait_for_resource_deletion(replica_id=replica_id)
        except exceptions.NotFound:
            pass

    @classmethod
    def promote_share_replica(cls, replica_id, client=None):
        client = client or cls.shares_v2_client
        replica = client.promote_share_replica(replica_id)
        client.wait_for_share_replica_status(
            replica["id"],
            constants.REPLICATION_STATE_ACTIVE,
            status_attr="replica_state")
        return replica

    @classmethod
    def create_share_network(cls, client=None,
                             cleanup_in_class=False, **kwargs):
        if client is None:
            client = cls.shares_client
        share_network = client.create_share_network(**kwargs)
        resource = {
            "type": "share_network",
            "id": share_network["id"],
            "client": client,
        }
        if cleanup_in_class:
            cls.class_resources.insert(0, resource)
        else:
            cls.method_resources.insert(0, resource)
        return share_network

    @classmethod
    def create_security_service(cls, ss_type="ldap", client=None,
                                cleanup_in_class=False, **kwargs):
        if client is None:
            client = cls.shares_client
        security_service = client.create_security_service(ss_type, **kwargs)
        resource = {
            "type": "security_service",
            "id": security_service["id"],
            "client": client,
        }
        if cleanup_in_class:
            cls.class_resources.insert(0, resource)
        else:
            cls.method_resources.insert(0, resource)
        return security_service

    @classmethod
    def create_share_type(cls, name, is_public=True, client=None,
                          cleanup_in_class=True, **kwargs):
        if client is None:
            client = cls.shares_v2_client
        share_type = client.create_share_type(name, is_public, **kwargs)
        resource = {
            "type": "share_type",
            "id": share_type["share_type"]["id"],
            "client": client,
        }
        if cleanup_in_class:
            cls.class_resources.insert(0, resource)
        else:
            cls.method_resources.insert(0, resource)
        return share_type

    @staticmethod
    def add_required_extra_specs_to_dict(extra_specs=None):
        dhss = six.text_type(CONF.share.multitenancy_enabled)
        snapshot_support = six.text_type(
            CONF.share.capability_snapshot_support)
        required = {
            "driver_handles_share_servers": dhss,
            "snapshot_support": snapshot_support,
        }
        if extra_specs:
            required.update(extra_specs)
        return required

    @classmethod
    def clear_isolated_creds(cls, creds=None):
        if creds is None:
            creds = cls.method_isolated_creds
        for ic in creds:
            if "deleted" not in ic.keys():
                ic["deleted"] = False
            if not ic["deleted"]:
                with handle_cleanup_exceptions():
                    ic["method"]()
                ic["deleted"] = True

    @classmethod
    def clear_share_replicas(cls, share_id, client=None):
        client = client or cls.shares_v2_client
        share_replicas = client.list_share_replicas(
            share_id=share_id)

        for replica in share_replicas:
            try:
                cls.delete_share_replica(replica['id'])
            except exceptions.BadRequest:
                # Ignore the exception due to deletion of last active replica
                pass

    @classmethod
    def clear_resources(cls, resources=None):
        """Deletes resources, that were created in test suites.

        This method tries to remove resources from resource list,
        if it is not found, assumed it was deleted in test itself.
        It is expected, that all resources were added as LIFO
        due to restriction of deletion resources, that is in the chain.

        :param resources: dict with keys 'type','id','client' and 'deleted'
        """

        if resources is None:
            resources = cls.method_resources
        for res in resources:
            if "deleted" not in res.keys():
                res["deleted"] = False
            if "client" not in res.keys():
                res["client"] = cls.shares_client
            if not(res["deleted"]):
                res_id = res['id']
                client = res["client"]
                with handle_cleanup_exceptions():
                    if res["type"] is "share":
                        cls.clear_share_replicas(res_id)
                        cg_id = res.get('consistency_group_id')
                        if cg_id:
                            params = {'consistency_group_id': cg_id}
                            client.delete_share(res_id, params=params)
                        else:
                            client.delete_share(res_id)
                        client.wait_for_resource_deletion(share_id=res_id)
                    elif res["type"] is "snapshot":
                        client.delete_snapshot(res_id)
                        client.wait_for_resource_deletion(snapshot_id=res_id)
                    elif res["type"] is "share_network":
                        client.delete_share_network(res_id)
                        client.wait_for_resource_deletion(sn_id=res_id)
                    elif res["type"] is "security_service":
                        client.delete_security_service(res_id)
                        client.wait_for_resource_deletion(ss_id=res_id)
                    elif res["type"] is "share_type":
                        client.delete_share_type(res_id)
                        client.wait_for_resource_deletion(st_id=res_id)
                    elif res["type"] is "consistency_group":
                        client.delete_consistency_group(res_id)
                        client.wait_for_resource_deletion(cg_id=res_id)
                    elif res["type"] is "cgsnapshot":
                        client.delete_cgsnapshot(res_id)
                        client.wait_for_resource_deletion(cgsnapshot_id=res_id)
                    elif res["type"] is "share_replica":
                        client.delete_share_replica(res_id)
                        client.wait_for_resource_deletion(replica_id=res_id)
                    else:
                        LOG.warning("Provided unsupported resource type for "
                                    "cleanup '%s'. Skipping." % res["type"])
                res["deleted"] = True

    @classmethod
    def generate_share_network_data(self):
        data = {
            "name": data_utils.rand_name("sn-name"),
            "description": data_utils.rand_name("sn-desc"),
            "neutron_net_id": data_utils.rand_name("net-id"),
            "neutron_subnet_id": data_utils.rand_name("subnet-id"),
        }
        return data

    @classmethod
    def generate_security_service_data(self):
        data = {
            "name": data_utils.rand_name("ss-name"),
            "description": data_utils.rand_name("ss-desc"),
            "dns_ip": utils.rand_ip(),
            "server": utils.rand_ip(),
            "domain": data_utils.rand_name("ss-domain"),
            "user": data_utils.rand_name("ss-user"),
            "password": data_utils.rand_name("ss-password"),
        }
        return data

    # Useful assertions
    def assertDictMatch(self, d1, d2, approx_equal=False, tolerance=0.001):
        """Assert two dicts are equivalent.

        This is a 'deep' match in the sense that it handles nested
        dictionaries appropriately.

        NOTE:

            If you don't care (or don't know) a given value, you can specify
            the string DONTCARE as the value. This will cause that dict-item
            to be skipped.

        """
        def raise_assertion(msg):
            d1str = str(d1)
            d2str = str(d2)
            base_msg = ('Dictionaries do not match. %(msg)s d1: %(d1str)s '
                        'd2: %(d2str)s' %
                        {"msg": msg, "d1str": d1str, "d2str": d2str})
            raise AssertionError(base_msg)

        d1keys = set(d1.keys())
        d2keys = set(d2.keys())
        if d1keys != d2keys:
            d1only = d1keys - d2keys
            d2only = d2keys - d1keys
            raise_assertion('Keys in d1 and not d2: %(d1only)s. '
                            'Keys in d2 and not d1: %(d2only)s' %
                            {"d1only": d1only, "d2only": d2only})

        for key in d1keys:
            d1value = d1[key]
            d2value = d2[key]
            try:
                error = abs(float(d1value) - float(d2value))
                within_tolerance = error <= tolerance
            except (ValueError, TypeError):
                # If both values aren't convertible to float, just ignore
                # ValueError if arg is a str, TypeError if it's something else
                # (like None)
                within_tolerance = False

            if hasattr(d1value, 'keys') and hasattr(d2value, 'keys'):
                self.assertDictMatch(d1value, d2value)
            elif 'DONTCARE' in (d1value, d2value):
                continue
            elif approx_equal and within_tolerance:
                continue
            elif d1value != d2value:
                raise_assertion("d1['%(key)s']=%(d1value)s != "
                                "d2['%(key)s']=%(d2value)s" %
                                {
                                    "key": key,
                                    "d1value": d1value,
                                    "d2value": d2value
                                })


class BaseSharesAltTest(BaseSharesTest):
    """Base test case class for all Shares Alt API tests."""

    @classmethod
    def resource_setup(cls):
        cls.username = CONF.identity.alt_username
        cls.password = CONF.identity.alt_password
        cls.tenant_name = CONF.identity.alt_tenant_name
        cls.verify_nonempty(cls.username, cls.password, cls.tenant_name)
        cls.os = clients.AltManager()
        alt_share_network_id = CONF.share.alt_share_network_id
        cls.os.shares_client.share_network_id = alt_share_network_id
        cls.os.shares_v2_client.share_network_id = alt_share_network_id
        super(BaseSharesAltTest, cls).resource_setup()


class BaseSharesAdminTest(BaseSharesTest):
    """Base test case class for all Shares Admin API tests."""

    @classmethod
    def resource_setup(cls):
        if hasattr(CONF.identity, 'admin_username'):
            cls.username = CONF.identity.admin_username
            cls.password = CONF.identity.admin_password
            cls.tenant_name = CONF.identity.admin_tenant_name
        else:
            cls.username = CONF.auth.admin_username
            cls.password = CONF.auth.admin_password
            cls.tenant_name = CONF.auth.admin_tenant_name
        cls.verify_nonempty(cls.username, cls.password, cls.tenant_name)
        cls.os = clients.AdminManager()
        admin_share_network_id = CONF.share.admin_share_network_id
        cls.os.shares_client.share_network_id = admin_share_network_id
        cls.os.shares_v2_client.share_network_id = admin_share_network_id
        super(BaseSharesAdminTest, cls).resource_setup()
