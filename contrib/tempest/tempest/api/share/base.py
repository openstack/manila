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

from tempest_lib import exceptions as lib_exc  # noqa

import six
from tempest import clients_share as clients
from tempest.common import isolated_creds
from tempest.common.utils import data_utils
from tempest import config_share as config
from tempest import exceptions
from tempest.openstack.common import lockutils
from tempest.openstack.common import log as logging
from tempest import share_exceptions
from tempest import test

CONF = config.CONF
LOG = logging.getLogger(__name__)


class handle_cleanup_exceptions(object):
    """Handle exceptions raised with cleanup operations.

    Always suppress errors when lib_exc.NotFound or lib_exc.Unauthorized
    are raised.
    Suppress all other exceptions only in case config opt
    'suppress_errors_in_cleanup' in config group 'share' is True.
    """

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if not (isinstance(exc_value,
                           (lib_exc.NotFound, lib_exc.Unauthorized)) or
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


class BaseSharesTest(test.BaseTestCase):
    """Base test case class for all Manila API tests."""

    force_tenant_isolation = False
    protocols = ["nfs", "cifs"]

    # Will be cleaned up in resource_cleanup
    class_resources = []

    # Will be cleaned up in tearDown method
    method_resources = []

    # Will be cleaned up in resource_cleanup
    class_isolated_creds = []

    # Will be cleaned up in tearDown method
    method_isolated_creds = []

    # All the successful HTTP status codes from RFC 2616
    HTTP_SUCCESS = (200, 201, 202, 203, 204, 205, 206)

    @classmethod
    def get_client_with_isolated_creds(cls,
                                       name=None,
                                       type_of_creds="admin",
                                       cleanup_in_class=False):
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
        ic = isolated_creds.IsolatedCreds(name)
        if "admin" in type_of_creds:
            creds = ic.get_admin_creds()
        elif "alt" in type_of_creds:
            creds = ic.get_alt_creds()
        else:
            creds = ic.self.get_credentials(type_of_creds)
        ic.type_of_creds = type_of_creds

        # create client with isolated creds
        os = clients.Manager(credentials=creds)
        client = os.shares_client

        # Get tenant and user
        identity_client = cls._get_identity_admin_client()
        client.creds = {}
        client.creds["tenant"] = identity_client.get_tenant_by_name(
            client.auth_params["tenant"])
        client.creds["user"] = identity_client.get_user_by_username(
            client.creds["tenant"]["id"],
            client.auth_params["user"])

        # Set place where will be deleted isolated creds
        ic_res = {
            "method": ic.clear_isolated_creds,
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
            nc = os.network_client
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
            nc = cls.os.network_client
            share_network_id = cls.provide_share_network(sc, nc)
            cls.os.shares_client.share_network_id = share_network_id
        cls.shares_client = cls.os.shares_client

    def setUp(self):
        super(BaseSharesTest, self).setUp()
        self.addCleanup(self.clear_resources)
        self.addCleanup(self.clear_isolated_creds)

    @classmethod
    def resource_cleanup(cls):
        super(BaseSharesTest, cls).resource_cleanup()
        cls.clear_resources(cls.class_resources)
        cls.clear_isolated_creds(cls.class_isolated_creds)

    @classmethod
    @network_synchronized
    def provide_share_network(cls, shares_client, network_client,
                              isolated_creds_client=None):
        """Used for finding/creating share network for multitenant driver.

        This method creates/gets entity share-network for one tenant. This
        share-network will be used for creation of service vm.

        :param shares_client: shares client, which requires share-network
        :param network_client: network client from same tenant as shares
        :param isolated_creds_client: IsolatedCreds instance
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
                networks = network_client.list_networks()
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
                    ic = isolated_creds.IsolatedCreds(service_net_name)
                    identity_client = cls._get_identity_admin_client()
                    tenant = identity_client.\
                        get_tenant_by_name(sc.auth_params["tenant"])
                    net_data = ic._create_network_resources(tenant["id"])
                    network, subnet, router = net_data
                    net_id = network["id"]
                    subnet_id = subnet["id"]

                # Try get suitable share-network
                __, share_networks = sc.list_share_networks_with_detail()
                for sn in share_networks:
                    if (net_id == sn["neutron_net_id"] and
                            subnet_id == sn["neutron_subnet_id"] and
                            sn["name"] and search_word in sn["name"]):
                        share_network_id = sn["id"]
                        break
            else:
                sn_name = "autogenerated_by_tempest_for_isolated_creds"
                # Use precreated network and subnet from isolated creds
                net_resources = (
                    isolated_creds_client.isolated_net_resources[
                        isolated_creds_client.type_of_creds])
                net_id = net_resources[0]["id"]
                subnet_id = net_resources[1]["id"]

            # Create suitable share-network
            if share_network_id is None:
                sn_desc = "This share-network was created by tempest"
                __, sn = sc.create_share_network(name=sn_name,
                                                 description=sn_desc,
                                                 neutron_net_id=net_id,
                                                 neutron_subnet_id=subnet_id)
                share_network_id = sn["id"]

        return share_network_id

    @classmethod
    def _create_share(cls, share_protocol=None, size=1, name=None,
                      snapshot_id=None, description=None, metadata=None,
                      share_network_id=None, share_type_id=None,
                      client=None, cleanup_in_class=True, is_public=False):
        client = client or cls.shares_client
        description = description or "Tempest's share"
        share_network_id = share_network_id or client.share_network_id or None
        metadata = metadata or {}
        kwargs = {
            'share_protocol': share_protocol,
            'size': size,
            'name': name,
            'snapshot_id': snapshot_id,
            'description': description,
            'metadata': metadata,
            'share_network_id': share_network_id,
            'share_type_id': share_type_id,
            'is_public': is_public,
        }
        resp, share = client.create_share(**kwargs)
        resource = {"type": "share", "id": share["id"], "client": client}
        cleanup_list = (cls.class_resources if cleanup_in_class else
                        cls.method_resources)
        cleanup_list.insert(0, resource)
        return resp, share

    @classmethod
    def create_share(cls, *args, **kwargs):
        """Create one share and wait for available state. Retry if allowed."""
        result = cls.create_shares(
            [{"args": args, "kwargs": kwargs}], with_resp=True)
        return result[0]

    @classmethod
    def create_shares(cls, share_data_list, with_resp=False):
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
        :param with_resp: boolean -- whether to return list of
            tuples (resp, share) or just list of shares.
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
                "client", cls.shares_client)
            d["resp"], d["share"] = cls._create_share(
                *d["args"], **d["kwargs"])
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
                        d["resp"], d["share"] = cls._create_share(
                            *d["args"], **d["kwargs"])
                    else:
                        raise e

        if with_resp:
            return [(d["resp"], d["share"]) for d in data]
        return [d["share"] for d in data]

    @classmethod
    def create_snapshot_wait_for_active(cls, share_id, name=None,
                                        description=None, force=False,
                                        client=None, cleanup_in_class=True):
        if client is None:
            client = cls.shares_client
        if description is None:
            description = "Tempest's snapshot"
        r, s = client.create_snapshot(share_id, name, description, force)
        resource = {
            "type": "snapshot",
            "id": s["id"],
            "client": client,
        }
        if cleanup_in_class:
            cls.class_resources.insert(0, resource)
        else:
            cls.method_resources.insert(0, resource)
        client.wait_for_snapshot_status(s["id"], "available")
        return r, s

    @classmethod
    def create_share_network(cls, client=None,
                             cleanup_in_class=False, **kwargs):
        if client is None:
            client = cls.shares_client
        resp, sn = client.create_share_network(**kwargs)
        resource = {
            "type": "share_network",
            "id": sn["id"],
            "client": client,
        }
        if cleanup_in_class:
            cls.class_resources.insert(0, resource)
        else:
            cls.method_resources.insert(0, resource)
        return resp, sn

    @classmethod
    def create_security_service(cls, ss_type="ldap", client=None,
                                cleanup_in_class=False, **kwargs):
        if client is None:
            client = cls.shares_client
        resp, ss = client.create_security_service(ss_type, **kwargs)
        resource = {
            "type": "security_service",
            "id": ss["id"],
            "client": client,
        }
        if cleanup_in_class:
            cls.class_resources.insert(0, resource)
        else:
            cls.method_resources.insert(0, resource)
        return resp, ss

    @classmethod
    def create_share_type(cls, name, client=None, cleanup_in_class=True,
                          **kwargs):
        if client is None:
            client = cls.shares_client
        resp, st = client.create_share_type(name, **kwargs)
        resource = {
            "type": "share_type",
            "id": st["share_type"]["id"],
            "client": client,
        }
        if cleanup_in_class:
            cls.class_resources.insert(0, resource)
        else:
            cls.method_resources.insert(0, resource)
        return resp, st

    @staticmethod
    def add_required_extra_specs_to_dict(extra_specs=None):
        value = six.text_type(CONF.share.multitenancy_enabled)
        required = {"driver_handles_share_servers": value}
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
                    else:
                        LOG.warn("Provided unsupported resource type for "
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
            "dns_ip": data_utils.rand_name("ss-dns_ip"),
            "server": data_utils.rand_name("ss-server"),
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
                # If both values aren't convertable to float, just ignore
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
        super(BaseSharesAltTest, cls).resource_setup()


class BaseSharesAdminTest(BaseSharesTest):
    """Base test case class for all Shares Admin API tests."""

    @classmethod
    def resource_setup(cls):
        cls.username = CONF.identity.admin_username
        cls.password = CONF.identity.admin_password
        cls.tenant_name = CONF.identity.admin_tenant_name
        cls.verify_nonempty(cls.username, cls.password, cls.tenant_name)
        cls.os = clients.AdminManager()
        admin_share_network_id = CONF.share.admin_share_network_id
        cls.os.shares_client.share_network_id = admin_share_network_id
        super(BaseSharesAdminTest, cls).resource_setup()
