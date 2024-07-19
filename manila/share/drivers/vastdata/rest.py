# Copyright 2024 VAST Data Inc.
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
from abc import ABC
import json
import pprint
import textwrap

import cachetools
from oslo_log import log as logging
from oslo_utils import versionutils
from packaging import version as packaging_version
import requests

from manila import exception
from manila.share.drivers.vastdata import driver_util
import manila.utils as manila_utils

LOG = logging.getLogger(__name__)


class Session(requests.Session):

    def __init__(self, host, username, password, ssl_verify, plugin_version):
        super().__init__()
        self.base_url = f"https://{host.strip('/')}/api"
        self.ssl_verify = ssl_verify
        self.username = username
        self.password = password
        self.headers["Accept"] = "application/json"
        self.headers["Content-Type"] = "application/json"
        self.headers["User-Agent"] = (
            f"manila/v{plugin_version}"
            f" ({requests.utils.default_user_agent()})"
        )
        # will be updated on first request
        self.headers["authorization"] = "Bearer"

        if not ssl_verify:
            import urllib3

            urllib3.disable_warnings()

    def refresh_auth_token(self):
        try:
            resp = super().request(
                "POST",
                f"{self.base_url}/token/",
                verify=self.ssl_verify,
                timeout=5,
                json={"username": self.username, "password": self.password},
            )
            resp.raise_for_status()
            token = resp.json()["access"]
            self.headers["authorization"] = f"Bearer {token}"
        except ConnectionError as e:
            raise exception.VastApiException(
                reason=f"The vms on the designated host {self.base_url} "
                f"cannot be accessed. Please verify the specified endpoint. "
                f"origin error: {e}"
            )

    @manila_utils.retry(retry_param=exception.VastApiRetry, retries=3)
    def request(
            self, verb, api_method, params=None, log_result=True, **kwargs
    ):
        verb = verb.upper()
        api_method = api_method.strip("/")
        url = f"{self.base_url}/{api_method}/"
        log_pref = f"\n[{verb}] {url}"

        if "data" in kwargs:
            kwargs["data"] = json.dumps(kwargs["data"])

        if log_result and (params or kwargs):
            payload = dict(kwargs, params=params)
            formatted_request = textwrap.indent(
                pprint.pformat(payload), prefix="|  "
            )
            LOG.debug(f"{log_pref} >>>:\n{formatted_request}")
        else:
            LOG.debug(f"{log_pref} >>> (request)")

        ret = super().request(
            verb, url, verify=self.ssl_verify, params=params, **kwargs
        )
        if ret.status_code == 403 and "Token is invalid" in ret.text:
            self.refresh_auth_token()
            raise exception.VastApiRetry(reason="Token is invalid or expired.")

        if ret.status_code in (400, 503) and ret.text:
            raise exception.VastApiException(reason=ret.text)

        try:
            ret.raise_for_status()
        except Exception as exc:
            raise exception.VastApiException(reason=str(exc))

        ret = ret.json() if ret.content else {}
        if ret and log_result:
            formatted_response = textwrap.indent(
                pprint.pformat(ret), prefix="|  "
            )
            LOG.debug(f"{log_pref} <<<:\n{formatted_response}")
        else:
            LOG.debug(f"{log_pref} <<< (response)")
        return driver_util.Bunch.from_dict(ret)

    def __getattr__(self, attr):
        if attr.startswith("_"):
            raise AttributeError(attr)

        def func(**params):
            return self.request("get", attr, params=params)

        func.__name__ = attr
        setattr(self, attr, func)
        return func


def requisite(semver: str, operation: str = None):
    """Use this decorator to indicate the minimum required version cluster

     for invoking the API that is being decorated.
    Decorator works in two modes:
    1. When ignore == False and version mismatch detected then
        `OperationNotSupported` exception will be thrown
    2. When ignore == True and version mismatch detected then
        method decorated method execution never happened
    """

    def dec(fn):

        def _args_wrapper(self, *args, **kwargs):

            version = packaging_version.parse(
                self.rest.get_sw_version().replace("-", ".")
            )
            sw_version = f"{version.major}.{version.minor}.{version.micro}"

            if not versionutils.is_compatible(
                    semver, sw_version, same_major=False
            ):
                op = operation or fn.__name__
                raise exception.VastDriverException(
                    f"Operation {op} is not supported"
                    f" on VAST version {sw_version}."
                    f" Required version is {semver}"
                )
            return fn(self, *args, **kwargs)

        return _args_wrapper

    return dec


class VastResource(ABC):
    resource_name = None

    def __init__(self, rest):
        self.rest = rest  # For intercommunication between resources.
        self.session = rest.session

    def list(self, **params):
        """Get list of entries with optional filtering params"""
        return self.session.get(self.resource_name, params=params)

    def create(self, **params):
        """Create new entry with provided params"""
        return self.session.post(self.resource_name, data=params)

    def update(self, entry_id, **params):
        """Update entry by id with provided params"""
        return self.session.patch(
            f"{self.resource_name}/{entry_id}", data=params
        )

    def delete(self, name):
        """Delete entry by name. Skip if entry not found."""
        entry = self.one(name)
        if not entry:
            resource = self.__class__.__name__.lower()
            LOG.warning(
                f"{resource} {name} not found on VAST, skipping delete"
            )
            return
        return self.session.delete(f"{self.resource_name}/{entry.id}")

    def one(self, name):
        """Get single entry by name.

         Raise exception if multiple entries found.
         """
        entries = self.list(name=name)
        if not entries:
            return
        if len(entries) > 1:
            resource = self.__class__.__name__.lower() + "s"
            raise exception.VastDriverException(
                reason=f"Too many {resource} found with name {name}"
            )
        return entries[0]

    def ensure(self, name, **params):
        entry = self.one(name)
        if not entry:
            entry = self.create(name=name, **params)
        return entry


class View(VastResource):
    resource_name = "views"

    def create(self, name, path, policy_id):
        data = dict(
            name=name,
            path=path,
            policy_id=policy_id,
            create_dir=True,
            protocols=["NFS"],
        )
        return super().create(**data)


class ViewPolicy(VastResource):
    resource_name = "viewpolicies"


class CapacityMetrics(VastResource):

    def get(self, metrics, object_type="cluster", time_frame="1m"):
        """Get capacity metrics for the cluster"""
        params = dict(
            prop_list=metrics,
            object_type=object_type, time_frame=time_frame
        )
        ret = self.session.get("monitors/ad_hoc_query", params=params)
        last_sample = ret.data[-1]
        return driver_util.Bunch(
            {
                name.partition(",")[-1]: value
                for name, value in zip(ret.prop_list, last_sample)
            }
        )


class Quota(VastResource):
    resource_name = "quotas"


class VipPool(VastResource):
    resource_name = "vippools"

    def vips(self, pool_name):
        """Get list of ip addresses from vip pool"""
        vippool = self.one(name=pool_name)
        if not vippool:
            raise exception.VastDriverException(
                reason=f"No vip pool found with name {pool_name}"
            )
        vips = driver_util.generate_ip_range(vippool.ip_ranges)
        if not vips:
            raise exception.VastDriverException(
                reason=f"Pool {pool_name} has no available vips"
            )
        return vips


class Snapshots(VastResource):
    resource_name = "snapshots"


class Folders(VastResource):
    resource_name = "folders"

    @requisite(semver="4.7.0")
    def delete(self, path):
        try:
            self.session.delete(
                f"{self.resource_name}/delete_folder/", data=dict(path=path)
            )
        except exception.VastApiException as e:
            exc_msg = str(e)
            if "no such directory" in exc_msg:
                LOG.debug(f"remote directory "
                          f"might have been removed earlier. ({e})")
            elif "trash folder disabled" in exc_msg:
                raise exception.VastDriverException(
                    reason="Trash Folder Access is disabled"
                    " (see Settings/Cluster/Features in VMS)"
                )
            else:
                # unpredictable error
                raise


class RestApi:

    def __init__(self, host, username, password, ssl_verify, plugin_version):
        self.session = Session(
            host=host,
            username=username,
            password=password,
            ssl_verify=ssl_verify,
            plugin_version=plugin_version,
        )
        self.views = View(self)
        self.view_policies = ViewPolicy(self)
        self.capacity_metrics = CapacityMetrics(self)
        self.quotas = Quota(self)
        self.vip_pools = VipPool(self)
        self.snapshots = Snapshots(self)
        self.folders = Folders(self)

        # Refresh auth token to avoid initial "forbidden" status error.
        self.session.refresh_auth_token()

    @cachetools.cached(cache=cachetools.TTLCache(ttl=60 * 60, maxsize=1))
    def get_sw_version(self):
        """Software version of cluster Rest API interacts with"""
        return self.session.versions(status="success")[0].sys_version
