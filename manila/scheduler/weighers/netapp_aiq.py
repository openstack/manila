# Copyright 2023 NetApp, Inc.
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
from oslo_log import log as logging
from oslo_serialization import jsonutils
import requests
from requests.adapters import HTTPAdapter
from requests import auth
from urllib3.util import retry

from manila import exception
from manila.scheduler.weighers import base_host

ACTIVE_IQ_WEIGHER_GROUP = 'netapp_active_iq'


active_iq_weight_opts = [
    cfg.HostAddressOpt('aiq_hostname',
                       help='The hostname (or IP address) for the Active IQ.'),
    cfg.PortOpt('aiq_port',
                help=('The TCP port to use for communication with the Active '
                      'IQ. If not specified, the weigher driver will use 80 '
                      'for HTTP and 443 for HTTPS.')),
    cfg.StrOpt('aiq_transport_type',
               default='https',
               choices=['http', 'https'],
               help=('The transport protocol used when communicating with '
                     'the Active IQ. Valid values are '
                     'http or https.')),
    cfg.BoolOpt('aiq_ssl_verify',
                default=False,
                help='Verifying the SSL certificate. Default is False.'),
    cfg.StrOpt('aiq_ssl_cert_path',
               help=("The path to a CA_BUNDLE file or directory with "
                     "certificates of trusted CA. If set to a directory, it "
                     "must have been processed using the c_rehash utility "
                     "supplied with OpenSSL. If not informed, it will use the "
                     "Mozilla's carefully curated collection of Root "
                     "Certificates for validating the trustworthiness of SSL "
                     "certificates.")),
    cfg.StrOpt('aiq_username',
               help=('Administrative user account name used to access the '
                     'Active IQ.')),
    cfg.StrOpt('aiq_password',
               help=('Password for the administrative user account '
                     'specified in the aiq_username option.'),
               secret=True),
    cfg.IntOpt('aiq_eval_method',
               default=0,
               help='Integer indicator of which evaluation method, defaults '
                    'to 0 (0 - by index, 1 - normalized value, 2 - by '
                    'literal value).'),
    cfg.ListOpt('aiq_priority_order',
                default=[
                    'ops',
                    'latency',
                    'volume_count',
                    'size'
                ],
                help='Permutation of the list ["volume_count", "size", '
                     '"latency", “ops”]. Note that for volume_count and '
                     'latency, the higher the values, the less optimal the '
                     'resources. For capacity and ops, the higher the value '
                     'the more desirable the resources. If metrics are to be '
                     'considered with equal weights, concatenate the strings, '
                     'separated by ":".'
                     'An example is ["volume_count", "size", “latency:ops”] '
                     'if latency and ops want to have equal but minimum '
                     'weights, or ["volume_count:size", "latency", “ops”] '
                     'if volume_count and size have equal maximum weights. '
                     'If not provided, the default order is '
                     '["volume_count", "size", "latency", “ops”].'),
]
CONF = cfg.CONF
CONF.register_opts(active_iq_weight_opts, ACTIVE_IQ_WEIGHER_GROUP)

LOG = logging.getLogger(__name__)


class NetAppAIQWeigher(base_host.BaseHostWeigher):
    """AIQ Weigher.  Assign weights based on NetApp Active IQ tool."""

    def __init__(self, *args, **kwargs):
        super(NetAppAIQWeigher, self).__init__(*args, **kwargs)

        self.configuration = CONF[ACTIVE_IQ_WEIGHER_GROUP]

        self.host = self.configuration.aiq_hostname
        if not self.host:
            raise exception.NetappActiveIQWeigherRequiredParameter(
                config="aiq_hostname")

        self.username = self.configuration.aiq_username
        if not self.username:
            raise exception.NetappActiveIQWeigherRequiredParameter(
                config="aiq_username")

        self.password = self.configuration.aiq_password
        if not self.password:
            raise exception.NetappActiveIQWeigherRequiredParameter(
                config="aiq_password")

        self.protocol = self.configuration.aiq_transport_type
        self.port = self.configuration.aiq_port
        if not self.port:
            self.port = "80" if self.protocol == "http" else "443"

        self.ssl_verify = self.configuration.aiq_ssl_verify
        if self.ssl_verify and self.configuration.aiq_ssl_cert_path:
            self.ssl_verify = self.configuration.aiq_ssl_cert_path

        self.eval_method = self.configuration.aiq_eval_method
        self.priority_order = self.configuration.aiq_priority_order

    def _weigh_object(self, host_state, weight_properties):
        """Weight for a specific object from parent abstract class"""
        # NOTE(felipe_rodrigues): this abstract class method is not called for
        # the AIQ weigher, since it does not weigh one single object.
        raise NotImplementedError()

    def _weigh_active_iq(self, netapp_aggregates_location, weight_properties):
        """Determine host's rating based on a Active IQ."""
        size = weight_properties.get('size')
        share_type = weight_properties.get('share_type', {})
        performance_level_name = share_type.get('extra_specs', {}).get(
            'netapp:performance_service_level_name')

        # retrieves the performance service level key if a PSL name is given.
        performance_level_id = None
        if performance_level_name:
            performance_level_id = self._get_performance_level_id(
                performance_level_name)
            if not performance_level_id:
                return []

        # retrieves the equivalent active IQ keys of the pools.
        resource_keys = self._get_resource_keys(netapp_aggregates_location)
        if len(resource_keys) == 0:
            return []

        result = self._balance_aggregates(resource_keys, size,
                                          performance_level_id)

        return result

    def _get_url(self):
        """Get the base URL for REST requests."""
        host = self.host
        if ':' in host:
            host = '[%s]' % host
        return f'{self.protocol}://{host}:{self.port}/api/'

    def _get_request_method(self, method, session):
        """Returns the request method to be used in the REST call."""

        request_methods = {
            'post': session.post,
            'get': session.get,
            'put': session.put,
            'delete': session.delete,
            'patch': session.patch,
        }
        return request_methods[method]

    def _get_session_method(self, method):
        """Get the REST method from the session."""

        # NOTE(felipe_rodrigues): request resilient of temporary network
        # failures (like name resolution failure), retrying until 5 times.
        _session = requests.Session()
        max_retries = retry.Retry(total=5, connect=5, read=2, backoff_factor=1)
        adapter = HTTPAdapter(max_retries=max_retries)
        _session.mount('%s://' % self.protocol, adapter)

        _session.auth = auth.HTTPBasicAuth(self.username, self.password)
        _session.verify = self.ssl_verify
        _session.headers = {}

        return self._get_request_method(method, _session)

    def _call_active_iq(self, action_path, method, body=None):
        """Call the Active IQ REST API."""
        rest_method = self._get_session_method(method)
        url = self._get_url() + action_path

        msg_args = {
            "method": method.upper(),
            "url": url,
            "body": body,
        }
        LOG.debug("REQUEST: %(method)s %(url)s Body=%(body)s", msg_args)

        response = rest_method(url, json=body)

        code = response.status_code
        response_body = response.content
        msg_args = {
            "code": code,
            "body": response_body,
        }
        LOG.debug("RESPONSE: %(code)s Body=%(body)s", msg_args)

        return code, response_body

    def _get_performance_level_id(self, performance_level_name):
        """Gets the ID of a performance level name."""
        psl_endpoint = (f'storage-provider/performance-service-levels?'
                        f'name={performance_level_name}')
        try:
            code, res = self._call_active_iq(psl_endpoint, "get")
        except Exception as e:
            LOG.error("Could not retrieve the key of the performance service "
                      "level named as '%(psl)s'. Skipping the weigher. "
                      "Error: %(error)s",
                      {'psl': performance_level_name, 'error': e})
            LOG.error(e)
            return None

        if code != 200:
            LOG.error("Could not retrieve the key of the performance service "
                      "level named as '%(psl)s'. Skipping the weigher.",
                      {'psl': performance_level_name})
            return None

        res = jsonutils.loads(res) if res else {}
        psl_list = res.get('records', [])
        if len(psl_list) == 0:
            LOG.error("Could not found any performance service level named "
                      "as '%s'. Skipping the weigher.", performance_level_name)
            return None

        return psl_list[0].get("key", None)

    def _get_aggregate_identifier(self, aggr_name, cluster_name):
        """Returns the string identifier of an aggregate on a cluster."""
        return f'{aggr_name}:{cluster_name}'

    def _get_resource_keys(self, netapp_aggregates_location):
        """Map the aggregates names to the AIQ resource keys."""
        aggregate_endpoint = 'datacenter/storage/aggregates'

        try:
            code, res = self._call_active_iq(aggregate_endpoint, "get")
        except Exception as e:
            LOG.error("Could not retrieve the aggregates resource keys. "
                      "Skipping the weigher. Error: %s", e)
            LOG.error(e)
            return []

        if code != 200:
            LOG.error("Could not retrieve the aggregates resource keys. "
                      "Skipping the weigher.")
            return []

        res = jsonutils.loads(res) if res else {}
        aggr_map = {}
        for aggr in res.get('records', []):
            identifier = self._get_aggregate_identifier(
                aggr["name"], aggr["cluster"]["name"])
            aggr_map[identifier] = aggr["key"]

        # we must keep the lists with the same order.
        resource_keys = []
        found_pool_keys = []
        for identifier in netapp_aggregates_location:
            if identifier in aggr_map:
                found_pool_keys.append(identifier)
            # If a pool could not be found, it is marked as resource key 0.
            resource_keys.append(aggr_map.get(identifier, 0))

        LOG.debug("The following pools will be evaluated by Active IQ: %s",
                  found_pool_keys)

        return resource_keys

    def _balance_aggregates(self, resource_keys, size, performance_level_uuid):
        """Call AIQ to generate the weights of each aggregate."""
        balance_endpoint = 'storage-provider/data-placement/balance'
        body = {
            "capacity": f'{size}GB',
            "eval_method": self.eval_method,
            # NOTE(felipe_rodrigues): from Active IQ documentation, the
            # opt_method only works as 0.
            "opt_method": 0,
            "priority_order": self.priority_order,
            "separate_flag": False,
            # NOTE(felipe_rodrigues): remove the keys marked with 0, since they
            # are not found the pool keys.
            "resource_keys": [key for key in resource_keys if key != 0],
        }
        if performance_level_uuid:
            body["ssl_key"] = performance_level_uuid

        try:
            code, res = self._call_active_iq(
                balance_endpoint, "post", body=body)
        except Exception as e:
            LOG.error("Could not balance the aggregates. Skipping the "
                      "weigher. Error: %s", e)
            LOG.error(e)
            return []

        if code != 200:
            LOG.error("Could not balance the aggregates. Skipping the "
                      "weigher.")
            return []

        res = jsonutils.loads(res) if res else []
        weight_map = {}
        for aggr in res:
            weight_map[aggr["key"]] = aggr["scores"]["total_weighted_score"]

        # it must keep the lists with the same order.
        weights = []
        for key in resource_keys:
            weights.append(weight_map.get(key, 0.0))

        return weights

    def weigh_objects(self, weighed_obj_list, weight_properties):
        """Weigh multiple objects using Active IQ."""
        netapp_aggregates_location = []
        for obj in weighed_obj_list:

            # if at least one host is not from NetApp, the entire weigher is
            # skipped.
            if obj.obj.vendor_name != "NetApp":
                LOG.debug(
                    "Skipping Active IQ weigher given that some backends "
                    "are not from NetApp.")
                return []
            else:
                cluster_name = obj.obj.capabilities.get("netapp_cluster_name")
                aggr_name = obj.obj.pool_name
                netapp_aggregates_location.append(
                    self._get_aggregate_identifier(aggr_name, cluster_name))

        result = self._weigh_active_iq(
            netapp_aggregates_location, weight_properties)

        LOG.debug("Active IQ weight result: %s", result)
        return result
