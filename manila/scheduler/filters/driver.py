# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
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

import six

from oslo_log import log as logging

from manila.scheduler.evaluator import evaluator
from manila.scheduler.filters import base_host
from manila.scheduler import utils


LOG = logging.getLogger(__name__)


class DriverFilter(base_host.BaseHostFilter):
    """DriverFilter filters hosts based on a 'filter function' and metrics.

    DriverFilter filters based on share host's provided 'filter function'
    and metrics.
    """

    def host_passes(self, host_state, filter_properties):
        """Determines whether a host has a passing filter_function or not."""
        stats = self._generate_stats(host_state, filter_properties)

        LOG.debug("Driver Filter: Checking host '%s'",
                  stats['host_stats']['host'])
        result = self._check_filter_function(stats)
        LOG.debug("Result: %s", result)
        LOG.debug("Done checking host '%s'", stats['host_stats']['host'])

        return result

    def _check_filter_function(self, stats):
        """Checks if a share passes a host's filter function.

           Returns a tuple in the format (filter_passing, filter_invalid).
           Both values are booleans.
        """

        if stats['filter_function'] is None:
            LOG.debug("Filter function not set :: passing host.")
            return True

        try:
            filter_result = self._run_evaluator(stats['filter_function'],
                                                stats)
        except Exception as ex:
            # Warn the admin for now that there is an error in the
            # filter function.
            LOG.warning("Error in filtering function "
                        "'%(function)s' : '%(error)s' :: failing host.",
                        {'function': stats['filter_function'],
                         'error': ex, })
            return False

        msg = "Filter function result for host %(host)s: %(result)s."
        args = {'host': stats['host_stats']['host'],
                'result': six.text_type(filter_result)}
        LOG.info(msg, args)

        return filter_result

    def _run_evaluator(self, func, stats):
        """Evaluates a given function using the provided available stats."""
        host_stats = stats['host_stats']
        host_caps = stats['host_caps']
        extra_specs = stats['extra_specs']
        share_stats = stats['share_stats']

        result = evaluator.evaluate(
            func,
            extra=extra_specs,
            stats=host_stats,
            capabilities=host_caps,
            share=share_stats)

        return result

    def _generate_stats(self, host_state, filter_properties):
        """Generates statistics from host and share data."""

        filter_function = None

        if ('filter_function' in host_state.capabilities and
                host_state.capabilities['filter_function'] is not None):
            filter_function = six.text_type(
                host_state.capabilities['filter_function'])

        stats = utils.generate_stats(host_state, filter_properties)

        stats['filter_function'] = filter_function

        return stats
