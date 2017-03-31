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

from oslo_log import log as logging
import six

from manila.scheduler.evaluator import evaluator
from manila.scheduler import utils
from manila.scheduler.weighers import base_host


LOG = logging.getLogger(__name__)


class GoodnessWeigher(base_host.BaseHostWeigher):
    """Goodness Weigher.  Assign weights based on a host's goodness function.

    Goodness rating is the following:

    .. code-block:: none

          0 -- host is a poor choice
          .
          .
         50 -- host is a good choice
          .
          .
        100 -- host is a perfect choice

    """

    def _weigh_object(self, host_state, weight_properties):
        """Determine host's goodness rating based on a goodness_function."""
        stats = self._generate_stats(host_state, weight_properties)
        LOG.debug("Checking host '%s'", stats['host_stats']['host'])
        result = self._check_goodness_function(stats)
        LOG.debug("Goodness: %s", result)
        LOG.debug("Done checking host '%s'", stats['host_stats']['host'])

        return result

    def _check_goodness_function(self, stats):
        """Gets a host's goodness rating based on its goodness function."""

        goodness_rating = 0

        if stats['goodness_function'] is None:
            LOG.warning("Goodness function not set :: defaulting to "
                        "minimal goodness rating of 0.")
        else:
            try:
                goodness_result = self._run_evaluator(
                    stats['goodness_function'],
                    stats)
            except Exception as ex:
                LOG.warning("Error in goodness_function function "
                            "'%(function)s' : '%(error)s' :: Defaulting "
                            "to a goodness of 0.",
                            {'function': stats['goodness_function'],
                             'error': ex, })
                return goodness_rating

            if type(goodness_result) is bool:
                if goodness_result:
                    goodness_rating = 100
            elif goodness_result < 0 or goodness_result > 100:
                LOG.warning("Invalid goodness result.  Result must be "
                            "between 0 and 100.  Result generated: '%s' "
                            ":: Defaulting to a goodness of 0.",
                            goodness_result)
            else:
                goodness_rating = goodness_result

        msg = "Goodness function result for host %(host)s: %(result)s."
        args = {'host': stats['host_stats']['host'],
                'result': six.text_type(goodness_rating)}
        LOG.info(msg, args)

        return goodness_rating

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

    def _generate_stats(self, host_state, weight_properties):
        """Generates statistics from host and share data."""

        goodness_function = None

        if ('goodness_function' in host_state.capabilities and
                host_state.capabilities['goodness_function'] is not None):
            goodness_function = six.text_type(
                host_state.capabilities['goodness_function'])

        stats = utils.generate_stats(host_state, weight_properties)

        stats['goodness_function'] = goodness_function

        return stats
