====================
Manila Sample Policy
====================

.. warning::

   JSON formatted policy file is deprecated since Manila 12.0.0 (Wallaby).
   This `oslopolicy-convert-json-to-yaml`__ tool will migrate your existing
   JSON-formatted policy file to YAML in a backward-compatible way.

.. __: https://docs.openstack.org/oslo.policy/latest/cli/oslopolicy-convert-json-to-yaml.html

The following is a sample Manila policy file that has been auto-generated
from default policy values in code. If you're using the default policies, then
the maintenance of this file is not necessary.
It is here to help explain which policy operations protect specific Manila API,
but it is not suggested to copy and paste into a deployment unless you're planning
on providing a different policy for an operation that is not the default. For
instance, if you want to change the default value of "share:create", you only
need to keep this single rule in your policy config
file (**/etc/manila/policy.yaml**).

.. only:: html

   .. literalinclude:: ../../../_static/manila.policy.yaml.sample
      :language: ini

.. only:: latex

   See the online version of this documentation for the sample file
   (``manila.policy.yaml.sample``).

