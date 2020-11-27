====================
Policy configuration
====================

.. warning::

   JSON formatted policy file is deprecated since Manila 12.0.0 (Wallaby).
   This `oslopolicy-convert-json-to-yaml`__ tool will migrate your existing
   JSON-formatted policy file to YAML in a backward-compatible way.

.. __: https://docs.openstack.org/oslo.policy/latest/cli/oslopolicy-convert-json-to-yaml.html

Configuration
~~~~~~~~~~~~~

.. only:: html

   The following is an overview of all available policies in Manila.

   .. show-policy::
      :config-file: etc/manila/manila-policy-generator.conf

.. only:: latex

   See the online version of this documentation for the list of available
   policies in Manila.
