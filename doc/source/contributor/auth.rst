..
      Copyright 2010-2011 United States Government as represented by the
      Administrator of the National Aeronautics and Space Administration.
      Copyright 2014 Mirantis, Inc.
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

.. _auth:

Authentication and Authorization
================================

The :mod:`manila.quota` Module
------------------------------

.. automodule:: manila.quota
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:

The :mod:`manila.policy` Module
-------------------------------

.. automodule:: manila.policy
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:


Tests
-----

The :mod:`test_quota` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.tests.test_quota
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:

The :mod:`test_policy` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.tests.test_policy
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:


System limits
-------------

The following limits need to be defined and enforced:

*   Maximum cumulative size of shares and snapshots (GB)
*   Total number of shares
*   Total number of snapshots
*   Total number of share networks
