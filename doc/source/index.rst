..
      Copyright 2010-2012 United States Government as represented by the
      Administrator of the National Aeronautics and Space Administration.
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

===================================================
OpenStack Shared Filesystems (manila) documentation
===================================================

What is Manila?
---------------

Manila is the OpenStack Shared Filesystems service for providing Shared
Filesystems as a service. Some of the goals of Manila are to be/have:

* **Component based architecture**: Quickly add new behaviors
* **Highly available**: Scale to very serious workloads
* **Fault-Tolerant**: Isolated processes avoid cascading failures
* **Recoverable**: Failures should be easy to diagnose, debug, and rectify
* **Open Standards**: Be a reference implementation for a community-driven api

For end users
-------------

As an end user of Manila, you'll use Manila to create a remote file system with
either tools or the API directly:
`python-manilaclient <https://docs.openstack.org/python-manilaclient/latest/>`_,
or by directly using the
`REST API <https://docs.openstack.org/api-ref/shared-file-system/>`_.

Tools for using Manila
~~~~~~~~~~~~~~~~~~~~~~

Contents:

.. toctree::
   :maxdepth: 1

   user/index

Using the Manila API
~~~~~~~~~~~~~~~~~~~~

All features of Manila are exposed via a REST API that can be used to build
more complicated logic or automation with Manila. This can be consumed directly
or via various SDKs. The following resources can help you get started consuming
the API directly:

* `Manila API <https://docs.openstack.org/api-ref/shared-file-system/>`_
* :doc:`Manila microversion history </contributor/api_microversion_history>`

For operators
-------------

This section has details for deploying and maintaining Manila services.

Installing Manila
~~~~~~~~~~~~~~~~~

Manila can be configured standalone using the configuration setting
``auth_strategy = noauth``, but in most cases you will want to at least have
the `Keystone <https://docs.openstack.org/keystone/latest/install/>`_ Identity
service and other
`OpenStack services <https://docs.openstack.org/latest/install/>`_ installed.

.. toctree::
   :maxdepth: 1

   install/index

Administrating Manila
~~~~~~~~~~~~~~~~~~~~~

Contents:

.. toctree::
   :maxdepth: 1

   admin/index

Reference
~~~~~~~~~

Contents：

.. toctree::
   :maxdepth: 1

   configuration/index
   cli/index

Additional resources
~~~~~~~~~~~~~~~~~~~~

* `Manila release notes <https://docs.openstack.org/releasenotes/manila/>`_

For contributors
----------------

If you are a ``new contributor`` :doc:`start here <contributor/contributing>`.

.. toctree::
   :maxdepth: 1

   contributor/index
   API Microversions </contributor/api_microversion_dev/>

Additional reference
~~~~~~~~~~~~~~~~~~~~

Contents:

.. toctree::
   :maxdepth: 1

   reference/index

.. only:: html

   Additional reference
   ~~~~~~~~~~~~~~~~~~~~

   Contents:

   * :ref:`genindex`

