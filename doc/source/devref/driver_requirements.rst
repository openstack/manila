..
      Copyright (c) 2015 Hitachi Data Systems
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

Manila minimum requirements and features since Mitaka
=====================================================

In order for a driver to be accepted into Manila code base, there are certain
minimum requirements and features that must be met, in order to ensure
interoperability and standardized Manila functionality among cloud providers.

At least one driver mode (:term:`DHSS` true/false)
--------------------------------------------------

Driver modes determine if the driver is managing network resources
(:term:`DHSS` = true) in an automated way, in order to segregate tenants and
private networks by making use of Manila Share Networks, or if it is up to the
administrator to manually configure all networks (:term:`DHSS` = false) and be
responsible for segregation, if that is desired. At least one driver mode must
be supported. In :term:`DHSS` = true mode, Share Server entities are used, so
the driver must implement functions that setup and teardown such servers.

At least one file system sharing protocol
-----------------------------------------

In order to serve shares as a shared file system service, the driver must
support at least one file system sharing protocol, which can be a new protocol
or one of the currently supported protocols. The current list of supported
protocols is as follows:

- NFS
- CIFS
- GlusterFS
- HDFS

Access rules
------------

Access rules control how shares are accessible, by whom, and what the level of
access is. Access rule operations include allowing access and denying access
to a given share. The authentication type should be based on IP, User and/or
Certificate. Drivers must support read-write and read-only access levels for each
supported protocol, either through individual access rules or separate export
locations.

Shares
------

Share servicing is the core functionality of a shared file system service, so
a driver must be able to create and delete shares.

Share extending
---------------

In order to best satisfy cloud service requirements, shares must be elastic, so
drivers must implement a share extend function that allows shares' size to be
increased.

Capabilities
------------

In order for Manila to function accordingly to the driver being used, the
driver must provide a set of information to Manila, known as capabilities, as
follows:

- share_backend_name: a name for the backend;
- driver_handles_share_servers: driver mode, whether this driver instance
  handles share servers, possible values are true or false;
- vendor_name: driver vendor name;
- driver_version: current driver instance version;
- storage_protocol: list of shared file system protocols supported by this
  driver instance;
- total_capacity_gb: total amount of storage space provided, in GB;
- free_capacity_gb: amount of storage space available for use, in GB;
- reserved_percentage: percentage of total storage space to be kept from being
  used.

Certain features, if supported by drivers, need to be reported in order to
function correctly in Manila, such as:

- dedupe: whether the backend supports deduplication;
- compression: whether the backend supports compressed shares;
- thin_provisioning: whether the backend is overprovisioning shares;
- pools: list of storage pools managed by this driver instance;
- qos: whether the backend supports quality of service for shares.

.. note:: for more information please see http://docs.openstack.org/developer/manila/devref/capabilities_and_extra_specs.html

Continuous Integration systems
------------------------------

Every driver vendor must supply a CI system that tests its drivers
continuously for each patch submitted to OpenStack gerrit. This allows for
better QA and quicker response and notification for driver vendors when a
patch submitted affects an existing driver. The CI system must run all
applicable tempest tests, test all patches Jenkins has posted +1 and post its
test results.

.. note:: for more information please see http://docs.openstack.org/infra/system-config/third_party.html

Unit tests
----------

All drivers submitted must be contemplated with unit tests covering at least
90% of the code, preferably 100% if possible. Unit tests must use mock
framework and be located in-tree using a structure that mirrors the functional
code, such as directory names and filenames. See template below:

  ::

    manila/[tests/]path/to/brand/new/[test_]driver.py

Documentation
-------------

Drivers submitted must provide and maintain related documentation on
openstack-manuals, containing instructions on how to properly install and
configure. The intended audience for this manual is cloud operators and
administrators. Also, driver maintainers must update the Manila share features
support mapping documentation found at
http://docs.openstack.org/developer/manila/devref/share_back_ends_feature_support_mapping.html


Manila optional requirements and features since Mitaka
======================================================

Additional to the minimum required features supported by Manila, other optional
features can be supported by drivers as they are already supported in Manila
and can be accessed through the API.

Snapshots
---------

Share Snapshots allow for data respective to a particular point in time to be
saved in order to be used later. In Manila API, share snapshots taken can only
be restored by creating new shares from them, thus the original share remains
unaffected. If Snapshots are supported by drivers, they must be
crash-consistent.

Managing/Unmanaging shares
--------------------------

If :term:`DHSS` = false mode is used, then drivers may implement a function
that supports reading existing shares in the backend that were not created by
Manila. After the previously existing share is registered in Manila, it is
completely controlled by Manila and should not be handled externally anymore.
Additionally, a function that de-registers such shares from Manila but do
not delete from backend may also be supported.

Share shrinking
---------------

Manila API supports share shrinking, thus a share can be shrunk in a similar
way it can be extended, but the driver is responsible for making sure no data
is compromised.

Share ensuring
--------------

In some situations, such as when the driver is restarted, Manila attempts to
perform maintenance on created shares, on the purpose of ensuring previously
created shares are available and being serviced correctly. The driver can
implement this function by checking shares' status and performing maintenance
operations if needed, such as re-exporting.


Manila experimental features since Mitaka
=========================================

Some features are initially released as experimental and can be accessed by
including specific additional HTTP Request headers. Those features are not
recommended for production cloud environments while in experimental stage.

Share Migration
---------------

Shares can be migrated between different backends and pools. Manila implements
migration using an approach that works for any manufacturer, but driver vendors
can implement a better optimized migration function for when migration involves
backends or pools related to the same vendor.

Consistency Groups
------------------

Shares can be created within Consistency Groups in order to guarantee snapshot
consistency of multiple shares. In order to make use of this feature, driver
vendors must report this capability and implement its functions to work
according to the backend, so the feature can be properly invoked through
Manila API.
