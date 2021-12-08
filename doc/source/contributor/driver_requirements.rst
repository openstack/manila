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

Manila minimum requirements and features
========================================

In order for a driver to be accepted into manila code base, there are certain
minimum requirements and features that must be met, in order to ensure
interoperability and standardized manila functionality among cloud providers.

At least one driver mode (:term:`DHSS` true/false)
--------------------------------------------------

Driver modes determine if the driver is managing network resources
(:term:`DHSS` = true) in an automated way, in order to segregate tenants and
private networks by making use of manila Share Networks, or if it is up to the
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
- MapRFS
- CephFS

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

In order for manila to function accordingly to the driver being used, the
driver must provide a set of information to manila, known as capabilities.
Share driver can use Share type extra-specs (scoped and un-scoped) to serve
new shares. See :doc:`../admin/capabilities_and_extra_specs` for more
information. At a minimum your driver must report:


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
function correctly in manila, such as:

- dedupe: whether the backend supports deduplication;
- compression: whether the backend supports compressed shares;
- thin_provisioning: whether the backend is overprovisioning shares;
- pools: list of storage pools managed by this driver instance;
- qos: whether the backend supports quality of service for shares;
- replication_domain: string specifying a common group name for all backends
  that can replicate between each other;
- replication_type: string specifying the type of replication supported by
  the driver. Can be one of ('readable', 'writable' or 'dr').
- security_service_update_support: boolean specifying whether the driver
  supports updating or adding security services in an already deployed share
  server. It defaults to ``False``.

Below is an example of drivers with multiple pools. "my" is used as an
example vendor prefix:

::

    {
        'driver_handles_share_servers': 'False',  #\
        'share_backend_name': 'My Backend',       # backend level
        'vendor_name': 'MY',                      # mandatory/fixed
        'driver_version': '1.0',                  # stats & capabilities
        'storage_protocol': 'NFS_CIFS',           #/
                                                  #\
        'my_capability_1': 'custom_val',          # "my" optional vendor
        'my_capability_2': True,                  # stats & capabilities
                                                  #/
        'pools': [
            {'pool_name':
               'thin-dedupe-compression pool',    #\
             'total_capacity_gb': 500,            #  mandatory stats for
             'free_capacity_gb': 230,             #  pools
             'reserved_percentage': 0,            #/
                                                  #\
             'dedupe': True,                      # common capabilities
             'compression': True,                 #
             'snapshot_support': True,            #
             'create_share_from_snapshot_support': True,
             'revert_to_snapshot_support': True,
             'qos': True,                         # this backend supports QoS
             'thin_provisioning': True,           #
             'max_over_subscription_ratio': 10,   # (mandatory for thin)
             'provisioned_capacity_gb': 270,      # (mandatory for thin)
                                                  #
                                                  #
             'replication_type': 'dr',            # this backend supports
                                                  # replication_type 'dr'
                                                  #/
             'my_dying_disks': 100,               #\
             'my_super_hero_1': 'Hulk',           #  "my" optional vendor
             'my_super_hero_2': 'Spider-Man',     #  stats & capabilities
                                                  #/
                                                  #\
                                                  # can replicate to other
             'replication_domain': 'asgard',      # backends in
                                                  # replication_domain 'asgard'
                                                  #/
             'ipv4_support': True,
             'ipv6_support': True,
             'security_service_update_support': False,

            },
            {'pool_name': 'thick pool',
             'total_capacity_gb': 1024,
             'free_capacity_gb': 1024,
             'qos': False,
             'snapshot_support': True,
             'create_share_from_snapshot_support': False, # this pool does not
                                                          # allow creating
                                                          # shares from
                                                          # snapshots
             'revert_to_snapshot_support': True,
             'reserved_percentage': 0,
             'dedupe': False,
             'compression': False,
             'thin_provisioning': False,
             'replication_type': None,
             'my_dying_disks': 200,
             'my_super_hero_1': 'Batman',
             'my_super_hero_2': 'Robin',
             'ipv4_support': True,
             'ipv6_support': True,
             'security_service_update_support': False,
            },
         ]
    }


Continuous Integration systems
------------------------------

Every driver vendor must supply a CI system that tests its drivers
continuously for each patch submitted to OpenStack gerrit. This allows for
better QA and quicker response and notification for driver vendors when a
patch submitted affects an existing driver. The CI system must run all
applicable tempest tests, test all patches Zuul has posted +1 and post its
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
administrators. Also, driver maintainers must update the manila share features
support mapping documentation found at
https://docs.openstack.org/manila/latest/admin/share_back_ends_feature_support_mapping.html

Manila optional requirements and features since Mitaka
======================================================

Additional to the minimum required features supported by manila, other optional
features can be supported by drivers as they are already supported in manila
and can be accessed through the API.

Snapshots
---------

Share Snapshots allow for data respective to a particular point in time to be
saved in order to be used later. In manila API, share snapshots taken can only
be restored by creating new shares from them, thus the original share remains
unaffected. If Snapshots are supported by drivers, they must be
crash-consistent.

Managing/Unmanaging shares
--------------------------

If :term:`DHSS` = false mode is used, then drivers may implement a function
that supports reading existing shares in the backend that were not created by
manila. After the previously existing share is registered in manila, it is
completely controlled by manila and should not be handled externally anymore.
Additionally, a function that de-registers such shares from manila but do
not delete from backend may also be supported.

Share shrinking
---------------

Manila API supports share shrinking, thus a share can be shrunk in a similar
way it can be extended, but the driver is responsible for making sure no data
is compromised.

Share ensuring
--------------

In some situations, such as when the driver is restarted, manila attempts to
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

Share Groups (since Ocata)
--------------------------

The share groups provides the ability to manage a group of shares together.
This feature is implemented at the manager level, every driver gets this feature
by default. If a driver wants to override the default behavior to support
additional functionalities such as consistent group snapshot, the driver
vendors may report this capability as a group capability, such as: Ordered
writes, Consistent snapshots, Group replication.

Drivers need to report group capabilities as part of the updated stats (e.g.
capacity) and filled in 'share_group_stats' node for their back end. Share group
type group-specs (scoped and un-scoped) are available for the driver
implementation to use as-needed. Below is an example of the share stats
payload from the driver having multiple pools and group capabilities. "my"
is used as an example vendor prefix:

::

    {
        'driver_handles_share_servers': 'False',          #\
        'share_backend_name': 'My Backend',               # backend level
        'vendor_name': 'MY',                              # mandatory/fixed
        'driver_version': '1.0',                          # stats & capabilities
        'storage_protocol': 'NFS_CIFS',                   #/
                                                          #\
        'my_capability_1': 'custom_val',                  # "my" optional vendor
        'my_capability_2': True,                          # stats & capabilities
                                                          #/
        'share_group_stats': {
                                                          #\
                'my_group_capability_1': 'custom_val',    # "my" optional vendor
                'my_group_capability_2': True,            # stats & group capabilities
                                                          #/
                'consistent_snapshot_support': 'host',    #\
                                                          # common group capabilities
                                                          #/
            },
         ]
    }


.. note::

  for more information please see :doc:`../admin/group_capabilities_and_extra_specs`

Share Replication
-----------------

Replicas of shares can be created for either data protection (for disaster
recovery) or for load sharing. In order to utilize this feature, drivers must
report the ``replication_type`` they support as a capability and implement
necessary methods.

More details can be found at: :doc:`../admin/shared-file-systems-share-replication`

Update "used_size" of shares
----------------------------
Drivers can update, for all the shares created on a particular backend, the
consumed space in GiB. While the polling interval for drivers to update this
information is configurable, drivers can choose to submit cached information
as necessary, but specify a time at which this information was "gathered_at".

Share Server Migration (Since Victoria)
---------------------------------------

Shares servers can be migrated between different backends. Driver vendors
need to implement the share server migration functions in order to migrate
share servers in an efficient way.
