.. _capabilities_and_extra_specs:

Capabilities and Extra-Specs
============================
Cloud Administrators create :ref:`shared_file_systems_share_types` with
extra-specs to:

- influence the scheduler's decision to place new shares, and
- instruct the Shared File System service or its storage driver/s to perform
  certain special actions with respect to the users' shares.

As an administrator, you can choose a descriptive name or provide good
descriptions for your share types to convey the share type capabilities to
end users. End users can view standard ``tenant-visible`` extra-specs that
can let them seek required behavior and automate their applications
accordingly. By design, however, all other extra-specs of a share type are not
exposed to non-privileged users.

Types of Extra-Specs
--------------------

The Shared File Systems service back-end storage drivers offer a wide range of
capabilities. The variation in these capabilities allows cloud
administrators to provide a storage service catalog to their end users.
Share type extra-specs tie-in with these capabilities.

Some back-end capabilities are very specific to a storage system, and are
opaque to the Shared File System service or the end users. These
capabilities are invoked with the help of "scoped" extra-specs. Using scoped
extra-specs is a way to provide programmatic directives to the concerned
storage driver to do something during share creation or share manipulation.
You can learn about the opaque capabilities through driver documentation
and configure these capabilities within share types as scoped
extra-specs (e.g.: hpe3par:nfs_options). The Shared File System service
scheduler ignores scoped extra-specs during its quest to find the right back
end to provision shares.

There are some back-end capabilities in manila that do matter to the scheduler.
For our understanding, lets call these non-scoped or non-opaque capabilities.
All non-scoped capabilities can be directly used as share types extra-specs.
They are considered by the scheduler’s capabilities filter (and any custom
filter defined by deployers).

You can get a list of non-scoped capabilities from the scheduler by using:

.. code-block:: console

    $ manila pool-list --detail

The non-scoped capabilities can be of three types:

- **Capabilities pertaining to a specific back end storage system driver**: For
  example, *huawei_smartcache*.
  No Shared File System service API relies on non-opaque back end specific
  capabilities.
- **Common capabilities that are not visible to end users**: The manila
  community has standardized some cross-platform capabilities like
  *thin_provisioning*, *dedupe*, *compression*, *qos*, *ipv6_support* and
  *ipv4_support*. Values of these options do not matter to any Shared File
  System service APIs; however, they can signify something to the manila
  services themselves. For example when a back end supports thin_provisioning,
  the scheduler service performs over-provisioning, and if a back end does
  not report *ipv6_support* as True, the share-manager service drops IPv6
  access rules before invoking the storage driver to update access rules.
- **Common capabilities that are visible to end users**: Some capabilities
  affect functionality exposed via the Shared File System service API. For
  example, not all back ends support snapshots, and even if they do, they
  may not support all of the snapshot operations. For example, cloning
  snapshots into new shares, reverting shares in-place to snapshots, etc.

  The support for these capabilities determines whether users would be able
  to perform certain control-plane operations with manila. For example, a back
  end driver may report *snapshot_support=True* allowing end users to
  create share snapshots, however, the driver can report
  *create_share_from_snapshot_support=False*.
  This reporting allows cloud administrators to create share types that
  support snapshots but not creating shares from snapshots. When a user uses
  such a share type, they will not be able to clone snapshots into new shares.
  Tenant-visible capabilities aid manila in validating requests and failing
  fast on requests it cannot accommodate. They also help level set the user
  expectations on some failures. For example, if snapshot_support is set to
  False on the share type, since users can see this, they will not invoke
  the create snapshot API, and even if they do, they will understand the
  HTTP 400 (and error message) in better context.

.. important::

    All extra-specs are optional, except one: *driver_handles_share_servers*.

Scheduler's treatment of non-scoped extra specs
-----------------------------------------------

The CapabilitiesFilter in the Shared File System scheduler uses the following
for matching operators:

* No operator
  This defaults to doing a python ==. Additionally it will match boolean values.

* **<=, >=, ==, !=**

  This does a float conversion and then uses the python operators as expected.

* **<in>**

  This either chooses a host that has partially matching string in the capability
  or chooses a host if it matches any value in a list. For example, if "<in> sse4"
  is used, it will match a host that reports capability of "sse4_1" or "sse4_2".

* **<or>**

  This chooses a host that has one of the items specified. If the first word in
  the string is <or>, another <or> and value pair can be concatenated. Examples
  are "<or> 3", "<or> 3 <or> 5", and "<or> 1 <or> 3 <or> 7". This is for
  string values only.

* **<is>**

  This chooses a host that matches a boolean capability. An example extra-spec value
  would be "<is> True".

* **=**

  This does a float conversion and chooses a host that has equal to or greater
  than the resource specified. This operator behaves this way for historical
  reasons.

* **s==, s!=, s>=, s>, s<=, s<**

  The "s" indicates it is a string comparison. These choose a host that
  satisfies the comparison of strings in capability and specification. For
  example, if "capabilities:replication_type s== dr", a host that reports
  replication_type of "dr" will be chosen. If "share_backend_name s!=
  cephfs" is used, any host not named "cephfs" can be chosen.

For vendor-specific non-scoped capabilities (which need to be visible to the
scheduler), drivers are recommended to use the vendor prefix followed
by an underscore. This is not a strict requirement, but can provide a
consistent look along-side the scoped extra-specs and will be a clear
indicator of vendor capabilities vs. common capabilities.

Common Capabilities
-------------------
Common capabilities apply to multiple backends.
Like all other backend reported capabilities, these capabilities
can be used verbatim as extra_specs in share types used to create shares.

Share type common capability extra-specs that are visible to end users:
-----------------------------------------------------------------------

* **driver_handles_share_servers** is a special, required common
  capability. When set to True, the scheduler matches requests with back ends
  that can isolate user workloads with dedicated share servers exporting
  shares on user provided share networks.

* **snapshot_support** indicates whether snapshots are supported for shares
  created on the pool/backend. When administrators do not set this capability
  as an extra-spec in a share type, the scheduler can place new shares of that
  type in pools without regard for whether snapshots are supported, and those
  shares will not support snapshots.

* **create_share_from_snapshot_support** indicates whether a backend can
  create a new share from a snapshot. When administrators do not set this
  capability as an extra-spec in a share type, the scheduler can place new
  shares of that type in pools without regard for whether creating shares
  from snapshots is supported, and those shares will not support creating
  shares from snapshots.

* **revert_to_snapshot_support** indicates that a driver is capable of
  reverting a share in place to its most recent snapshot. When administrators
  do not set this capability as an extra-spec in a share type, the scheduler
  can place new shares of that type in pools without regard for whether
  reverting shares to snapshots is supported, and those shares will not support
  reverting shares to snapshots.

* **mount_snapshot_support** indicates that a driver is capable of exporting
  share snapshots for mounting. Users can provide and revoke access to
  mountable snapshots just like they can with their shares.

* **replication_type** indicates the style of replication supported for the
  backend/pool. This extra_spec will have a string value and could be one
  of :term:`writable`, :term:`readable` or :term:`dr`. `writable` replication
  type involves synchronously replicated shares where all replicas are
  writable. Promotion is not supported and not needed. `readable` and `dr`
  replication types involve a single `active` or `primary` replica and one or
  more `non-active` or secondary replicas per share. In `readable` type of
  replication, `non-active` replicas have one or more export_locations and
  can thus be mounted and read while the `active` replica is the only one
  that can be written into. In `dr` style of replication, only
  the `active` replica can be mounted, read from and written into.

* **availability_zones** indicates a comma separated list of availability
  zones that can be used for provisioning. Users can always provide a specific
  availability zone during share creation, and they will receive a
  synchronous failure message if they attempt to create a share in an
  availability zone that the share type does not permit. If you do not set
  this extra-spec, the share type is assumed to be serviceable in all
  availability zones known to the Shared File Systems service.

Share type common capability extra-specs that are not visible to end users:
---------------------------------------------------------------------------

* **dedupe** indicates that a backend/pool can provide shares using some
  deduplication technology. The default value of the dedupe capability (if a
  driver doesn't report it) is False. Drivers can support both dedupe and
  non-deduped shares in a single storage pool by reporting ``dedupe=[True,
  False]``. You can make a share type use deduplication by setting this
  extra-spec to '<is> True', or prevent it by setting this extra-spec
  to '<is> False'.

* **compression** indicates that a backend/pool can provide shares using some
  compression technology. The default value of the compression capability (if a
  driver doesn't report it) is False. Drivers can support compressed and
  non-compressed shares in a single storage pool by reporting
  ``compression=[True, False]``. You can make a share type use compression
  by setting this extra-spec to '<is> True', or prevent it by setting this
  extra-spec to '<is> False'.

* **thin_provisioning** can be enabled where shares will not be
  guaranteed space allocations and overprovisioning will be enabled. This
  capability defaults to False. Back ends/pools that support thin
  provisioning report True for this capability. Administrators can make a
  share type use thin provisioned shares by setting this extra-spec
  to '<is> True'. If a driver reports thin_provisioning=False (the default)
  then it's assumed that the driver is doing thick provisioning and
  overprovisioning is turned off. A driver can support thin provisioned
  and thick provisioned shares in the same pool by reporting
  ``thin_provisioning=[True, False]``.

  To provision a thick
  share on a back end that supports both thin and thick provisioning, set one
  of the following in extra specs:

::

    {'thin_provisioning': 'False'}
    {'thin_provisioning': '<is> False'}
    {'capabilities:thin_provisioning': 'False'}
    {'capabilities:thin_provisioning': '<is> False'}

* **qos** indicates that a backend/pool can provide shares using some
  QoS (Quality of Service) specification. The default value of the qos
  capability (if a driver doesn't report it) is False. You can make a share
  type use QoS by setting this extra-spec to '<is> True' and also setting
  the relevant QoS-related extra specs for the drivers being used.
  Administrators can prevent a share type from using QoS by setting this
  extra-spec to '<is> False'. Different drivers have different ways of
  specifying QoS limits (or guarantees) and this extra spec merely allows
  the scheduler to filter by pools that either have or don't have QoS
  support enabled.

* **ipv4_support** indicates whether a back end can create a share that
  can be accessed via IPv4 protocol. If administrators do not set this
  capability as an extra-spec in a share type, the scheduler can place new
  shares of that type in pools without regard for whether IPv4 is supported.

* **ipv6_support** - indicates whether a back end can create a share that
  can be accessed via IPv6 protocol. If administrators do not set this
  capability as an extra-spec in a share type, the scheduler can place new
  shares of that type in pools without regard for whether IPv6 is supported.

* **provisioning:max_share_size** can set the max size of share, the value
  must be an integer and greater than 0. If administrators set this capability
  as an extra-spec in a share type, the size of share created with the share
  type can not be greater than the specified value.

* **provisioning:min_share_size** can set the min size of share, the value
  must be an integer and greater than 0. If administrators set this capability
  as an extra-spec in a share type, the size of share created with the share
  type can not be less than the specified value.

* **provisioning:max_share_extend_size** can set the max size of share extend,
  the value must be an integer and greater than 0. If administrators set this
  capability as an extra-spec in a share type, the size of share extended with
  the share type can not be greater than the specified value. This capability
  is ignored for regular users and the "provisioning:max_share_size" is the
  only effective limit.
