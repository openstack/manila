.. _capabilities_and_extra_specs:

Capabilities and Extra-Specs
============================
Manila Administrators create share types with extra-specs to allow users
to request a type of share to create. The Administrator chooses a name
for the share type and decides how to communicate the significance of
the different share types in terms that the users should understand or
need to know. By design, most of the details of a share type (the extra-
specs) are not exposed to users -- only Administrators.

Share Types
-----------
Refer to the manila client command-line help for information on how to
create a share type and set "extra-spec" key/value pairs for a share type.

Extra-Specs
-----------
There are 3 types of extra-specs: required, scoped, and un-scoped.

Manila *requires* the driver_handles_share_servers extra-spec.

*Scoped* extra-specs use a prefix followed by a colon to define a namespace
for scoping the extra-spec. A prefix could be a vendor name or acronym
and is a hint that this extra-spec key/value only applies to that vendor's
driver. Scoped extra-specs are not used by the scheduler to determine
where a share is created (except for the special `capabilities` prefix).
It is up to each driver implementation to determine how to use scoped
extra-specs and to document them.

The prefix "capabilities" is a special prefix to indicate extra-specs that
are treated like un-scoped extra-specs. In the CapabilitiesFilter the
"capabilities:" is stripped from the key and then the extra-spec key and
value are used as an un-scoped extra-spec.

*Un-scoped* extra-specs have a key that either starts with "capabilities:" or
does not contain a colon. When the CapabilitiesFilter is enabled (it is
enabled by default), the scheduler will only create a share on a backend
that reports capabilities that match the share type's un-scoped extra-spec
keys.

The CapabilitiesFilter uses the following for matching operators:

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

  The "s" indicates it is a string comparison. These choose a host that satisfies
  the comparison of strings in capability and specification. For example,
  if "capabilities:replication_type s== dr", a host that reports
  replication_type of "dr" will be chosen.

For vendor-specific capabilities (which need to be visible to the
CapabilityFilter), it is recommended to use the vendor prefix followed
by an underscore. This is not a strict requirement, but will provide a
consistent look along-side the scoped extra-specs and will be a clear
indicator of vendor capabilities vs. common capabilities.

Common Capabilities
-------------------
For capabilities that apply to multiple backends a common capability can
be created. Like all other backend reported capabilities, these capabilities
can be used verbatim as extra_specs in share types used to create shares.

* `driver_handles_share_servers` is a special, required, user-visible common
  capability. Added in Kilo.

* `dedupe` - indicates that a backend/pool can provide shares using some
  deduplication technology. The default value of the dedupe capability (if a
  driver doesn't report it) is False. In Liberty, drivers cannot report to the
  scheduler that they support both dedupe and non-deduped share. For each pool
  it's either always on or always off, even if the drivers can technically
  support both dedupe and non-deduped in a pool. Since Mitaka, the logic is
  changed to allow a driver to report dedupe=[True, False] if it can support
  both dedupe and non-deduped in a pool. Administrators can make a share type
  use deduplication by setting this extra-spec to '<is> True'. Administrators
  can prevent a share type from using deduplication by setting this extra-spec
  to '<is> False'. Added in Liberty.

* `compression` - indicates that a backend/pool can provide shares using some
  compression technology. The default value of the compression capability (if a
  driver doesn't report it) is False. In Liberty, drivers cannot report to the
  scheduler that they support both compression and non-compression. For each
  pool it's either always on or always off, even if the drivers can technically
  support both compression and non-compression in a pool. Since Mitaka, the
  logic is changed to allow a driver to report compression=[True, False] if it
  can support both compression and non-compression in a pool. Administrators
  can make a share type use compression by setting this extra-spec to
  '<is> True'. Administrators can prevent a share type from using compression
  by setting this extra-spec to '<is> False'. Added in Liberty.

* `thin_provisioning` - shares will not be space guaranteed and
  overprovisioning will be enabled. This capability defaults to False.
  Backends/pools that support thin provisioning must report True for this
  capability. Administrators can make a share type use thin provisioned shares
  by setting this extra-spec to '<is> True'. If a driver reports
  thin_provisioning=False (the default) then it's assumed that the driver is
  doing thick provisioning and overprovisioning is turned off.
  This was added in Liberty. In Liberty and Mitaka, the driver was required
  to configure one pool for thin and another pool for thick and report
  thin_provisioning as either True or False even if an array can technically
  support both thin and thick provisioning in a pool. In Newton, the logic is
  changed to allow a driver to report thin_provisioning=[True, False] if it
  can support both thin and thick provisioning in a pool. To provision a thick
  share on a back end that supports both thin and thick provisioning, set one
  of the following in extra specs:

::

    {'thin_provisioning': 'False'}
    {'thin_provisioning': '<is> False'}
    {'capabilities:thin_provisioning': 'False'}
    {'capabilities:thin_provisioning': '<is> False'}

* `qos` - indicates that a backend/pool can provide shares using some
  QoS (Quality of Service) specification. The default value of the qos
  capability (if a driver doesn't report it) is False. Administrators
  can make a share type use QoS by setting this extra-spec to '<is> True' and
  also setting the relevant QoS-related extra specs for the drivers being used.
  Administrators can prevent a share type from using QoS by setting this
  extra-spec to '<is> False'. Different drivers have different ways of specifying
  QoS limits (or guarantees) and this extra spec merely allows the scheduler to
  filter by pools that either have or don't have QoS support enabled. Added in
  Mitaka.

* `replication_type` - indicates the style of replication supported for the
  backend/pool. This extra_spec will have a string value and could be one
  of :term:`writable`, :term:`readable` or :term:`dr`. `writable` replication
  type involves synchronously replicated shares where all replicas are
  writable. Promotion is not supported and not needed. `readable` and `dr`
  replication types involve a single `active` or `primary` replica and one or
  more `non-active` or secondary replicas per share. In `readable` type of
  replication, `non-active` replicas have one or more export_locations and
  can thus be mounted and read while the `active` replica is the only one
  that can be written into. In `dr` style of replication, only
  the `active` replica can be mounted, read from and written into. Added in
  Mitaka.

* `snapshot_support` - indicates whether snapshots are supported for shares
  created on the pool/backend. When administrators do not set this capability
  as an extra-spec in a share type, the scheduler can place new shares of that
  type in pools without regard for whether snapshots are supported, and those
  shares will not support snapshots.

* `create_share_from_snapshot_support` - indicates whether a backend can create
  a new share from a snapshot. When administrators do not set this capability
  as an extra-spec in a share type, the scheduler can place new shares of that
  type in pools without regard for whether creating shares from snapshots is
  supported, and those shares will not support creating shares from snapshots.

* `revert_to_snapshot_support` - indicates that a driver is capable of
  reverting a share in place to its most recent snapshot. When administrators
  do not set this capability as an extra-spec in a share type, the scheduler
  can place new shares of that type in pools without regard for whether
  reverting shares to snapshots is supported, and those shares will not support
  reverting shares to snapshots.

* `ipv4_support` - indicates whether a back end can create a share that can be
  accessed via IPv4 protocol. If administrators do not set this capability
  as an extra-spec in a share type, the scheduler can place new shares of that
  type in pools without regard for whether IPv4 is supported.

* `ipv6_support` - indicates whether a back end can create a share that can be
  accessed via IPv6 protocol. If administrators do not set this capability
  as an extra-spec in a share type, the scheduler can place new shares of that
  type in pools without regard for whether IPv6 is supported.

Reporting Capabilities
----------------------
Drivers report capabilities as part of the updated stats (e.g. capacity)
for their backend/pools. This is how a backend/pool advertizes its ability
to provide a share that matches the capabilities requested in the share
type extra-specs.

Developer impact
----------------

Developers should update their drivers to include all backend and pool
capacities and capabilities in the share stats it reports to scheduler.
Below is an example having multiple pools. "my" is used as an
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
            },
         ]
    }

Work Flow
---------

1) Share Backends report how many pools and what those pools look like and
   are capable of to scheduler;

2) When request comes in, scheduler picks a pool that fits the need best to
   serve the request, it passes the request to the backend where the target
   pool resides;

3) Share driver gets the message and lets the target pool serve the request
   as scheduler instructed. Share type extra-specs (scoped and un-scoped)
   are available for the driver implementation to use as-needed.
