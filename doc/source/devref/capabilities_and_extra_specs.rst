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
Refer to the Manila client command-line help for information on how to
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

Refer to the CapabilitiesFilter for matching operators.  For example, to
match a boolean capability the extra-spec value would be '<is> True'.

For vendor-specific capabilities (which need to be visible to the
CapabilityFilter), it is recommended to use the vendor prefix followed
by an underscore. This is not a strict requirement, but will provide a
consistent look along-side the scoped extra-specs and will be a clear
indicator of vendor capabilities vs. common capabilities.

Common Capabilities
-------------------
For capabilities that apply to multiple backends a common capability can
be created.

* `driver_handles_share_servers` is a special, required, user-visible common
  capability. Added in Kilo.

* `dedupe` - indicates that a backend/pool can provide shares using some
  deduplication technology. The default value of the dedupe capability (if a
  driver doesn't report it) is False. Drivers cannot report to the scheduler
  that they support both dedupe and non-deduped share. For each pool it's
  either always on or always off. Administrators can make a share type use
  deduplication by setting this extra-spec to '<is> True'. Administrators can
  prevent a share type from using deduplication by setting this extra-spec to
  '<is> False'. Added in Liberty.

* `compression` - indicates that a backend/pool can provide shares using some
  compression technology. The default value of the compression capability (if a
  driver doesn't report it) is False. Drivers cannot report to the scheduler
  that they support both compression and non-compression. For each pool it's
  either always on or always off. Administrators can make a share type use
  compression by setting this extra-spec to '<is> True'. Administrators can
  prevent a share type from using compression by setting this extra-spec to
  '<is> False'. Added in Liberty.

* `thin_provisioning` - shares will not be space guaranteed and
  overprovisioning will be enabled. This capability defaults to False.
  Backends/pools that support thin provisioning must report True for this
  capability. Administrators can make a share type use thin provisioned shares
  by setting this extra-spec to '<is> True'. If a driver reports
  thin_provisioning=False (the default) then it's assumed that the driver is
  doing thick provisioning and overprovisioning is turned off.
  If an array can technically support both thin and thick provisioning in a
  pool, the driver still needs to programmatically determine which to use.
  This should be done by configuring one pool for thin and another pool for
  thick. So, a Manila pool will always report thin_provisioning as True or
  False. Added in Liberty.

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
        'driver_handles_share_servers': 'False', #\
        'share_backend_name': 'My Backend',      # backend level
        'vendor_name': 'MY',                     # mandatory/fixed
        'driver_version': '1.0',                 # stats & capabilities
        'storage_protocol': 'NFS_CIFS',          #/
                                                 #\
        'my_capability_1': 'custom_val',         # "my" optional vendor
        'my_capability_2': True,                 # stats & capabilities
                                                 #/
        'pools': [
            {'pool_name':
               'thin-dedupe-compression pool',   #\
             'total_capacity_gb': 500,           #  mandatory stats for
             'free_capacity_gb': 230,            #  pools
             'reserved_percentage': 0,           #/
                                                 #\
             'dedupe': True,                     # common capabilities
             'compression': True,                #
             'qos': True,                        # this backend supports QoS
             'thin_provisioning': True,          #
             'max_over_subscription_ratio': 10,  # (mandatory for thin)
             'provisioned_capacity_gb': 270,     # (mandatory for thin)
                                                 #/
             'my_dying_disks': 100,              #\
             'my_super_hero_1': 'Hulk',          #  "my" optional vendor
             'my_super_hero_2': 'Spider-Man'     #  stats & capabilities
                                                 #/
            },
            {'pool_name': 'thick pool',
             'total_capacity_gb': 1024,
             'free_capacity_gb': 1024,
             'qos': False,
             'reserved_percentage': 0,
             'dedupe': False,
             'compression': False,
             'thin_provisioning': False,
             'my_dying_disks': 200,
             'my_super_hero_1': 'Batman',
             'my_super_hero_2': 'Robin',
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
