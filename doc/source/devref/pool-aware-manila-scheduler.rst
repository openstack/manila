Pool-Aware Scheduler Support
============================
https://blueprints.launchpad.net/manila/+spec/dynamic-storage-pools

Manila currently sees each share backend as a whole, even if the backend
consists of several smaller pools with totally different capabilities and
capacities.

Extending Manila to support storage pools within share backends will make
Manila scheduling decisions smarter as it now knows the full set of
capabilities of a backend.


Problem Description
-------------------

The provisioning decisions in Manila are based on the statistics reported by
backends. Any backend is assumed to be a single discrete unit with a set of
capabilities and single capacity. In reality this assumption is not true for
many storage providers, as their storage can be further divided or
partitioned into pools to offer completely different sets of capabilities and
capacities. That is, there are storage backends which are a combination of
storage pools rather than a single homogeneous entity. Usually shares/snapshots
can't be placed across pools on such backends.

In the current implementation, an attempt is made to map a single backend
to a single storage controller, and the following problems may arise:

* After the scheduler selects a backend on which to place a new share, the
  backend may have to make a second decision about where to place the share
  within that backend. This logic is driver-specific and hard for admins to deal
  with.

* The capabilities that the backend reports back to the scheduler may not apply
  universally. A single backend may support both SATA and SSD-based storage,
  but perhaps not at the same time. Backends need a way to express exactly what
  they support and how much space is consumed out of each type of storage.

Therefore, it is important to extend Manila so that it is aware of storage
pools within each backend and can use them as the finest granularity for
resource placement.


Proposed change
---------------

A pool-aware scheduler will address the need for supporting multiple pools
from one storage backend.


Terminology
-----------

Pool
    A logical concept to describe a set of storage resources that can be
    used to serve core Manila requests, e.g. shares/snapshots. This notion is
    almost identical to Manila Share Backend, for it has similar attributes
    (capacity, capability). The difference is that a Pool may not exist on its
    own; it must reside in a Share Backend. One Share Backend can have multiple
    Pools but Pools do not have sub-Pools (meaning even if they have them,
    sub-Pools do not get to exposed to Manila, yet). Each Pool has a unique name
    in the Share Backend namespace, which means a Share Backend cannot have two
    pools using same name.


Design
------

The workflow in this change is simple:

1) Share Backends report how many pools and what those pools look like and
   are capable of to scheduler;

2) When request comes in, scheduler picks a pool that fits the need best to
   serve the request, it passes the request to the backend where the target pool
   resides;

3) Share driver gets the message and lets the target pool serve the request
   as scheduler instructed.

To support placing resources (share/snapshot) onto a pool, these changes will
be made to specific components of Manila:

1. Share Backends reporting capacity/capabilities at pool level;

2. Scheduler filtering/weighing based on pool capacity/capability and placing
   shares/snapshots to a pool of a certain backend;

3. Record which backend and pool a resource is located on.


Data model impact
-----------------

No DB schema change involved, however, the host field of Shares table will
now include pool information but no DB migration is needed.


Original host field of Shares:
``HostX@BackendY``


With this change:
``HostX@BackendY#pool0``


REST API impact
---------------

With pool support added to Manila, there is an awkward situation where we
require admin to input the exact location for shares to be imported, which
must have pool info. But there is no way to find out what pools are there for
backends except looking at the scheduler log.  That causes a poor user
experience and thus is a problem from the User's Point of View.
This change simply adds a new admin-api extension to allow admin to fetch all
the pool information from scheduler cache (memory), which closes the gap for
end users.
This extension provides two level of pool information: names only or detailed
information:

Pool name only: GET http://MANILA_API_ENDPOINT/v1/TENANT_ID/scheduler-stats/pools

Detailed Pool info: GET http://MANILA_API_ENDPOINT/v1/TENANT_ID/scheduler-stats/pools/detail


Security impact
---------------

N/A


Notifications impact
--------------------

Host attribute of shares now includes pool information in it, consumer of
notification can now extend to extract pool information if needed.


Admin impact
------------

Administrators now need to suffix commands with ``#pool`` to manage shares.


Other end user impact
---------------------

No impact visible to the end user directly, but administrators now need to
prefix commands that refer to the backend host with the concatenation of the
hashtag (``#``) sign and the name of the pool (e.g. ``#poolName``) to manage
shares. Other impacts might include scenarios where if a backend does not
expose pools, the backend name is used as the pool name. For instance,
``HostX@BackendY#BackendY`` would be used when the driver does not expose
pools.


Performance Impact
------------------

The size of RPC message for each share stats report will be bigger than
before (linear to the number of pools a backend has). It should not really
impact the RPC facility in terms of performance and even if it did, pure
text compression should easily mitigate this problem.


Developer impact
----------------

For those share backends that would like to expose internal pools to Manila
for more flexibility, developers should update their drivers to include all
pool capacities and capabilities in the share stats it reports to scheduler.
Share backends without multiple pools do not need to change their
implementation. Below is an example of new stats message having multiple
pools:

::

    {
        'share_backend_name': 'My Backend',   #\
        'vendor_name': 'OpenStack',           #  backend level
        'driver_version': '1.0',              #  mandatory/fixed
        'storage_protocol': 'NFS/CIFS',       #- stats&capabilities

        'active_shares': 10,                  #\
        'IOPS_provisioned': 30000,            #  optional custom
        'fancy_capability_1': 'eat',          #  stats & capabilities
        'fancy_capability_2': 'drink',        #/

        'pools': [
            {'pool_name': '1st pool',         #\
             'total_capacity_gb': 500,        #  mandatory stats for
             'free_capacity_gb': 230,         #  pools
             'allocated_capacity_gb': 270,    # |
             'qos': True,                     # |
             'reserved_percentage': 0,        #/

             'dying_disks': 100,              #\
             'super_hero_1': 'spider-man',    #  optional custom
             'super_hero_2': 'flash',         #  stats & capabilities
             'super_hero_3': 'neoncat'        #/
             },
            {'pool_name': '2nd pool',
             'total_capacity_gb': 1024,
             'free_capacity_gb': 1024,
             'allocated_capacity_gb': 0,
             'qos': False,
             'reserved_percentage': 0,

             'dying_disks': 200,
             'super_hero_1': 'superman',
             'super_hero_2': ' ',
             'super_hero_2': 'Hulk',
             }
         ]
    }

Documentation Impact
--------------------

Documentation impact for changes in Manila are introduced by the API changes.
Also, doc changes are needed to append pool names to host names. Driver
changes may also introduce new configuration options which would lead to
Doc changes.
