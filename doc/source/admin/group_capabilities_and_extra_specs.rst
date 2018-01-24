.. _group_capabilities_and_extra_specs:

Group Capabilities and group-specs
==================================
Manila Administrators create share group types with `share types
<https://docs.openstack.org/manila/latest/admin/
shared-file-systems-share-types.html>`_ and group-specs to allow users
to request a group type of share group to create. The Administrator chooses
a name for the share group type and decides how to communicate the significance
of the different share group types in terms that the users should understand or
need to know. By design, most of the details of a share group type (the extra-
specs) are not exposed to users -- only Administrators.

Share group Types
-----------------
Refer to the manila client command-line help for information on how to
create a share group type and set "share types", "group-spec" key/value
pairs for a share group type.

Group-Specs
-----------
The group specs contains the group capabilities, similar to snapshot_support
in share types. Users know what a group can do from group specs.

The group specs is a exact match requirement in share group filter
(such as ConsistentSnapshotFilter). When the ConsistentSnapshotFilter is enabled
(it is enabled by default), the scheduler will only create a share group on
a backend that reports capabilities that match the share group type's
group-spec keys.

Common Group Capabilities
-------------------------
For group capabilities that apply to multiple backends a common capability can
be created. Like all other backend reported group capabilities, these group
capabilities can be used verbatim as group_specs in share group types used to
create share groups.

* `consistent_snapshot_support` - indicates that a backend can enable you to
  create snapshots at the exact same point in time from multiple shares.
  The default value of the consistent_snapshot_support capability (if a
  driver doesn't report it) is None. Administrators can make a share group
  type use consistent snapshot support by setting this group-spec to 'host'.

Reporting Group Capabilities
----------------------------
Drivers report group capabilities as part of the updated stats (e.g. capacity)
and filled in 'share_group_stats' node for their back end. This is how a backend
advertizes its ability to provide a share that matches the group capabilities
requested in the share group type group-specs.

Developer impact
----------------

Developers should update their drivers to include all backend and pool
capacities and capabilities in the share stats it reports to scheduler.
Below is an example having multiple pools. "my" is used as an
example vendor prefix:

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

Work Flow
---------

1) Share Backends report how many pools and what those pools look like and
   are capable of to group scheduler;

2) When request comes in, scheduler picks a backend that fits the need best to
   serve the request, it passes the request to the backend where the target
   pool resides;

3) Share driver gets the message and lets the target pool serve the request
   as group scheduler instructed. Share group type group-specs (scoped and un-scoped)
   are available for the driver implementation to use as-needed.
