.. _group_capabilities_and_extra_specs:

Group Capabilities and group-specs
==================================
Manila Administrators create share group types with
:ref:`shared_file_systems_share_types` and group-specs to allow users
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

The group specs is an exact match requirement in share group filter
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
