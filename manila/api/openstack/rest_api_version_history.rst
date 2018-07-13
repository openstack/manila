REST API Version History
========================

This documents the changes made to the REST API with every
microversion change. The description for each version should be a
verbose one which has enough information to be suitable for use in
user documentation.

1.0 (Maximum in Kilo)
---------------------
  The 1.0 Manila API includes all v1 core APIs existing prior to
  the introduction of microversions.  The /v1 URL is used to call
  1.0 APIs, and microversions headers sent to this endpoint are
  ignored.

2.0
---
  This is the initial version of the Manila API which supports
  microversions.  The /v2 URL is used to call 2.x APIs.

  A user can specify a header in the API request::

    X-OpenStack-Manila-API-Version: <version>

  where ``<version>`` is any valid api version for this API.

  If no version is specified then the API will behave as if version 2.0
  was requested.

  The only API change in version 2.0 is versions, i.e.
  GET http://localhost:8786/, which now returns information about
  both 1.0 and 2.x versions and their respective /v1 and /v2 endpoints.

  All other 2.0 APIs are functionally identical to version 1.0.

2.1
---
  Share create() method doesn't ignore availability_zone field of provided
  share.

2.2
---
  Snapshots become optional and share payload now has
  boolean attr 'snapshot_support'.

2.3
---
  Share instances admin API and update of Admin Actions extension.

2.4
---
  Consistency groups support. /consistency-groups and /cgsnapshots are
  implemented. AdminActions 'os-force_delete and' 'os-reset_status' have been
  updated for both new resources.

2.5
---
  Share Migration admin API.

2.6 (Maximum in Liberty)
------------------------
  Return share_type UUID instead of name in Share API and add share_type_name
  field.

2.7
---
  Rename old extension-like API URLs to core-API-like.

2.8
---
  Allow to set share visibility explicitly using "manage" API.

2.9
---
  Add export locations API. Remove export locations from "shares" and
  "share instances" APIs.

2.10
----
  Field 'access_rules_status' was added to shares and share instances.

2.11
----
  Share Replication support added. All Share replication APIs are tagged
  'Experimental'. Share APIs return two new attributes: 'has_replicas' and
  'replication_type'. Share instance APIs return a new attribute,
  'replica_state'.

2.12
----
  Share snapshot manage and unmanage API.

2.13
----
  Add 'cephx' authentication type for the CephFS Native driver.

2.14
----
  Added attribute 'preferred' to export locations.  Drivers may use this
  field to identify which export locations are most efficient and should be
  used preferentially by clients.  Also, change 'uuid' field to 'id', move
  timestamps to detail view, and return all non-admin fields to users.

2.15 (Maximum in Mitaka)
------------------------
  Added Share migration 'migration_cancel', 'migration_get_progress',
  'migration_complete' APIs, renamed 'migrate_share' to 'migration_start' and
  added notify parameter to 'migration_start'.

2.16
----
  Add user_id in share show/create/manage API.

2.17
----
  Added user_id and project_id in snapshot show/create/manage APIs.

2.18
----
  Add gateway in share network show API.

2.19
----
  Add admin APIs(list/show/detail/reset-status) of snapshot instances.

2.20
----
  Add MTU in share network show API.

2.21
----
  Add access_key in access_list API.

2.22 (Maximum in Newton)
------------------------
  Updated migration_start API with 'preserve_metadata', 'writable',
  'nondisruptive' and 'new_share_network_id' parameters, renamed
  'force_host_copy' to 'force_host_assisted_migration', removed 'notify'
  parameter and removed previous migrate_share API support. Updated
  reset_task_state API to accept 'None' value.

2.23
----
  Added share_type to filter results of scheduler-stats/pools API.

2.24
----
  Added optional create_share_from_snapshot_support extra spec. Made
  snapshot_support extra spec optional.

2.25
----
  Added quota-show detail API.

2.26
----
  Removed nova-net plugin support and removed 'nova_net_id' parameter from
  share_network API.

2.27
----
  Added share revert to snapshot. This API reverts a share to the specified
  snapshot. The share is reverted in place, and the snapshot must be the most
  recent one known to manila. The feature is controlled by a new standard
  optional extra spec, revert_to_snapshot_support.

2.28
----
  Added transitional states ('queued_to_apply' - was previously 'new',
  'queued_to_deny', 'applying' and 'denying') to access rules.
  'updating', 'updating_multiple' and 'out_of_sync' are no longer valid
  values for the 'access_rules_status' field of shares, they have
  been collapsed into the transitional state 'syncing'. Access rule changes
  can be made independent of a share's 'access_rules_status'.

2.29
----
  Updated migration_start API adding mandatory parameter 'preserve_snapshots'
  and changed 'preserve_metadata', 'writable', 'nondisruptive' to be mandatory
  as well. All previous migration_start APIs prior to this microversion are now
  unsupported.

2.30
----
  Added cast_rules_to_readonly field to share_instances.

2.31
----
  Convert consistency groups to share groups.

2.32 (Maximum in Ocata)
-----------------------
  Added mountable snapshots APIs.

2.33
----
  Added created_at and updated_at in access_list API.

2.34
----
  Added 'availability_zone_id' and 'consistent_snapshot_support' fields to
  'share_group' object.

2.35
----
  Added support to retrieve shares filtered by export_location_id and
  export_location_path.

2.36
----
  Added like filter support in ``shares``, ``snapshots``, ``share-networks``,
  ``share-groups`` list APIs.

2.37
----
  Added /messages APIs.

2.38
----
  Support IPv6 format validation in allow_access API to enable IPv6.

2.39
----
  Added share-type quotas.

2.40 (Maximum in Pike)
----------------------
  Added share group and share group snapshot quotas.

2.41
----
  Added 'description' in share type create/list APIs.

2.42 (Maximum in Queens)
------------------------
  Added ``with_count`` in share list API to get total count info.
