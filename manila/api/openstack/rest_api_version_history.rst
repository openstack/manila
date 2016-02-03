REST API Version History
========================

This documents the changes made to the REST API with every
microversion change. The description for each version should be a
verbose one which has enough information to be suitable for use in
user documentation.

1.0
---
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

2.6
---
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
____
  Added attribute 'preferred' to export locations.  Drivers may use this
  field to identify which export locations are most efficient and should be
  used preferentially by clients.  Also, change 'uuid' field to 'id', move
  timestamps to detail view, and return all non-admin fields to users.

2.15
----
  Added Share migration 'migration_cancel', 'migration_get_progress',
  'migration_complete' APIs, renamed 'migrate_share' to 'migration_start' and
  added notify parameter to 'migration_start'.
