.. -*- rst -*-

===============================
Scheduler Stats - Storage Pools
===============================

An administrator can list all back-end storage pools that are known
to the scheduler service.


List back-end storage pools
===========================

.. rest_method::  GET /v2/{tenant_id}/scheduler-stats/pools?pool={pool_name}&host={host_name}&backend={backend_name}&capabilities={capabilities}&share_type={share_type}

Lists all back-end storage pools. If search options are provided, the pool
list that is returned is filtered with these options.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - pool_name: backend_pool_query
   - host_name: backend_host_query
   - backend_name: backend_query
   - capabilities: backend_capabilities_query
   - share_type: share_type_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - backend: backend
   - host: backend_host
   - pool: pool
   - name: backend_name

Response example
----------------

.. literalinclude:: samples/pools-list-response.json
   :language: javascript


List back-end storage pools with details
========================================

.. rest_method::  GET /v2/{tenant_id}/scheduler-stats/pools/detail?pool={pool_name}&host={host_name}&backend={backend_name}&capabilities={capabilities}&share_type={share_type}

Lists all back-end storage pools with details. If search options are provided,
the pool list that is returned is filtered with these options.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - pool_name: backend_pool_query
   - host_name: backend_host_query
   - backend_name: backend_query
   - capabilities: backend_capabilities_query
   - share_type: share_type_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - pools: pools
   - name: backend_name
   - backend: backend
   - pool: pool
   - host: backend_host
   - capabilities: capabilities
   - qos: capability_qos
   - timestamp: timestamp
   - share_backend_name: capability_share_backend_name
   - server_pools_mapping: capability_server_pools_mapping
   - driver_handles_share_servers: capability_driver_handles_share_servers
   - driver_version: capability_driver_version
   - total_capacity_gb: capability_total_capacity_gb
   - free_capacity_gb: capability_free_capacity_gb
   - reserved_percentage: capability_reserved_percentage
   - vendor_name: capability_vendor_name
   - snapshot_support: capability_snapshot_support
   - replication_domain: capability_replication_domain
   - storage_protocol: capability_storage_protocol

Response example
----------------

.. literalinclude:: samples/pools-list-detailed-response.json
   :language: javascript
