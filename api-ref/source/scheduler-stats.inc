.. -*- rst -*-

===============================
Scheduler Stats - Storage Pools
===============================

An administrator can list all back-end storage pools that are known
to the scheduler service.


List back-end storage pools
===========================

.. rest_method::  GET /v2/{tenant_id}/scheduler-stats/pools?pool={pool_name}&host={host_name}&backend={backend_name}&capabilities={capabilities}

Lists all back-end storage pools. If search options are provided, the pool
list that is returned is filtered with these options.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - pool: pool_1
   - host: host_9
   - backend: backend_1
   - capabilities: capabilities_1

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - backend: backend
   - host: host_4
   - pool: pool
   - name: name_11

Response example
----------------

.. literalinclude:: samples/pools-list-response.json
   :language: javascript


List back-end storage pools with details
========================================

.. rest_method::  GET /v2/{tenant_id}/scheduler-stats/pools/detail?pool={pool_name}&host={host_name}&backend={backend_name}&capabilities={capabilities}

Lists all back-end storage pools with details. If search options are provided,
the pool list that is returned is filtered with these options.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - pool: pool_1
   - host: host_9
   - backend: backend_1
   - capabilities: capabilities_1

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - backend: backend
   - host: host_4
   - pool: pool
   - name: name_11
   - capabilities: capabilities_1
   - qos: qos
   - consistency_group_support: consistency_group_support
   - timestamp: timestamp
   - share_backend_name: share_backend_name
   - server_pools_mapping: server_pools_mapping
   - driver_handles_share_servers: driver_handles_share_servers
   - driver_version: driver_version
   - total_capacity_gb: total_capacity_gb
   - free_capacity_gb: free_capacity_gb
   - reserved_percentage: reserved_percentage
   - pools: pools
   - vendor_name: vendor_name
   - snapshot_support: snapshot_support_2
   - replication_type: replication_type
   - storage_protocol: storage_protocol

Response example
----------------

.. literalinclude:: samples/pools-list-detailed-response.json
   :language: javascript
