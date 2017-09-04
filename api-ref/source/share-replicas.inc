.. -*- rst -*-

===================================
Share replicas (Since version 2.11)
===================================

Share replicas are the replicated copies of the existing share. You can use
Share Replicas to sync data so that each share replica has an identical copy
of the same share. Share replication can be used as a disaster recovery
solution or as a load sharing mirroring solution.

Manila supports replication of shares between different storage pools.
These pools may be on different back-end storage systems or within the same
back end, depending upon the replication style chosen, the capability of
the driver and the configuration of back ends. To ensure that a secondary
copy is scheduled to a distinct back end, you must specify the
``availability_zone`` attribute.

.. note::

  You can create a replicated share with the help of a share type
  that has an extra-spec ``replication_type`` specified with a valid
  replication style. Once a replicated share has been created,
  it always starts out with an ``active`` replica. You may then create
  secondary copies of the share. A secondary copy can be "promoted"
  to fail-over to becoming the ``active`` replica.

To create a share that supports replication, the share type must specify
one of these supported replication types:

- writable

  Synchronously replicated shares where all replicas are writable.
  Promotion is not supported and not needed because all copies are already
  exported and can be accessed simultaneously.

- readable

  Mirror-style replication with a primary (writable) copy and one or more
  secondary (read-only) copies which can become writable after a promotion.

- dr (for Disaster Recovery)

  Generalized replication with secondary copies that are inaccessible until
  they are promoted to become the active replica.

.. important::

  The term active replica refers to the primary share. In writable style of
  replication, all replicas are active, and there could be no distinction of
  a primary share. In readable and dr styles of replication, a secondary
  replica may be referred to as passive, non-active or simply replica.


Create share replica
====================

.. rest_method::  POST /v2/{tenant_id}/share-replicas

Create a share replica for the share.

Normal response codes: 202

Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_id: share_replica_share_id
   - availability_zone: share_replica_az
   - share_network_id: share_replica_share_network_id

Request example
---------------

.. literalinclude:: samples/share-replica-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share_id: share_replica_share_id
   - status: share_replica_status
   - cast_rules_to_readonly: share_replica_cast_rules_to_readonly
   - updated_at: share_replica_updated_at
   - share_network_id: share_network_id
   - share_server_id: share_server_id
   - host: share_replica_host
   - id: share_replica_id
   - replica_state: share_replica_replica_state
   - created_at: share_replica_created_at


Response example
----------------

.. literalinclude:: samples/share-replica-create-response.json
   :language: javascript


Promote share replica
=====================

.. rest_method::  POST /v2/{tenant_id}/share-replicas/{share_replica_id}/action

Promotes a replica to ``active`` replica state.

Normal response codes: 202

Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_replica_id: share_replica_id_path


Resync share replica
====================

.. rest_method::  POST /v2/{tenant_id}/share-replicas/{share_replica_id}/action

Resync a replica with its ``active`` mirror.

Normal response codes: 202

Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_replica_id: share_replica_id_path


List share replicas
===================

.. rest_method::  GET /v2/{tenant_id}/share-replicas?share_id={share_id}

Lists share replicas.

Normal response codes: 200

Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - share_id: share_id
   - tenant_id: tenant_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share_id: share_replica_share_id
   - status: share_replica_status
   - id: share_replica_id
   - replica_state: share_replica_replica_state

Response example
----------------

.. literalinclude:: samples/share-replicas-list-response.json
   :language: javascript


List share replicas with details
================================

.. rest_method::  GET /v2/{tenant_id}/share-replicas/detail?share_id={share_id}

Lists share replicas with details.

Normal response codes: 200

Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - share_id: share_id
   - tenant_id: tenant_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share_id: share_replica_share_id
   - status: share_replica_status
   - cast_rules_to_readonly: share_replica_cast_rules_to_readonly
   - updated_at: share_replica_updated_at
   - share_network_id: share_network_id
   - share_server_id: share_server_id
   - host: share_replica_host
   - id: share_replica_id
   - replica_state: share_replica_replica_state
   - created_at: share_replica_created_at

Response example
----------------

.. literalinclude:: samples/share-replicas-list-detail-response.json
   :language: javascript


Show share replica
==================

.. rest_method::  GET /v2/{tenant_id}/share-replicas/{share_replica_id}

Show a share replica.

Normal response codes: 200

Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - share_replica_id: share_replica_id_path
   - tenant_id: tenant_id_path


Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share_id: share_replica_share_id
   - status: share_replica_status
   - cast_rules_to_readonly: share_replica_cast_rules_to_readonly
   - updated_at: share_replica_updated_at
   - share_network_id: share_network_id
   - share_server_id: share_server_id
   - host: share_replica_host
   - id: share_replica_id
   - replica_state: share_replica_replica_state
   - created_at: share_replica_created_at

Response example
----------------

.. literalinclude:: samples/share-replicas-show-response.json
   :language: javascript


Reset status of the share replica
=================================

.. rest_method::  POST /v2/{tenant_id}/share-replicas/{share_replica_id}/action

Administrator only. Explicitly updates the ``status`` of a share replica.

Use the ``policy.json`` file to grant permissions for this action
to other roles.

Normal response codes: 202

Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - reset_status: reset_status
   - status: share_replica_status
   - share_replica_id: share_replica_id_path
   - tenant_id: tenant_id_path

Request example
---------------

.. literalinclude:: samples/share-replicas-reset-state-request.json
   :language: javascript


Reset replica_state of the share replica
========================================

.. rest_method::  POST /v2/{tenant_id}/share-replicas/{share_replica_id}/action

Administrator only. Explicitly updates the ``replica state`` of a share replica.

Use the ``policy.json`` file to grant permissions for this action
to other roles.

Normal response codes: 202

Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - reset_replica_state: share_replica_reset_replica_state
   - replica_state: share_replica_replica_state
   - share_replica_id: share_replica_id_path
   - tenant_id: tenant_id_path

Request example
---------------

.. literalinclude:: samples/share-replicas-reset-replica-state-request.json
   :language: javascript


Delete share replica
====================

.. rest_method::  DELETE /v2/{tenant_id}/share-replicas/{share_replica_id}

Deletes a share replica.

Normal response codes: 202

Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

.. note::

    The ``active`` replica cannot be deleted with this API.

Request
-------

.. rest_parameters:: parameters.yaml

   - share_replica_id: share_replica_id_path
   - tenant_id: tenant_id_path


Force-delete share replica
==========================

.. rest_method::  POST /v2/{tenant_id}/share-replicas/{share_replica_id}/action

Administrator only. Force-deletes a share replica in any state.

Use the ``policy.json`` file to grant permissions for this action
to other roles.

Normal response codes: 202

Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

.. note::

    The ``active`` replica cannot be deleted with this API.

Request
-------

.. rest_parameters:: parameters.yaml

   - force_delete: share_replica_force_delete
   - share_replica_id: share_replica_id_path
   - tenant_id: tenant_id_path

Request example
---------------

.. literalinclude:: samples/share-replicas-force-delete-request.json
   :language: javascript
