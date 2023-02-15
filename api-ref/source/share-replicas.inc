.. -*- rst -*-

Share replicas (since API v2.11)
================================

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
~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-replicas

.. versionadded:: 2.11

Create a share replica for the share.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_id: share_replica_share_id
   - availability_zone: share_replica_az
   - share_network_id: share_replica_share_network_id
   - scheduler_hints: share_replica_scheduler_hints

Request example
---------------

.. literalinclude:: samples/share-replica-create-request.json
   :language: javascript

.. note::
   Since API version 2.72, the parameter ``share_network_id`` is added which
   was earlier supported but later deprecated from version 2.51. In case, the
   parameter is not specified, it will be inherited from its parent share,
   and the Shared File Systems service will automatically choose which share
   network subnet your share replica will be placed, according to the
   specified availability zone.


Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share_id: share_replica_share_id
   - status: share_replica_status
   - cast_rules_to_readonly: share_replica_cast_rules_to_readonly
   - updated_at: updated_at
   - share_network_id: share_network_id
   - share_server_id: share_server_id
   - host: share_replica_host
   - id: share_replica_id
   - replica_state: share_replica_replica_state
   - created_at: created_at


Response example
----------------

.. literalinclude:: samples/share-replica-create-response.json
   :language: javascript


Promote share replica
~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-replicas/{share_replica_id}/action

.. versionadded:: 2.11

Promotes a replica to ``active`` replica state.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_replica_id: share_replica_id_path
   - quiesce_wait_time: share_replica_quiesce_wait_time

Request example
---------------

.. literalinclude:: samples/share-replica-promote-request.json
   :language: javascript


Resync share replica
~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-replicas/{share_replica_id}/action

.. versionadded:: 2.11

Resync a replica with its ``active`` mirror.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_replica_id: share_replica_id_path


Request example
---------------

.. literalinclude:: samples/share-replica-resync-request.json
   :language: javascript


List share replicas
~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-replicas?share_id={share_id}

.. versionadded:: 2.11

Lists share replicas.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_id: share_id

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
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-replicas/detail?share_id={share_id}

.. versionadded:: 2.11

Lists share replicas with details.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_id: share_id_replicas_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share_id: share_replica_share_id
   - status: share_replica_status
   - cast_rules_to_readonly: share_replica_cast_rules_to_readonly
   - updated_at: updated_at
   - share_network_id: share_network_id
   - share_server_id: share_server_id
   - host: share_replica_host
   - id: share_replica_id
   - replica_state: share_replica_replica_state
   - created_at: created_at

Response example
----------------

.. literalinclude:: samples/share-replicas-list-detail-response.json
   :language: javascript


Show share replica
~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-replicas/{share_replica_id}

.. versionadded:: 2.11

Show a share replica.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_replica_id: share_replica_id_path


Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share_id: share_replica_share_id
   - status: share_replica_status
   - cast_rules_to_readonly: share_replica_cast_rules_to_readonly
   - updated_at: updated_at
   - share_network_id: share_network_id
   - share_server_id: share_server_id
   - host: share_replica_host
   - id: share_replica_id
   - replica_state: share_replica_replica_state
   - created_at: created_at

Response example
----------------

.. literalinclude:: samples/share-replicas-show-response.json
   :language: javascript


Reset status of the share replica
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-replicas/{share_replica_id}/action

.. versionadded:: 2.11

Administrator only. Explicitly updates the ``status`` of a share replica.

Use the ``policy.yaml`` file to grant permissions for this action
to other roles.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_replica_id: share_replica_id_path
   - reset_status: reset_status
   - status: share_replica_status

Request example
---------------

.. literalinclude:: samples/share-replicas-reset-state-request.json
   :language: javascript


Reset replica_state of the share replica
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-replicas/{share_replica_id}/action

.. versionadded:: 2.11

Administrator only. Explicitly updates the ``replica state`` of a share replica.

Use the ``policy.yaml`` file to grant permissions for this action
to other roles.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_replica_id: share_replica_id_path
   - reset_replica_state: share_replica_reset_replica_state
   - replica_state: share_replica_replica_state

Request example
---------------

.. literalinclude:: samples/share-replicas-reset-replica-state-request.json
   :language: javascript


Delete share replica
~~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/share-replicas/{share_replica_id}

.. versionadded:: 2.11

Deletes a share replica.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409

.. note::

    The ``active`` replica cannot be deleted with this API.

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_replica_id: share_replica_id_path


Force-delete share replica
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-replicas/{share_replica_id}/action

.. versionadded:: 2.11

Administrator only. Force-deletes a share replica in any state.

Use the ``policy.yaml`` file to grant permissions for this action
to other roles.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

.. note::

    The ``active`` replica cannot be deleted with this API.

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_replica_id: share_replica_id_path
   - force_delete: share_replica_force_delete

Request example
---------------

.. literalinclude:: samples/share-replicas-force-delete-request.json
   :language: javascript
