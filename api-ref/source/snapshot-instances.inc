.. -*- rst -*-

==========================================
Share snapshot instances (since API v2.19)
==========================================

A share snapshot instance is an internal representation for a snapshot
of a share. A single snapshot can have multiple snapshot instances if
the parent share has multiple ``instances``. When a share is replicated
or is in the process of being migrated, it can live in multiple places
and each individual location is called an "instance", internally within
the Shared File Systems service.

By default administrators can list, show information for and explicitly
set the state of share snapshot instances. Use the ``policy.json`` file
to grant permissions for these actions to other roles.


List share snapshot instances
=============================

.. rest_method::  GET /v2/{tenant_id}/snapshot-instances

Lists all share snapshot instances.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - snapshot_id: snapshot_id_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: snapshot_instance_id_response
   - snapshot_id: snapshot_id
   - status: snapshot_instance_status

Response example
----------------

.. literalinclude:: samples/snapshot-instances-list-response.json
   :language: javascript


List share snapshot instances with details
==========================================

.. rest_method::  GET /v2/{tenant_id}/snapshot-instances/detail

Lists all share snapshot instances with details.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - snapshot_id: snapshot_id_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: snapshot_instance_id_response
   - snapshot_id: snapshot_id
   - created_at: snapshot_created_at
   - updated_at: snapshot_instance_updated_at
   - status: snapshot_instance_status
   - share_id: share_id
   - share_instance_id: share_instance_id_1
   - progress: progress
   - provider_location: snapshot_provider_location

Response example
----------------

.. literalinclude:: samples/snapshot-instances-list-with-detail-response.json
   :language: javascript


Show share snapshot instance details
====================================

.. rest_method::  GET /v2/{tenant_id}/snapshot-instances/{snapshot_instance_id}

Shows details for a share snapshot instance.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - snapshot_instance_id: snapshot_instance_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: snapshot_instance_id_response
   - snapshot_id: snapshot_id
   - created_at: snapshot_created_at
   - updated_at: snapshot_instance_updated_at
   - status: snapshot_instance_status
   - share_id: share_id
   - share_instance_id: share_instance_id_1
   - progress: progress
   - provider_location: snapshot_provider_location

Response example
----------------

.. literalinclude:: samples/snapshot-instance-show-response.json
   :language: javascript


Reset share snapshot instance state
===================================

.. rest_method::  POST /v2/{tenant_id}/snapshot-instances/{snapshot_instance_id}/action

Administrator only. Explicitly updates the state of a share snapshot instance.

Use the ``policy.json`` file to grant permissions for this action
to other roles.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)


Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - snapshot_instance_id: snapshot_instance_id_path
   - status: snapshot_instance_status

Request example
---------------

.. literalinclude:: samples/snapshot-instance-actions-reset-state-request.json
   :language: javascript
