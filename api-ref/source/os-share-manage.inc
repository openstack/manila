.. -*- rst -*-

==========================
Manage and unmanage shares
==========================

Configures Shared File Systems to manage or unmanage a share.


Manage share
============

.. rest_method::  POST /v2/{tenant_id}/os-share-manage

**Minimum Supported API Version**: 1.0, 2.0
**Last supported API Version**: 2.6

Use this API to bring a share under the management of the Shared File
Systems service.

Administrator only. Use the ``policy.json`` file to grant permissions for this
action to other roles.

This API was removed in API version 2.7; please see share actions for the
new version of the API to utilize this feature.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share: share
   - protocol: protocol
   - name: name_5
   - display_name: display_name
   - share_type: share_type_2
   - driver_options: driver_options
   - export_path: export_path
   - service_host: service_host
   - is_public: is_public
   - description: description_5
   - display_description: display_description

Request example
---------------

.. literalinclude:: samples/share-manage-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - share: share
   - links: links
   - availability_zone: availability_zone_1
   - share_network_id: share_network_id
   - export_locations: export_locations
   - share_server_id: share_server_id
   - snapshot_id: snapshot_id_share_response
   - id: id_4
   - size: size_2
   - share_type: share_type_1
   - share_type_name: share_type_name
   - has_replicas: has_replicas
   - replication_type: replication_type
   - export_location: export_location
   - project_id: project_id_8
   - metadata: metadata
   - status: status_8
   - description: description_5
   - host: host_7
   - is_public: is_public
   - snapshot_support: snapshot_support
   - name: name_5
   - created_at: created_at_4
   - share_proto: share_proto
   - volume_type: volume_type

Response example
----------------

.. literalinclude:: samples/share-manage-response.json
   :language: javascript


Unmanage share
==============

.. rest_method::  POST /v2/{tenant_id}/os-share-unmanage/{share_id}/unmanage

**Minimum Supported API Version**: 1.0, 2.0
**Last supported API Version**: 2.6

Use this API to remove a share from the management of the Shared File
Systems service.

Administrator only. Use the ``policy.json`` file to grant permissions for this
action to other roles.

Share unmanage operation is not supported for shares that are created on top
of share servers (created with share networks). You should remove any
snapshots and share replicas before attempting to unmanage a share.

This API was removed in API version 2.7; please see share actions for the
new version of the API to utilize this feature.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_id: share_id
