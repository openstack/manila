.. -*- rst -*-

Availability zones
==================

Describes availability zones that the Shared File Systems service is
configured with.

.. important::

    For API versions 2.6 and prior, replace ``availability-zones`` in the URLs
    with ``os-availability-zone``.


List availability zones
~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/availability-zones

Lists all availability zones.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - availability_zones: availability_zones
   - id: availability_zone_id
   - name: availability_zone_name
   - created_at: created_at
   - updated_at: updated_at

Response example
----------------

.. literalinclude:: samples/availability-zones-list-response.json
   :language: javascript
