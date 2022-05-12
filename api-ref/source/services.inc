.. -*- rst -*-

Services
========

These APIs help in interacting with the Shared File Systems services,
``manila-scheduler``, ``manila-share`` and ``manila-data``.

.. important::

    For API versions 2.6 and prior, replace ``services`` in the URLs
    with ``os-services``.


List services
~~~~~~~~~~~~~

.. rest_method::  GET /v2/services?host={host}&binary={binary}&zone={zone}&state={state}&status={status}

Lists all services optionally filtered with the specified search options.

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
   - host: service_host_query
   - binary: service_binary_query
   - zone: service_zone_query
   - state: service_state_query
   - status: service_status_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - services: services
   - id: service_id_response
   - status: service_status_response
   - binary: service_binary_response
   - zone: service_zone_response
   - host: service_host_response
   - state: service_state_response
   - updated_at: updated_at

Response example
----------------

.. literalinclude:: samples/services-list-response.json
   :language: javascript


Enable service
~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/services/enable

Enables a service.

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
   - binary: service_enable_binary_request
   - host: service_enable_host_request

Request example
---------------

.. literalinclude:: samples/service-enable-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - host: service_enable_host_response
   - binary: service_binary_response
   - disabled: service_disabled_response

Response example
----------------

.. literalinclude:: samples/service-enable-response.json
   :language: javascript


Disable service
~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/services/disable

Disables a service.

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
   - binary: service_disable_binary_request
   - host: service_disable_host_request

Request example
---------------

.. literalinclude:: samples/service-disable-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - host: service_disable_host_response
   - binary: service_disable_binary_response
   - disabled: service_disabled_response

Response example
----------------

.. literalinclude:: samples/service-disable-response.json
   :language: javascript
