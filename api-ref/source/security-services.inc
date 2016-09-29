.. -*- rst -*-

=================
Security services
=================

You can create, update, view, and delete a security service. A
security service stores configuration information for clients for
authentication and authorization (AuthN/AuthZ). For example, a
share server will be the client for an existing service such as
LDAP, Kerberos, or Microsoft Active Directory.

You can associate a share with from one to three security service
types:

- ``ldap``. LDAP.

- ``kerberos``. Kerberos.

- ``active_directory``. Microsoft Active Directory.

You can configure a security service with these options:

- A DNS IP address.

- An IP address or host name.

- A domain.

- A user or group name.

- The password for the user, if you specify a user name.


List security services
======================

.. rest_method::  GET /v2/{tenant_id}/security-services

Lists all security services.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: security_service_status
   - type: security_service_type
   - id: security_service_id
   - name: security_service_name

Response example
----------------

.. literalinclude:: samples/security-services-list-response.json
   :language: javascript


List security services with details
===================================

.. rest_method::  GET /v2/{tenant_id}/security-services/detail

Lists all security services with details.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: security_service_status
   - id: security_service_id
   - project_id: security_service_project_id
   - type: security_service_type
   - name: security_service_name
   - description: security_service_description
   - dns_ip: security_service_dns_ip
   - user: security_service_user
   - password: security_service_password
   - domain: security_service_domain
   - server: security_service_server
   - updated_at: security_service_updated_at
   - created_at: security_service_created_at

Response example
----------------

.. literalinclude:: samples/security-services-list-detailed-response.json
   :language: javascript


Show security service details
=============================

.. rest_method::  GET /v2/{tenant_id}/security-services/{security_service_id}

Shows details for a security service.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - security_service_id: security_service_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: security_service_status
   - id: security_service_id
   - project_id: security_service_project_id
   - type: security_service_type
   - name: security_service_name
   - description: security_service_description
   - dns_ip: security_service_dns_ip
   - user: security_service_user
   - password: security_service_password
   - domain: security_service_domain
   - server: security_service_server
   - updated_at: security_service_updated_at
   - created_at: security_service_created_at

Response example
----------------

.. literalinclude:: samples/security-service-show-response.json
   :language: javascript


Create security service
=======================

.. rest_method::  POST /v2/{tenant_id}/security-services

Creates a security service.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
unprocessableEntity(422)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - type: security_service_type
   - name: security_service_name
   - description: security_service_description_request
   - dns_ip: security_service_dns_ip_request
   - user: security_service_user_request
   - password: security_service_password_request
   - domain: security_service_domain_request
   - server: security_service_server_request

Request example
---------------

.. literalinclude:: samples/security-service-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: security_service_status
   - id: security_service_id
   - project_id: security_service_project_id
   - type: security_service_type
   - name: security_service_name
   - description: security_service_description
   - dns_ip: security_service_dns_ip
   - user: security_service_user
   - password: security_service_password
   - domain: security_service_domain
   - server: security_service_server
   - updated_at: security_service_updated_at
   - created_at: security_service_created_at

Response example
----------------

.. literalinclude:: samples/security-service-create-response.json
   :language: javascript


Update security service
=======================

.. rest_method::  PUT /v2/{tenant_id}/security-services/{security_service_id}

Updates a security service.

If the security service is in ``active`` state, you can update only
the ``name`` and ``description`` attributes. A security service in
``active`` state is attached to a share network with an associated
share server.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), unprocessableEntity(422)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - security_service_id: security_service_id_path
   - type: security_service_type
   - name: security_service_name
   - description: security_service_description_request
   - dns_ip: security_service_dns_ip_request
   - user: security_service_user_request
   - password: security_service_password_request
   - domain: security_service_domain_request
   - server: security_service_server_request

Request example
---------------

.. literalinclude:: samples/security-service-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: security_service_status
   - id: security_service_id
   - project_id: security_service_project_id
   - type: security_service_type
   - name: security_service_name
   - description: security_service_description
   - dns_ip: security_service_dns_ip
   - user: security_service_user
   - password: security_service_password
   - domain: security_service_domain
   - server: security_service_server
   - updated_at: security_service_updated_at
   - created_at: security_service_created_at

Response example
----------------

.. literalinclude:: samples/security-service-update-response.json
   :language: javascript


Delete security service
=======================

.. rest_method::  DELETE /v2/{tenant_id}/security-services/{security_service_id}

Deletes a security service.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - security_service_id: security_service_id_path
