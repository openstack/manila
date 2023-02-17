.. -*- rst -*-

Security services
=================

You can create, update, view, and delete security services. A
security service resource represents configuration information for clients for
authentication and authorization (AuthN/AuthZ). For example, a
share server will be the client for an existing security service such as
LDAP, Kerberos, or Microsoft Active Directory.

The Shared File Systems service supports three security service types:

- ``ldap``. LDAP.

- ``kerberos``. Kerberos.

- ``active_directory``. Microsoft Active Directory.

You can configure a security service with these options:

- A DNS IP address. Some drivers may allow a comma separated list of multiple
  addresses, e.g. NetApp ONTAP.

- An IP address or host name.

- A domain.

- An ou, the organizational unit. (available starting with API version 2.44)

- A user or group name.

- The password for the user, if you specify a user name.

- A default AD site, optional (available starting with API version 2.76)

A security service resource can also be given a user defined name and
description.

List security services
~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/security-services

Lists all security services.

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
   - all_tenants: all_tenants_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: security_service_status
   - type: security_service_type
   - id: security_service_id
   - name: name

Response example
----------------

.. literalinclude:: samples/security-services-list-response.json
   :language: javascript


List security services with details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/security-services/detail

Lists all security services with details.

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
   - all_tenants: all_tenants_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: security_service_status
   - id: security_service_id
   - project_id: project_id
   - type: security_service_type
   - name: name
   - description: description
   - dns_ip: security_service_dns_ip
   - user: security_service_user
   - password: security_service_password
   - domain: security_service_domain
   - ou: security_service_ou
   - server: security_service_server
   - default_ad_site: security_service_default_ad_site
   - updated_at: updated_at
   - created_at: created_at

Response example
----------------

.. literalinclude:: samples/security-services-list-detailed-response.json
   :language: javascript


Show security service details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/security-services/{security_service_id}

Shows details for a security service.

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
   - security_service_id: security_service_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: security_service_status
   - id: security_service_id
   - project_id: project_id
   - type: security_service_type
   - name: name
   - description: description
   - dns_ip: security_service_dns_ip
   - user: security_service_user
   - password: security_service_password
   - domain: security_service_domain
   - ou: security_service_ou
   - server: security_service_server
   - default_ad_site: security_service_default_ad_site
   - updated_at: updated_at
   - created_at: created_at

Response example
----------------

.. literalinclude:: samples/security-service-show-response.json
   :language: javascript


Create security service
~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/security-services

Creates a security service.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 422

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - type: security_service_type
   - name: name_request
   - description: description_request
   - dns_ip: security_service_dns_ip_request
   - user: security_service_user_request
   - password: security_service_password_request
   - domain: security_service_domain_request
   - ou: security_service_ou_request
   - server: security_service_server_request
   - default_ad_site: security_service_default_ad_site_request

Request example
---------------

.. literalinclude:: samples/security-service-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: security_service_status
   - id: security_service_id
   - project_id: project_id
   - type: security_service_type
   - name: name
   - description: description
   - dns_ip: security_service_dns_ip
   - user: security_service_user
   - password: security_service_password
   - domain: security_service_domain
   - ou: security_service_ou
   - server: security_service_server
   - default_ad_site: security_service_default_ad_site
   - updated_at: updated_at
   - created_at: created_at

Response example
----------------

.. literalinclude:: samples/security-service-create-response.json
   :language: javascript


Update security service
~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/security-services/{security_service_id}

Updates a security service.

If the security service is in ``active`` state, you can update only
the ``name`` and ``description`` attributes. A security service in
``active`` state is attached to a share network with an associated
share server.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 422

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - security_service_id: security_service_id_path
   - type: security_service_type
   - name: name_request
   - description: description_request
   - dns_ip: security_service_dns_ip_request
   - user: security_service_user_request
   - password: security_service_password_request
   - domain: security_service_domain_request
   - ou: security_service_ou_request
   - server: security_service_server_request
   - default_ad_site: security_service_default_ad_site_request

Request example
---------------

.. literalinclude:: samples/security-service-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - status: security_service_status
   - id: security_service_id
   - project_id: project_id
   - type: security_service_type
   - name: name
   - description: description
   - dns_ip: security_service_dns_ip
   - user: security_service_user
   - password: security_service_password
   - domain: security_service_domain
   - ou: security_service_ou
   - server: security_service_server
   - default_ad_site: security_service_default_ad_site
   - updated_at: updated_at
   - created_at: created_at

Response example
----------------

.. literalinclude:: samples/security-service-update-response.json
   :language: javascript


Delete security service
~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/security-services/{security_service_id}

Deletes a security service.

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
   - security_service_id: security_service_id_path
