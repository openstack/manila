.. -*- rst -*-

================================
Share Migration (Since API v2.5)
================================
As an administrator, you can migrate a share with its data from one
location to another in a manner that is transparent to users and workloads.

Possible use cases for data migration include:

 - Bring down a physical storage device for maintenance without disrupting
   workloads.
 - Modify the properties of a share.
 - Free up space in a thinly-provisioned back end.

.. note::

    Share Migration APIs are part of the `experimental APIs
    <http://developer.openstack.org/api-ref/shared-file-systems/
    #experimental-apis>`_ .


Migrate share (versions 2.5 to 2.14)
=========================================

.. rest_method::  POST /v2/{tenant_id}/shares/{share_id}/action

Migrates a share from one back end to another.

You can migrate a share from one back end to another but both back
ends must set the ``driver_handles_share_servers`` parameter to
``False``. If a share driver handles one of the back ends, this
action is not supported. You can configure a back end in the
``manila.conf`` file.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_id: share_id
   - os-migrate_share: os-migrate_share
   - migrate_share: migrate_share
   - host: host_10
   - force_host_copy: force_host_copy


Start Migration (Since version 2.15)
====================================

.. rest_method::  POST /v2/{tenant_id}/shares/{share_id}/action

Initiates share migration. This API will initiate the share data copy to the
new host. The copy operation is non-disruptive.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_id: share_id
   - migrate-start: migrate-start
   - host: host_10
   - notify: notify
   - force_host_copy: force_host_copy


Complete Migration (Since version 2.15)
=======================================

.. rest_method::  POST /v2/{tenant_id}/shares/{share_id}/action

Completes share migration. This API will initiate the switch-over from the
source to destination share. This operation is disruptive.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404), conflict(409)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - share_id: share_id
   - migration_complete: migration_complete
   - host: host_10
   - notify: notify
   - force_host_copy: force_host_copy
