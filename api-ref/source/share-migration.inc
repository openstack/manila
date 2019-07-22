.. -*- rst -*-

================================
Share Migration (since API v2.5)
================================
As an administrator, you can migrate a share with its data from one
location to another in a manner that is transparent to users and workloads.

Possible use cases for data migration include:

 - Bring down a physical storage device for maintenance without disrupting
   workloads.
 - Modify the properties of a share.
 - Free up space in a thinly-provisioned back end.

.. note::

    Share Migration APIs are `experimental APIs <#experimental-apis>`_ .


Migrate share (DEPRECATED)
==========================

.. warning::

   This API is deprecated starting with microversion 2.15 and requests to
   this API will fail with a 404 starting from microversion 2.15. Please see
   the new experimental API below.

.. rest_method::  POST /v2/{project_id}/shares/{share_id}/action

.. versionadded:: 2.5

Migrates a share from one back end to another.

You can migrate a share from one back end to another but both back
ends must set the ``driver_handles_share_servers`` parameter to
``False``. If a share driver handles one of the back ends, this
action is not supported. You can configure a back end in the
``manila.conf`` file.

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

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_id: share_id
   - os-migrate_share: os-migrate_share
   - migrate_share: migrate_share
   - host: host_10
   - force_host_copy: force_host_copy


Start Migration (since API v2.15)
=================================

.. rest_method::  POST /v2/{project_id}/shares/{share_id}/action

.. versionadded:: 2.15

Initiates share migration. This API will initiate the share data copy to the
new host. The copy operation is non-disruptive.

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

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_id: share_id
   - migrate-start: migrate-start
   - host: host_10
   - notify: notify
   - force_host_copy: force_host_copy


Complete Migration (since API v2.15)
=======================================

.. rest_method::  POST /v2/{project_id}/shares/{share_id}/action

.. versionadded:: 2.15

Completes share migration. This API will initiate the switch-over from the
source to destination share. This operation is disruptive.

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

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_id: share_id
   - migration_complete: migration_complete
   - host: host_10
   - notify: notify
   - force_host_copy: force_host_copy
