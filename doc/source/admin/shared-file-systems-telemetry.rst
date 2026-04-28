.. _shared_file_systems_telemetry:

Shared File Systems Telemetry
=============================

Overview
--------

Telemetry in the Shared File Systems service (Manila) allows operators
to collect and monitor metrics related to shared file systems. These
metrics help track resource usage, monitor performance, and support
billing and auditing use cases.

In OpenStack deployments, telemetry is typically provided by services
such as Ceilometer and Prometheus-based telemetry systems. These
services collect and store metric data generated from notifications
emitted by Manila.

Configuration
-------------

To enable telemetry notifications in the Shared File Systems service,
configure the following options in ``manila.conf``:

- ``[oslo_messaging_notifications] driver`` must be set (for example,
  ``messagingv2``) for notifications to be emitted.

- ``[oslo_messaging_notifications] topics`` defaults to
  ``notifications``.

- ``[DEFAULT] enable_gathering_share_usage_size`` must be set to
  ``True`` to emit periodic usage metrics. The default value is
  ``False``.

- ``[DEFAULT] share_usage_size_update_interval`` defines the polling
  interval in seconds. The default value is ``300``.

Notifications
-------------

The Shared File Systems service emits notifications via
``oslo_messaging`` for various lifecycle events, including:

- ``share.create.start`` and ``share.create.end``
- ``share.delete.start`` and ``share.delete.end``
- ``share.extend.start`` and ``share.extend.end``
- ``share.shrink.start`` and ``share.shrink.end``

Additionally, periodic usage metrics are emitted. The corresponding
Ceilometer meter for share size is:

- ``manila.share.size``

Snapshot-related notifications are currently not emitted by the
service.

Ceilometer Metrics
------------------

If using Ceilometer, operators can access metrics derived from
notifications. See:

`Ceilometer telemetry measurements <https://docs.openstack.org/ceilometer/latest/admin/telemetry-measurements.html#openstack-file-share>`_

Retrieving Metrics
------------------

Telemetry data collected from the Shared File Systems service can be
accessed using OpenStack command-line tools when telemetry services
are configured.

To list available metrics:

.. code-block:: bash

   openstack metric list

To view details of a specific metric:

.. code-block:: bash

   openstack metric show <metric-id>

To retrieve measurements for a metric:

.. code-block:: bash

   openstack metric measures show <metric-id>

Notes
-----

Ensure that telemetry services are properly configured and integrated
with the Shared File Systems service. Without proper configuration,
metrics may not be collected or available for querying.
