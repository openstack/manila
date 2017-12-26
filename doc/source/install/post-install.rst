.. _post-install:

Creating and using shared file systems
======================================

Depending on the option chosen while installing the share node (Option with
share server management and one without); the steps to create and use your
shared file systems will vary. When the Shared File Systems service handles
the creation and management of share servers, you would need to specify the
``share network`` with the request to create a share. Either modes will vary
in their respective share type definition. When using the driver mode with
automatic handling of share servers, a service image is needed as specified
in your configuration. The instructions below enumerate the steps for both
driver modes. Follow what is appropriate for your installation.

.. include:: common/dhss-false-mode-using-shared-file-systems.rst

.. include:: common/dhss-true-mode-using-shared-file-systems.rst

For more information about how to manage shares, see the
`OpenStack End User Guide
<https://docs.openstack.org/manila/latest/user/>`_
