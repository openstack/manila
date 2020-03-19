======================
 Enabling in Devstack
======================

We can enable the manila service in DevStack. For details, please refer to
`development-environment-devstack`_, the following steps can be used as a
quickstart reference:

1. Download DevStack

2. Add this repo as an external repository::

     > cat local.conf
     [[local|localrc]]
     # Enable manila
     enable_plugin manila https://opendev.org/openstack/manila

     # Enable manila ui in the dashboard
     enable_plugin manila-ui https://opendev.org/openstack/manila-ui

3. run ``stack.sh``

.. _development-environment-devstack: https://docs.openstack.org/manila/latest/contributor/development-environment-devstack.html
