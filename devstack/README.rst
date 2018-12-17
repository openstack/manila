======================
 Enabling in Devstack
======================

1. Download DevStack

2. Add this repo as an external repository::

     > cat local.conf
     [[local|localrc]]
     enable_plugin manila https://git.openstack.org/openstack/manila

3. run ``stack.sh``
