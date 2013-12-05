====================
Devstack Integration
====================

This directory contains the files necessary to integrate Manila with devstack.

To install:

$ DEVSTACK_DIR=/path/to/devstack

$ cp lib/manila ${DEVSTACK_DIR}/lib

$ cp extras.d/70-manila.sh ${DEVSTACK_DIR}/extras.d

note: 70-manila.sh uses simple lvm-driver without multitenancy support.

To configure devstack to run manila:

$ cd ${DEVSTACK_DIR}

$ services=(manila m-api m-shr m-sch); for item in ${services[*]}; do echo "enable_service $item" >> localrc; done
