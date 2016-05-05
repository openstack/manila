#!/bin/bash
#
#

set -o errexit

source $GRENADE_DIR/grenaderc
source $GRENADE_DIR/functions

source $BASE_DEVSTACK_DIR/functions
source $BASE_DEVSTACK_DIR/stackrc # needed for status directory

# Locate the manila plugin and get its functions
MANILA_DEVSTACK_DIR=$(dirname $(dirname $0))
source $MANILA_DEVSTACK_DIR/plugin.sh

set -o xtrace

stop_manila

# Ensure everything is stopped
ensure_services_stopped manila-api manila-share manila-scheduler manila-data
