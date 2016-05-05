#!/usr/bin/env bash

# ``upgrade-manila``

echo "*********************************************************************"
echo "Begin $0"
echo "*********************************************************************"

# Clean up any resources that may be in use
cleanup() {
    set +o errexit

    echo "*********************************************************************"
    echo "ERROR: Abort $0"
    echo "*********************************************************************"

    # Kill ourselves to signal any calling process
    trap 2; kill -2 $$
}

trap cleanup SIGHUP SIGINT SIGTERM

# Keep track of the grenade directory
RUN_DIR=$(cd $(dirname "$0") && pwd)

# Source params
source $GRENADE_DIR/grenaderc

# Import common functions
source $GRENADE_DIR/functions

# This script exits on an error so that errors don't compound and you see
# only the first error that occurred.
set -o errexit

# Upgrade Manila
# ==============
# Locate manila devstack plugin, the directory above the
# grenade plugin.
MANILA_DEVSTACK_DIR=$(dirname $(dirname $0))

# Get functions from current DevStack
source $TARGET_DEVSTACK_DIR/functions
source $TARGET_DEVSTACK_DIR/lib/tls
source $TARGET_DEVSTACK_DIR/stackrc
source $(dirname $(dirname $BASH_SOURCE))/settings
source $(dirname $(dirname $BASH_SOURCE))/plugin.sh

# Print the commands being run so that we can see the command that triggers
# an error.  It is also useful for following allowing as the install occurs.
set -o xtrace

# Save current config files for posterity
[[ -d $SAVE_DIR/etc.manila ]] || cp -pr $MANILA_CONF_DIR $SAVE_DIR/etc.manila

# Install the target manila
install_manila

# calls upgrade-manila for specific release
upgrade_project manila $RUN_DIR $BASE_DEVSTACK_BRANCH $TARGET_DEVSTACK_BRANCH

# Migrate the database
$MANILA_BIN_DIR/manila-manage db sync || die $LINENO "DB migration error"

start_manila

# Don't succeed unless the services come up
ensure_services_started manila-api manila-share manila-scheduler manila-data

set +o xtrace
echo "*********************************************************************"
echo "SUCCESS: End $0"
echo "*********************************************************************"
