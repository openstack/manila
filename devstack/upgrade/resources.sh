#!/bin/bash

set -o errexit

source $GRENADE_DIR/grenaderc
source $GRENADE_DIR/functions

source $TOP_DIR/openrc admin demo

set -o xtrace

################################# Settings ####################################

# Access rules data specific to first enabled backend.
MANILA_GRENADE_ACCESS_TYPE=${MANILA_GRENADE_ACCESS_TYPE:-"ip"}
MANILA_GRENADE_ACCESS_TO=${MANILA_GRENADE_ACCESS_TO:-"127.0.0.1"}

# Network information that will be used in case DHSS=True driver is used
# with non-single-network-plugin.
MANILA_GRENADE_NETWORK_NAME=${MANILA_GRENADE_NETWORK_NAME:-"private"}
MANILA_GRENADE_SUBNET_NAME=${MANILA_GRENADE_SUBNET_NAME:-"private-subnet"}

# Timeout that will be used for share creation wait operation.
MANILA_GRENADE_WAIT_STEP=${MANILA_GRENADE_WAIT_STEP:-"4"}
MANILA_GRENADE_WAIT_TIMEOUT=${MANILA_GRENADE_WAIT_TIMEOUT:-"300"}

MANILA_GRENADE_SHARE_NETWORK_NAME=${MANILA_GRENADE_SHARE_NETWORK_NAME:-"manila_grenade_share_network"}
MANILA_GRENADE_SHARE_TYPE_NAME=${MANILA_GRENADE_SHARE_TYPE_NAME:-"manila_grenade_share_type"}
MANILA_GRENADE_SHARE_NAME=${MANILA_GRENADE_SHARE_NAME:-"manila_grenade_share"}
MANILA_GRENADE_SHARE_SNAPSHOT_NAME=${MANILA_GRENADE_SHARE_SNAPSHOT_NAME:-"manila_grenade_share_snapshot"}

# Extra specs that will be set for newly created share type
MANILA_GRENADE_SHARE_TYPE_SNAPSHOT_SUPPORT_EXTRA_SPEC=${MANILA_GRENADE_SHARE_TYPE_SNAPSHOT_SUPPORT_EXTRA_SPEC:-"True"}
MANILA_GRENADE_SHARE_TYPE_CREATE_SHARE_FROM_SNAPSHOT_SUPPORT_EXTRA_SPEC=${MANILA_GRENADE_SHARE_TYPE_CREATE_SHARE_FROM_SNAPSHOT_SUPPORT_EXTRA_SPEC:-"True"}
MANILA_GRENADE_SHARE_TYPE_REVERT_TO_SNAPSHOT_SUPPORT_EXTRA_SPEC=${MANILA_GRENADE_SHARE_TYPE_REVERT_TO_SNAPSHOT_SUPPORT_EXTRA_SPEC:-"True"}
MANILA_GRENADE_SHARE_TYPE_MOUNT_SNAPSHOT_SUPPORT_EXTRA_SPEC=${MANILA_GRENADE_SHARE_TYPE_MOUNT_SNAPSHOT_SUPPORT_EXTRA_SPEC:-"True"}

MANILA_CONF_DIR=${MANILA_CONF_DIR:-/etc/manila}
MANILA_CONF=$MANILA_CONF_DIR/manila.conf

################################ Scenarios ####################################

function scenario_1_do_share_with_rules_and_metadata {
    # NOTE(vponomaryov): nova-network with DHSS=True drivers is not supported
    # by this scenario.
    enabled_share_backends=$(iniget $MANILA_CONF DEFAULT enabled_share_backends)
    backend=$( echo $enabled_share_backends | cut -d',' -f 1 )

    enabled_share_protocols=$(iniget $MANILA_CONF DEFAULT enabled_share_protocols)
    share_protocol=$( echo $enabled_share_protocols | cut -d',' -f 1 )

    driver_handles_share_servers=$(iniget $MANILA_CONF $backend driver_handles_share_servers)

    create_share_cmd="manila create $share_protocol 1 "
    create_share_cmd+="--share-type $MANILA_GRENADE_SHARE_TYPE_NAME "
    create_share_cmd+="--name $MANILA_GRENADE_SHARE_NAME"

    if [[ $(trueorfalse False driver_handles_share_servers) == True ]]; then
        share_driver=$(iniget $MANILA_CONF $backend share_driver)
        generic_driver='manila.share.drivers.generic.GenericShareDriver'
        windows_driver='manila.share.drivers.windows.windows_smb_driver.WindowsSMBDriver'
        network_plugin=$(iniget $MANILA_CONF $backend network_plugin)

        share_network_cmd="manila share-network-create "
        share_network_cmd+="--name $MANILA_GRENADE_SHARE_NETWORK_NAME"
        if is_service_enabled neutron; then
            if [[ $share_driver == $generic_driver || \
                    $share_driver == $windows_driver || \
                    ! $network_plugin =~ 'Single' || \
                    ! $network_plugin =~ 'Standalone' ]]; then
                net_id=$(openstack network show $MANILA_GRENADE_NETWORK_NAME -c id -f value)
                subnet_id=$(openstack subnet show $MANILA_GRENADE_SUBNET_NAME -c id -f value)
                share_network_cmd+=" --neutron-net $net_id --neutron-subnet $subnet_id"
            fi
        else
            echo 'Neutron service is disabled, creating empty share-network'
        fi
        create_share_cmd+=" --share-network $MANILA_GRENADE_SHARE_NETWORK_NAME"
        resource_save manila share_network $MANILA_GRENADE_SHARE_NETWORK_NAME
    else
        resource_save manila share_network 'None'
    fi

    # Create share-network
    eval $share_network_cmd

    # Create share-type
    manila type-create \
        $MANILA_GRENADE_SHARE_TYPE_NAME \
        $driver_handles_share_servers \
        --snapshot_support $MANILA_GRENADE_SHARE_TYPE_SNAPSHOT_SUPPORT_EXTRA_SPEC \
        --create_share_from_snapshot_support $MANILA_GRENADE_SHARE_TYPE_CREATE_SHARE_FROM_SNAPSHOT_SUPPORT_EXTRA_SPEC \
        --revert_to_snapshot_support $MANILA_GRENADE_SHARE_TYPE_REVERT_TO_SNAPSHOT_SUPPORT_EXTRA_SPEC \
        --mount_snapshot_support $MANILA_GRENADE_SHARE_TYPE_MOUNT_SNAPSHOT_SUPPORT_EXTRA_SPEC

    # Create share
    eval $create_share_cmd

    # Wait for share creation results
    wait_timeout=$MANILA_GRENADE_WAIT_TIMEOUT
    available='false'
    while (( wait_timeout > 0 )) ; do
        current_status=$( manila show $MANILA_GRENADE_SHARE_NAME | \
                          grep " status " | get_field 2 )
        if [[ $current_status == 'available' ]]; then
            available='true'
            break
        elif [[ $current_status == 'creating' ]]; then
            ((wait_timeout-=$MANILA_GRENADE_WAIT_STEP))
            sleep $MANILA_GRENADE_WAIT_STEP
        elif [[ $current_status == 'error' ]]; then
            die $LINENO "Share is in 'error' state."
        else
            die $LINENO "Should never reach this line."
        fi
    done
    if [[ $available == 'true' ]]; then
        echo "Share has been created successfully."
    else
        die $LINENO "Share timed out to reach 'available' status."
    fi

    # Create some metadata
    manila metadata $MANILA_GRENADE_SHARE_NAME set gre=nade

    # Add access rules
    manila access-allow $MANILA_GRENADE_SHARE_NAME \
        $MANILA_GRENADE_ACCESS_TYPE $MANILA_GRENADE_ACCESS_TO

    # Wait for access rule creation results
    wait_timeout=$MANILA_GRENADE_WAIT_TIMEOUT
    active='false'
    while (( wait_timeout > 0 )) ; do
        current_state=$( manila access-list $MANILA_GRENADE_SHARE_NAME | \
                         grep " $MANILA_GRENADE_ACCESS_TO " | get_field 5 )
        case $current_state in
            active)
                active='true'
                break;;
            creating|new|queued_to_apply|applying)
                ((wait_timeout-=$MANILA_GRENADE_WAIT_STEP))
                sleep $MANILA_GRENADE_WAIT_STEP;;
            error)
                die $LINENO "Failed to create access rule.";;
            *)
                die $LINENO "Should never reach this line.";;
        esac
    done
    if [[ $active == 'true' ]]; then
        echo "Access rule has been created successfully."
    else
        die $LINENO "Access rule timed out to reach 'active' state."
    fi
}

function scenario_1_verify_share_with_rules_and_metadata {
    share_status=$(manila show $MANILA_GRENADE_SHARE_NAME | \
        grep " status " | get_field 2)
    if [[ $share_status != "available" ]]; then
        die $LINENO "Share status is not 'available'. It is $share_status"
    fi

    rule_state=$(manila access-list $MANILA_GRENADE_SHARE_NAME | \
        grep " $MANILA_GRENADE_ACCESS_TO " | get_field 5)
    if [[ $rule_state != "active" ]]; then
        die $LINENO "Share rule state is not 'active'. It is $rule_state"
    fi

    metadata=$(manila metadata-show $MANILA_GRENADE_SHARE_NAME | \
        grep 'gre' | get_field 2)
    if [[ $metadata != "nade" ]]; then
        die $LINENO "Share metadata is not 'gre=nade'. It is gre=$metadata"
    fi
}

function scenario_1_destroy_share_with_rules_and_metadata {
    manila delete $MANILA_GRENADE_SHARE_NAME

    wait_timeout=$MANILA_GRENADE_WAIT_TIMEOUT
    found='true'
    while (( wait_timeout > 0 )) ; do
        share_status=$( manila list --columns id,name,status | \
            grep $MANILA_GRENADE_SHARE_NAME | get_field 3)
        if [[ -z $share_status ]]; then
            found='false'
            break
        elif [[ $share_status == 'deleting' ]]; then
            ((wait_timeout-=$MANILA_GRENADE_WAIT_STEP))
            sleep $MANILA_GRENADE_WAIT_STEP
        elif [[ $share_status == 'error_deleting' ]]; then
            die $LINENO "Share failed to be deleted."
        else
            die $LINENO "Should never reach this line."
        fi
    done
    if [[ $found == 'true' ]]; then
        die $LINENO "Share timed out to be deleted."
    else
        echo "Share has been deleted successfully."
    fi

    share_network=$(resource_get manila share_network)
    if [[ -n $share_network && $share_network != 'None' ]]; then
        manila share-network-delete $MANILA_GRENADE_SHARE_NETWORK_NAME
    fi

    manila type-delete $MANILA_GRENADE_SHARE_TYPE_NAME
}

#####

function scenario_2_do_attach_ss_to_sn {
    manila security-service-create \
        ldap \
        --name fake_ss_name \
        --description fake_ss_description \
        --dns-ip fake_dns_ip \
        --server fake_server \
        --domain fake_domain \
        --user fake_user \
        --password fake_password

    manila share-network-create \
        --name fake_sn_name \
        --description fake_sn_description \
        --neutron-net-id fake_net \
        --neutron-subnet-id fake_subnet

    manila share-network-security-service-add fake_sn_name fake_ss_name
}

function scenario_2_verify_attach_ss_to_sn {
    attached_security_service=$(\
        manila share-network-security-service-list fake_sn_name | \
        grep "fake_ss_name")
    if [[ -z $attached_security_service ]] ; then
        die $LINENO "Security service 'fake_ss_name' is not attached "\
                    "to share-network 'fake_sn_name'."
    fi

    function assert {
        actual=$(manila $1 $2 | grep " $3 " | get_field 2)
        if [[ $actual != $4 ]]; then
            die $LINENO "Field $3 for command $1 with arg $2 has "\
                        "value $actual, but $4 is expected."
        fi
    }

    assert share-network-show fake_sn_name description fake_sn_description
    assert share-network-show fake_sn_name neutron_net_id fake_net
    assert share-network-show fake_sn_name neutron_subnet_id fake_subnet

    assert security-service-show fake_ss_name description fake_ss_description
    assert security-service-show fake_ss_name dns_ip fake_dns_ip
    assert security-service-show fake_ss_name server fake_server
    assert security-service-show fake_ss_name domain fake_domain
    assert security-service-show fake_ss_name user fake_user
    assert security-service-show fake_ss_name password fake_password
}

function scenario_2_destroy_attach_ss_to_sn {
    manila share-network-delete fake_sn_name
    manila security-service-delete fake_ss_name
}

#####

function scenario_3_do_quotas {
    current_shares_quota=$(manila quota-show --tenant fake | \
        grep " shares " | get_field 2)
    ((new_shares_quota=$current_shares_quota + 5))
    manila quota-update fake --shares $new_shares_quota
    resource_save manila quota $new_shares_quota
}

function scenario_3_verify_quotas {
    shares_quota=$(manila quota-show --tenant fake | \
        grep " shares " | get_field 2)
    expected=$(resource_get manila quota)
    if [[ $shares_quota != $expected ]] ; then
        die $LINENO "Shares quota for 'fake' tenant is expected "\
                    "as $expected but it is $shares_quota."
    fi
}

function scenario_3_destroy_quotas {
    manila quota-delete --tenant fake
}

#####

function scenario_4_do_private_share_types {
    manila type-create ${MANILA_GRENADE_SHARE_TYPE_NAME}_scenario4 false \
        --is-public false
    manila type-access-add ${MANILA_GRENADE_SHARE_TYPE_NAME}_scenario4 \
        $(openstack project show demo -c id -f value)
}

function scenario_4_verify_private_share_types {
    share_type_visibility=$(manila type-list --all \
        --columns name,visibility | \
        grep ${MANILA_GRENADE_SHARE_TYPE_NAME}_scenario4 | get_field 2)
    if [[ $share_type_visibility != 'private' ]] ; then
        die $LINENO "Visibility of share type "\
                    "${MANILA_GRENADE_SHARE_TYPE_NAME}_scenario4 is not "\
                    "'private'. It is $share_type_visibility"
    fi

    project_id=$(openstack project show demo -c id -f value)
    access=$(manila type-access-list \
        ${MANILA_GRENADE_SHARE_TYPE_NAME}_scenario4 | grep $project_id)
    if [[ -z $access ]]; then
        die $LINENO "Expected $project_id project ID is not found in list "\
                    "of allowed projects of "\
                    "${MANILA_GRENADE_SHARE_TYPE_NAME}_scenario4 share type."
    fi
}

function scenario_4_destroy_private_share_types {
    manila type-delete ${MANILA_GRENADE_SHARE_TYPE_NAME}_scenario4
}

#####

function scenario_5_do_share_snapshot {
    if [[ $(trueorfalse True MANILA_GRENADE_SHARE_TYPE_SNAPSHOT_SUPPORT_EXTRA_SPEC) == True ]]; then
        # Create share snapshot
        manila snapshot-create $MANILA_GRENADE_SHARE_NAME \
            --name $MANILA_GRENADE_SHARE_SNAPSHOT_NAME
        resource_save manila share_snapshot $MANILA_GRENADE_SHARE_SNAPSHOT_NAME

        # Wait for share snapshot creation results
        wait_timeout=$MANILA_GRENADE_WAIT_TIMEOUT
        available='false'
        while (( wait_timeout > 0 )) ; do
            current_status=$( manila snapshot-show $MANILA_GRENADE_SHARE_SNAPSHOT_NAME | \
                              grep " status " | get_field 2 )
            if [[ $current_status == 'available' ]]; then
                available='true'
                break
            elif [[ $current_status == 'creating' ]]; then
                ((wait_timeout-=$MANILA_GRENADE_WAIT_STEP))
                sleep $MANILA_GRENADE_WAIT_STEP
            elif [[ $current_status == 'error' ]]; then
                die $LINENO "Share snapshot is in 'error' state."
            else
                die $LINENO "Should never reach this line."
            fi
        done
        if [[ $available == 'true' ]]; then
            echo "Share snapshot has been created successfully."
        else
            die $LINENO "Share snapshot timed out to reach 'available' status."
        fi
    else
        echo "Skipping scenario '5' with creation of share snapshot."
    fi
}

function scenario_5_verify_share_snapshot {
    if [[ $(trueorfalse True MANILA_GRENADE_SHARE_TYPE_SNAPSHOT_SUPPORT_EXTRA_SPEC) == True ]]; then
        # Check that source share ID is set
        share_id_in_snapshot=$( manila snapshot-show \
            $MANILA_GRENADE_SHARE_SNAPSHOT_NAME \
            | grep "| share_id " | get_field 2 )

        if [[ -z $share_id_in_snapshot ]]; then
            die $LINENO "Source share ID is not set."
        fi

        # Check that snapshot's source share ID is correct
        share_id=$( manila show $MANILA_GRENADE_SHARE_NAME \
            | grep "| id   " | get_field 2 )

        if [[ $share_id != $share_id_in_snapshot ]]; then
            die $LINENO "Actual source share ID '$share_id_in_snapshot' is not "\
                "equal to expected value '$share_id'."
        fi

        # Check presence of expected columns in snapshot view
        snapshot_output=$( manila snapshot-show $MANILA_GRENADE_SHARE_SNAPSHOT_NAME )
        for snapshot_column in 'id' 'provider_location' 'name' 'size' 'export_locations'; do
            echo $snapshot_output | grep "| $snapshot_column "
            if [[ $? != 0 ]]; then
                die $LINENO "'$snapshot_column' column was not found in output '$snapshot_output'"
            fi
        done
    fi
}

function scenario_5_destroy_share_snapshot {
    if [[ $(trueorfalse True MANILA_GRENADE_SHARE_TYPE_SNAPSHOT_SUPPORT_EXTRA_SPEC) == True ]]; then
        manila snapshot-delete $MANILA_GRENADE_SHARE_SNAPSHOT_NAME

        wait_timeout=$MANILA_GRENADE_WAIT_TIMEOUT
        found='true'
        while (( wait_timeout > 0 )) ; do
            snapshot_status=$( manila snapshot-list --columns id,name,status | \
                grep $MANILA_GRENADE_SHARE_SNAPSHOT_NAME | get_field 3)
            if [[ -z $snapshot_status ]]; then
                found='false'
                break
            elif [[ $snapshot_status == 'deleting' ]]; then
                ((wait_timeout-=$MANILA_GRENADE_WAIT_STEP))
                sleep $MANILA_GRENADE_WAIT_STEP
            elif [[ $snapshot_status == 'error_deleting' ]]; then
                die $LINENO "Share snapshot failed to be deleted."
            else
                die $LINENO "Should never reach this line."
            fi
        done
        if [[ $found == 'true' ]]; then
            die $LINENO "Share snapshot timed out to be deleted."
        else
            echo "Share snapshot has been deleted successfully."
        fi
    fi
}

################################# Main logic ##################################

function create {
    scenario_1_do_share_with_rules_and_metadata
    scenario_2_do_attach_ss_to_sn
    scenario_3_do_quotas
    scenario_4_do_private_share_types
    scenario_5_do_share_snapshot
    echo "Manila 'create': SUCCESS"
}

function verify {
    scenario_1_verify_share_with_rules_and_metadata
    scenario_2_verify_attach_ss_to_sn
    scenario_3_verify_quotas
    scenario_4_verify_private_share_types
    scenario_5_verify_share_snapshot
    echo "Manila 'verify': SUCCESS"
}

function destroy {
    scenario_5_destroy_share_snapshot
    scenario_1_destroy_share_with_rules_and_metadata
    scenario_2_destroy_attach_ss_to_sn
    scenario_3_destroy_quotas
    scenario_4_destroy_private_share_types
    echo "Manila 'destroy': SUCCESS"
}

function verify_noapi {
    :
}

################################# Dispatcher ##################################

case $1 in
    "create")
        create
        ;;
    "verify_noapi")
        verify_noapi
        ;;
    "verify")
        verify
        ;;
    "destroy")
        destroy
        ;;
    "force_destroy")
        set +o errexit
        destroy
        ;;
esac

###############################################################################
