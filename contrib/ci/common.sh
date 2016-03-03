# Environment variables

export MANILA_TEMPEST_COMMIT="4aaa5493"  # 2 Mar, 2016

# ----------------------------------------------

# Functions

# Import devstack functions
source $BASE/new/devstack/functions

function manila_check_service_vm_availability {
    # First argument is expected to be IP address of a service VM

    wait_step=10
    wait_timeout=300
    available='false'
    while (( wait_timeout > 0 )) ; do
        if ping -w 1 $1; then
            available='true'
            break
        fi
        ((wait_timeout-=$wait_step))
        sleep $wait_step
    done

    if [[ $available == 'true' ]]; then
        echo "SUCCESS! Service VM $1 is available."
    else
        echo "FAILURE! Service VM $1 is not available."
        exit 1
    fi
}

function manila_wait_for_generic_driver_init {
    # First argument is expected to be file path to Manila config

    MANILA_CONF=$1
    DRIVER_GROUPS=$(iniget $MANILA_CONF DEFAULT enabled_share_backends)
    for driver_group in ${DRIVER_GROUPS//,/ }; do
        SHARE_DRIVER=$(iniget $MANILA_CONF $driver_group share_driver)
        GENERIC_DRIVER='manila.share.drivers.generic.GenericShareDriver'
        DHSS=$(iniget $MANILA_CONF $driver_group driver_handles_share_servers)
        if [[ $SHARE_DRIVER == $GENERIC_DRIVER && $(trueorfalse False DHSS) == False ]]; then
            # Wait for availability
            source /opt/stack/new/devstack/openrc admin demo
            vm_id=$(iniget $MANILA_CONF $driver_group service_instance_name_or_id)
            vm_ips=$(nova show $vm_id | grep "private network")
            attempts=0
            for vm_ip in ${vm_ips//,/ }; do
                # Get IPv4 address
                if [[ $vm_ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                    # Check availability
                    ((attempts++))
                    manila_check_service_vm_availability $vm_ip
                    break
                fi
            done
            if [[ (( attempts < 1 )) ]]; then
                echo "No IPv4 addresses found among private IPs of '$vm_id' for '$GENERIC_DRIVER'. "\
                    "Reported IPs: '$vm_ips'."
                exit 1
            fi
        fi
    done
}

function manila_wait_for_drivers_init {
    # First argument is expected to be file path to Manila config

    manila_wait_for_generic_driver_init $1

    # Sleep to make manila-share service notify manila-scheduler about
    # its capabilities on time.
    sleep 10
}
