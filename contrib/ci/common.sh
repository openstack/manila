# Environment variables

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
            # Wait for service VM availability
            source /opt/stack/new/devstack/openrc admin demo
            vm_ip=$(iniget $MANILA_CONF $driver_group service_net_name_or_ip)

            # Check availability
            manila_check_service_vm_availability $vm_ip
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

function archive_file {
    # First argument is expected to be filename
    local filename=$1

    sudo gzip -9 $filename
    sudo chown $USER:stack $filename.gz
    sudo chmod a+r $filename.gz
}

function save_tempest_results {
    # First argument is expected to be number or tempest run

    local src_dirname
    local dst_dirname

    src_dirname="$BASE/new/tempest"
    dst_dirname="$BASE/logs/tempest_$1"

    # 1. Create destination directory
    sudo mkdir $dst_dirname
    sudo chown $USER:stack $dst_dirname
    sudo chmod 755 $dst_dirname

    # 2. Save tempest configuration file
    sudo cp $src_dirname/etc/tempest.conf $dst_dirname/tempest_conf.txt

    # 3. Save tempest log file
    cp $src_dirname/tempest.log $src_dirname/tempest.txt
    echo '' > $src_dirname/tempest.log
    archive_file $src_dirname/tempest.txt
    sudo mv $src_dirname/tempest.txt.gz $dst_dirname/tempest.txt.gz

    # 4. Save tempest stestr results

    if [ -f $src_dirname/.stestr/0 ]; then
        pushd $src_dirname
        sudo stestr last --subunit > $src_dirname/tempest.subunit
        popd
    else
        echo "Tests have not run!"
    fi

    if [ -f $src_dirname/tempest.subunit ]; then
        s2h=`type -p subunit2html`
        sudo $s2h $src_dirname/tempest.subunit $src_dirname/testr_results.html
        archive_file $src_dirname/tempest.subunit
        sudo mv $src_dirname/tempest.subunit.gz $dst_dirname/tempest.subunit.gz

        archive_file $src_dirname/testr_results.html
        sudo mv $src_dirname/testr_results.html.gz $dst_dirname/testr_results.html.gz

        # 5. Cleanup
        sudo rm -rf $src_dirname/.stestr
    else
        echo "No 'stestr' results available for saving. File '$src_dirname/tempest.subunit' is absent."
    fi
}
