# DevStack extras script to install Manila

if is_service_enabled manila; then
    if [[ "$1" == "source" ]]; then
        # Initial source
        source $TOP_DIR/lib/manila
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        echo_summary "Installing Manila"
        install_manila
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        echo_summary "Configuring Manila"
        configure_manila
        echo_summary "Initialing Manila"
        init_manila
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        echo_summary "Creating Manila entities for auth service"
        create_manila_accounts
        echo_summary "Creating Manila service flavor"
        create_manila_service_flavor
        echo_summary "Creating Manila service security group"
        create_manila_service_secgroup
        echo_summary "Creating Manila service image"
        create_manila_service_image
        echo_summary "Starting Manila"
        start_manila
    fi

    if [[ "$1" == "unstack" ]]; then
       cleanup_manila
    fi

    if [[ "$1" == "clean" ]]; then
       cleanup_manila
       sudo rm -rf /etc/manila
    fi
fi
