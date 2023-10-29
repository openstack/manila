Python
def create_share_network_subnet(request, share_network_id, cidr):
    """Creates a new share network subnet.

    Args:
        request: The HTTP request object.
        share_network_id: The ID of the share network.
        cidr: The CIDR range of the subnet.

    Returns:
        The newly created share network subnet.
    """

    if not is_valid_cidr(cidr):
        raise BadRequestException('Invalid CIDR range.')

    subnet = {'cidr': cidr}
    return manila_client.share_network_subnets.create(share_network_id, subnet)


def update_share_network_subnet(request, subnet_id, cidr):
    """Updates an existing share network subnet.

    Args:
        request: The HTTP request object.
        subnet_id: The ID of the share network subnet.
        cidr: The new CIDR range of the subnet.

    Returns:
        The updated share network subnet.
    """

    if not is_valid_cidr(cidr):
        raise BadRequestException('Invalid CIDR range.')

    subnet = {'cidr': cidr}
    return manila_client.share_network_subnets.update(subnet_id, subnet)


def delete_share_network_subnet(request, subnet_id):
    """Deletes an existing share network subnet.

    Args:
        request: The HTTP request object.
        subnet_id: The ID of the share network subnet.

    Returns:
        None.
    """

    manila_client.share_network_subnets.delete(subnet_id)


def create_share_metadata(request, share_id, key, value):
    """Creates a new metadata item for a share.

    Args:
        request: The HTTP request object.
        share_id: The ID of the share.
        key: The name of the metadata item.
        value: The value of the metadata item.

    Returns:
        None.
    """

    metadata = {key: value}
    manila_client.shares.set_metadata(share_id, metadata)


def update_share_metadata(request, share_id, key, value):
    """Updates an existing metadata item for a share.

    Args:
        request: The HTTP request object.
        share_id: The ID of the share.
        key: The name of the metadata item.
        value: The new value of the metadata item.

    Returns:
        None.
    """

    metadata = {key: value}
    manila_client.shares.update_metadata(share_id, metadata)


def delete_share_metadata(request, share_id, key):
    """Deletes an existing metadata item for a share.

    Args:
        request: The HTTP request object.
        share_id: The ID of the share.
        key: The name of the metadata item to delete.

    Returns:
        None.
    """

    manila_client.shares.delete_metadata(share_id, key)


def create_share_lock(request, share_id, lock_type, lock_owner):
    """Creates a new lock on a share.

    Args:
        request: The HTTP request object.
        share_id: The ID of the share.
        lock_type: The type of lock.
        lock_owner: The owner of the lock.

    Returns:
        The newly created lock.
    """

    lock = {'type': lock_type, 'owner': lock_owner}
    return manila_client.shares.lock(share_id, lock)


def update_share_lock(request, share_id, lock_id, lock_type, lock_owner):
    """Updates an existing lock on a share.

    Args:
        request: The HTTP request object.
        share_id: The ID of the share.
        lock_id: The ID of the lock.
        lock_type: The new type of lock.
        lock_owner: The new owner of the lock.

    Returns:


"""