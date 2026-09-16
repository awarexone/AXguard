def check_ownership(user_id, resource):
    return resource.get("owner_id") == user_id
