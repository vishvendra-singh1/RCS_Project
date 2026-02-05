def abe_encrypt(data, user_attrs, policy):
    if policy.issubset(user_attrs):
        return "ABE_ENCRYPTED::" + data
    else:
        return None
