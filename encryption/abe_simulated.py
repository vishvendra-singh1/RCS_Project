def abe_encrypt(data, user_attrs, policy):
    import time
    import random
    time.sleep(0.015 + random.random()*0.01)
    if policy.issubset(user_attrs):
        return "ABE_ENCRYPTED::" + data
    else:
        return None
