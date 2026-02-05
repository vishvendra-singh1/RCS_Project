ROLES = {
    "admin": ["read", "write"],
    "user": ["read"]
}

def rbac(role, action):
    return action in ROLES.get(role, [])
