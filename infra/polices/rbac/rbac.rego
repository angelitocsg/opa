package rbac.authz

import rego.v1

# user-role assignments
user_roles := {
    "alice": ["engineering", "webdev"],
    "bod": ["hr"]
}

# role-permissions assignments
role_permissions := {
    "engineering": [{"action": "read", "object": "server123"}],
    "webdev":      [{"action": "read", "object": "server123"},
                    {"action": "write", "object": "server123"}],
    "hr":          [{"action": "read", "object": "database456"}]
}

# logic that implements RBAC
default allow := false
allow if {
    # lookup the list of roles for the user
    roles := user_roles[input.user]
    # for each role in that list
    r := roles[_]
    # lookup the permissions list for role r
    permissions := role_permissions[r]
    # for each permission
    p := permissions[_]
    # check if the permission granted to r matches the user's request
    p == {"action": input.action, "object": input.object}
    # validate jwt payload
    user_owns_token
}

# Ensure that the token was issued to the user supplying it.
user_owns_token if input.user == token.payload.azp

# Helper to get the token payload.
token := {"payload": payload} if {
	[header, payload, signature] := io.jwt.decode(input.token)
}