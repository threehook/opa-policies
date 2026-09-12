package authz

import rego.v1

# By default, deny access if no rules match (best practice)
default allow = false

# Unconditionally allow everything
allow if true
