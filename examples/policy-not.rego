package policy_not

default allow := false

# ------------------------------------------------------------------------------
# Negation as Failure (NAF) using `not`
# ------------------------------------------------------------------------------
# In Rego, `not <expr>` expresses Negation as Failure (NAF):
#    `not <expr>` succeeds if and only if `<expr>` cannot be satisfied (yields 0 solutions).
#
# Semantics for Evaluation & Denotational Semantics:
# 1. Subquery Execution: The engine takes the negated literal, complements it
#    into a positive query body, and evaluates it in an isolated child frame.
# 2. `findOne = true`: The child evaluator stops at the very first solution.
# 3. Boolean Inversion:
#    - If the child query finds >= 1 solution -> `not` FAILS.
#    - If the child query finds 0 solutions  -> `not` SUCCEEDS.
# 4. Variable Safety: Variables appearing in a negated expression cannot be
#    grounded by it. They must be bound ("safe") before the `not` expression.
# ------------------------------------------------------------------------------

# Known revoked users
revoked_users contains "eve"
revoked_users contains "mallory"

# Restricted roles that require separate authorization
restricted_roles contains "super_admin"
restricted_roles contains "billing_admin"

# 1. Negating a base condition / flag
# True if the system is currently under maintenance.
is_maintenance_mode if {
    input.maintenance == true
}

# 2. Negation as Failure over a virtual document (set membership)
# Helper rule checking if the user is revoked.
is_revoked if {
    input.user in revoked_users
}

# Evaluates to true if `is_revoked` has ZERO solutions for `input.user`.
user_not_revoked if {
    not is_revoked
}

# 3. Variable Safety: Grounding variables before negation
# `role` is bound by the positive generator `some role in input.roles`.
# The negated expression `not restricted_roles[role]` tests whether that
# bound value is absent from the restricted_roles set.
has_non_restricted_role if {
    some role in input.roles
    not restricted_roles[role]
}

# Overall policy decision:
# Allow if the action is read, user is not revoked, system is not in maintenance,
# and user possesses at least one non-restricted role.
allow if {
    input.action == "read"
    user_not_revoked
    not is_maintenance_mode
    has_non_restricted_role
}
