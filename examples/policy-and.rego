package policy_and

import rego.v2

default allow := false

# ------------------------------------------------------------------------------
# Logical AND using `ast.LogicalAnd`
# ------------------------------------------------------------------------------
# In Rego v2 (via `import rego.v2`), the infix `and` keyword creates an
# `ast.LogicalAnd` node in the AST:
#    <lhs> and <rhs>
#
# Semantics for Evaluation & Denotational Semantics:
# 1. Short-Circuiting:
#    - First, the Left-Hand Side (LHS) is evaluated.
#    - If LHS is undefined (fails), RHS is NEVER evaluated (short-circuit).
# 2. Closed Scope / Isolated Operands:
#    - Each operand (LHS and RHS) is evaluated via `evalLogicalOperand` in an
#      isolated child frame with `findOne = true`.
#    - Variable bindings introduced inside an operand do NOT propagate out.
# 3. Continuation:
#    - If and only if BOTH LHS and RHS succeed, `evalLogicalAnd` calls `iter(e)`
#      to advance to the next expression in the query conjunction.
# ------------------------------------------------------------------------------

# 1. Infix AND between two attribute tests
is_admin if {
    input.user.status == "active" and input.user.role == "admin"
}

# 2. Infix AND for request matching (short-circuits if method != "GET")
valid_request if {
    input.method == "GET" and input.path == "/api/v1/resource"
}

# Overall decision: allow if both conditions hold and the account is not locked
allow if {
    is_admin and valid_request and not input.locked
}
