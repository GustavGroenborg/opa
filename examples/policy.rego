package authz

default allow := false

# ------------------------------------------------------------------------------
# 1. NOT DESUGARED RULE
# ------------------------------------------------------------------------------
# This rule is already in canonical "Core Rego" form:
# - Head is static with an explicit scalar value (no dynamic references or hoisted terms).
# - Body contains only a single atomic built-in call with flat arguments (`input.path`, `"/public"`).
# - Contains no `some ... in`, no `:=` variable assignments, no nested function calls,
#   and no complex/interpolated terms.
# The compiler passes this rule through all rewrite stages without modification.
public_path := true if {
    startswith(input.path, "/public")
}

# ------------------------------------------------------------------------------
# 2. DESUGARED RULE (Type A: `some ... in` collection iteration)
# ------------------------------------------------------------------------------
# Uses `some ... in ...` collection iteration syntax.
#
# How it is desugared by the compiler (`rewriteSomeDeclStatement` & `rewriteLocalVars`):
# 1. `some r in input.roles` is rewritten into an index lookup against a fresh variable:
#        r = input.roles[__local0__]
# 2. Local variable renaming (`rewriteLocalVars`) canonicalizes declared variables
#    into unique generated names (e.g., `r` -> `__local1__`) to eliminate scope collisions.
has_auditor_role if {
    some r in input.roles
    r == "auditor"
}

# ------------------------------------------------------------------------------
# 3. DESUGARED RULE (Type B: Nested function calls / expression hoisting)
# ------------------------------------------------------------------------------
# Uses nested function calls: lower(trim(input.action, " ")).
#
# How it is desugared by the compiler (`rewriteExprTerms` via `expandExprTerm`):
# Rego's top-down evaluation engine only executes flat, relational 3-address calls.
# The compiler flattens and hoists the inner call into a temporary variable:
#    trim(input.action, " ", __local0__)
#    lower(__local0__, __local1__)
#    __local1__ == "read"
normalized_read_action if {
    lower(trim(input.action, " ")) == "read"
}

# ------------------------------------------------------------------------------
# 4. DESUGARED RULE (Type C: Dynamic reference in rule head)
# ------------------------------------------------------------------------------
# The rule head contains a reference expression in its key: user_permissions[input.user].
#
# How it is desugared by the compiler (`rewriteRuleHeadRefs` & `rewriteRefsInHead`):
# The RuleTree indexing structure requires rule heads to be simple variables or scalars.
# The expression `input.user` is hoisted out of the rule head and into the body:
#    user_permissions[__local0__] := "granted" if {
#        __local0__ = input.user
#        input.user == "alice"
#    }
user_permissions[input.user] := "granted" if {
    input.user.name == "alice"
}

is_pg18 if {
    input.user.age > 18
}

is_lucky if {
    magic_num := (input.user.age * 4) / 2 + 8
    magic_num == 42
}

# Allow access if the public path, normalized action, and required role are satisfied
allow if {
    public_path
    normalized_read_action
    has_auditor_role
    not is_pg18
    is_lucky
}

