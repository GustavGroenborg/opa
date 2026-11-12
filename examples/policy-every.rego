package policy_every

default allow := false

# ------------------------------------------------------------------------------
# Universal Quantification using `every`
# ------------------------------------------------------------------------------
# In Rego, `every` expresses universal quantification (∀):
#    every <val> in <domain> { <body> }
#    every <key>, <val> in <domain> { <body> }
#
# Semantics for Evaluation & Denotational Semantics:
# 1. Domain Generation: The evaluator sets up a generator subquery to enumerate
#    all key/value pairs from <domain>.
# 2. Element Verification: For EACH element produced by the domain generator,
#    the inner body is evaluated as a subquery with `findOne = true`.
# 3. Vacuous Truth: If <domain> is empty, `every` evaluates to `true`.
# 4. Short-Circuiting: If any element from <domain> fails to satisfy the body,
#    the entire `every` construct fails immediately without checking remaining items.
# ------------------------------------------------------------------------------

# 1. Array iteration with `every <val> in <collection>`
# Asserts that every container image comes from an internal registry,
# does not use the mutable ":latest" tag, and runs with a read-only root filesystem.
all_containers_safe if {
    every container in input.containers {
        startswith(container.image, "registry.internal.example.com/")
        not endswith(container.image, ":latest")
        container.security_context.read_only_root_filesystem == true
    }
}

# 2. Key-Value iteration with `every <key>, <val> in <object>`
# Asserts that every key in the labels object begins with the corporate domain
# prefix and has a non-empty string value.
all_labels_valid if {
    every k, v in input.labels {
        startswith(k, "company.com/")
        v != ""
    }
}

# 3. Vacuous truth demonstration on an empty array
# If `input.exemptions` is empty (`[]`), this evaluates to true vacuously.
all_exemptions_active if {
    every ex in input.exemptions {
        ex.status == "active"
    }
}

# Overall policy decision: allow if all universal checks pass
allow if {
    all_containers_safe
    all_labels_valid
    all_exemptions_active
}
