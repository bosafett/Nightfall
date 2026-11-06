"""CONTROL (JANUS Addendum 5 §11): shared execution-governance rules.

Authorization checks still live next to the routes that need them (`core/tenancy/deps.py`,
`blacksite/boundary.py`, the scope evaluator, the worker's re-check). This package holds the
rules that more than one of them must agree on, so they can't drift apart.
"""
