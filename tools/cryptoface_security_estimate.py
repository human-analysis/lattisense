#!/usr/bin/env python3
"""Reproduce the CryptoFace RLWE security estimates with lattice-estimator.

Run this script with the Python interpreter from a Sage environment and with
the pinned lattice-estimator checkout on PYTHONPATH. The input is the
serialized server mega_ag.json used by inference.
"""

import argparse
import json

from sage.all import binomial, log, oo, prod

from estimator import LWE, ND
from estimator.reduction import ADPS16


def sparse_secret(total_weight, n):
    """Balanced fixed-weight approximation to independent random signs."""
    if total_weight % 2:
        raise ValueError("the balanced sparse-secret model requires an even weight")
    half = total_weight // 2
    return ND.SparseTernary(half, half, n)


def log2_number(value):
    if value == oo:
        return "infinity"
    return float(log(value, 2).n())


def estimate_case(name, n, modulus, secret, quantum_core_svp=False):
    params = LWE.Parameters(
        n=n,
        q=modulus,
        Xs=secret,
        Xe=ND.DiscreteGaussian(3.2),
        m=oo,
        tag=name,
    )
    kwargs = {}
    model = "MATZOV-default-classical"
    if quantum_core_svp:
        kwargs["red_cost_model"] = ADPS16(mode="quantum")
        model = "ADPS16-quantum-Core-SVP"

    attacks = {
        "primal_usvp": LWE.primal_usvp,
        "primal_bdd": LWE.primal_bdd,
        "dual": LWE.dual,
        "dual_hybrid": LWE.dual_hybrid,
    }
    results = {}
    for attack_name, attack in attacks.items():
        cost = attack(params, **kwargs)
        results[attack_name] = {
            "rop_bits": log2_number(cost["rop"]),
            "cost": repr(cost),
        }

    finite = [
        result["rop_bits"]
        for result in results.values()
        if result["rop_bits"] != "infinity"
    ]
    return {
        "name": name,
        "model": model,
        "n": n,
        "log2_modulus": float(log(modulus, 2).n()),
        "unlimited_samples": True,
        "minimum_rop_bits": min(finite) if finite else "greater-than-estimator-512-bit-cap",
        "attacks": results,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mega_ag", help="path to the serialized server mega_ag.json")
    parser.add_argument(
        "--case",
        choices=("active", "remove-q", "remove-p", "he-standard", "ephemeral", "all"),
        default="active",
    )
    parser.add_argument("--q-index", type=int, default=16)
    parser.add_argument("--p-index", type=int, default=2)
    parser.add_argument("--quantum-core-svp", action="store_true")
    args = parser.parse_args()

    with open(args.mega_ag, encoding="utf-8") as stream:
        parameter = json.load(stream)["parameter"]

    n = parameter["n"]
    q_primes = parameter["q"]
    p_primes = parameter["p"]
    main_secret = sparse_secret(192, n)

    q_without_one = q_primes.copy()
    del q_without_one[args.q_index]
    p_without_one = p_primes.copy()
    del p_without_one[args.p_index]

    cases = {
        "active": ("active-QP-H192", prod(q_primes + p_primes), main_secret),
        "remove-q": ("remove-one-Q-H192", prod(q_without_one + p_primes), main_secret),
        "remove-p": ("remove-one-P-H192", prod(q_primes + p_without_one), main_secret),
        "he-standard": ("HE-Standard-v2-Q1747-dense", 2**1747, ND.Ternary),
        "ephemeral": (
            "bootstrap-ephemeral-Q0P-H32",
            prod(q_primes[:1] + p_primes),
            sparse_secret(32, n),
        ),
    }

    selected = cases if args.case == "all" else {args.case: cases[args.case]}
    output = {
        "estimator_note": (
            "SparseTernary uses an exactly balanced sign split. The implementation uses "
            "fixed Hamming weight with independent random signs, so this is a conservative "
            "balanced approximation. m=infinity matches the HE Standard reference model."
        ),
        "main_secret_support_bits": float(log(binomial(n, 192) * 2**192, 2).n()),
        "ephemeral_secret_support_bits": float(log(binomial(n, 32) * 2**32, 2).n()),
        "cases": [],
    }
    for name, modulus, secret in selected.values():
        output["cases"].append(
            estimate_case(name, n, modulus, secret, args.quantum_core_svp)
        )
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
