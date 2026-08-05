"""Timing attack simulation for VaultKeep."""

import time
import hmac
import os
import statistics
import sys


def naive_compare(a, b):
    """Naive comparison function that returns True if a == b, False otherwise."""

    return a == b


def safe_compare(a, b):
    """Safe comparison function that returns True if a == b, False otherwise."""

    return hmac.compare_digest(a, b)


def _time_compare(compare_fn, a, b, iterations):
    """Run compare_fn(a, b) `iterations` times and return per-call durations in seconds."""

    durations = []
    for _ in range(iterations):
        start = time.perf_counter()
        compare_fn(a, b)
        durations.append(time.perf_counter() - start)
    return durations


def timing_attack_sim(iterations=10000):
    """Simulate a timing attack by comparing naive and safe comparison functions."""

    correct_token = b"supersecrettoken"
    exact_match = b"supersecrettoken"
    last_byte_wrong = b"supersecrettokeN"
    first_byte_wrong = b"Xupersecrettoken"

    cases = [
        ("naive vs exact_match", naive_compare, exact_match),
        ("naive vs last_byte_wrong", naive_compare, last_byte_wrong),
        ("naive vs first_byte_wrong", naive_compare, first_byte_wrong),
        ("safe vs exact_match", safe_compare, exact_match),
        ("safe vs last_byte_wrong", safe_compare, last_byte_wrong),
        ("safe vs first_byte_wrong", safe_compare, first_byte_wrong),
    ]

    print(f"Running {iterations} iterations per case...\n")

    for label, compare_fn, candidate in cases:
        durations = _time_compare(compare_fn, correct_token, candidate, iterations)
        mean = statistics.mean(durations)
        stdev = statistics.stdev(durations) if len(durations) > 1 else 0.0
        print(f"[{label}] mean={mean * 1e9:.1f}ns stdev={stdev * 1e9:.1f}ns")


if __name__ == "__main__":
    # Entry point - optional iteration count as command line argument

    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
    timing_attack_sim(iterations)
