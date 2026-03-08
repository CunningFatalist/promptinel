# Promptinel Design

This document captures the product intent behind Promptinel. It is the shortest explanation
of what the project is trying to optimize for and what it is deliberately not trying to do.

## What Promptinel Optimizes For

Promptinel is designed to be:

- deterministic
- offline-first
- useful in CI and local review workflows
- conservative about trust and capability assumptions
- small enough to understand without a large platform around it

## Product Shape

Promptinel is a static analysis tool for prompt content. It aims to help teams review prompts
before they are executed by an LLM or agent. That affects several design decisions:

- findings should be explainable
- outputs should be stable enough for automation
- configuration should remain explicit
- rules should be documented in user-facing language

## Non-Goals

Promptinel is **not** intended to provide:

- runtime sandboxing
- runtime monitoring
- broad content moderation
- a guarantee of complete prompt-attack detection
- an all-in-one platform for prompt security
- your only line of defense against prompt attacks

It works best as one layer in a broader review and security process.
