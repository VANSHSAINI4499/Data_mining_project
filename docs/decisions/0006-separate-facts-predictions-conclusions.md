# 0006. Separate facts, predictions, hypotheses, and conclusions

- Status: accepted
- Date: 2026-10-14

## Context

Mixing observed data with model output and analyst judgement makes results untrustworthy and evaluation circular.

## Decision

We will store observed events, dataset ground truth, model outputs, correlation alerts, and analyst feedback in separate tables; ground truth is immutable; the API and UI label each category.

## Alternatives considered

Updating a single `label` column (destroys ground truth).

## Consequences

- Clear lineage and honest evaluation.
- More tables and joins.
