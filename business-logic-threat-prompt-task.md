# Threat Modeling Interview Task: Business Logic Threat Prompt

## Overview

The candidate writes an LLM prompt that reads a system description and produces 10 business logic threats specific to that system. There is no retrieval or knowledge base: the prompt alone must guide the model from the scenario to the threats.

- **Assesses:** prompt engineering, threat modeling judgment, understanding of business logic flaws, and structured output design.
- **Time box:** 90 minutes, as a take-home or a live session.
- **Tools:** any LLM the candidate likes (Claude, GPT, Gemini, a local model). They must show the prompt and the raw output it produced.
- **What good looks like:** threats tied to the scenario's own workflows, not generic OWASP items with the product name swapped in.

## Scenario

Give the candidate this description exactly as written. Their prompt receives it as input.

```
PayLoop is a mobile digital wallet for small merchants and their customers in India.

Users and external entities
- Customers sign up with a mobile number and OTP. They start at KYC Tier 1
  (wallet limit Rs 10,000) and move to Tier 2 (limit Rs 2,00,000) after
  uploading PAN and Aadhaar, which a KYC partner API verifies.
- Merchants onboard through a web portal and receive payouts to their bank
  account every night.
- Support agents use an internal admin console to issue refunds and unlock
  accounts.
- External services: a payment gateway for adding money by card or UPI, the
  KYC partner API, an SMS provider for OTPs, and the merchant's bank for payouts.

Key features
1. Add money: the customer tops up the wallet through the payment gateway.
   The gateway calls PayLoop's webhook to confirm the payment, and the wallet
   is credited.
2. Pay merchant: the customer scans a merchant QR code, enters an amount and
   confirms with a 4-digit wallet PIN.
3. Send money: customers can transfer to other PayLoop users, up to
   Rs 25,000 per day.
4. Promo codes: marketing creates codes such as FIRST100 (Rs 100 cashback on
   the first payment, once per user).
5. Refunds: merchants can refund a payment from the portal. Support agents can
   also refund up to Rs 5,000 without approval; larger refunds need a
   manager's approval in the admin console.
6. Nightly settlement: a batch job totals each merchant's payments minus
   refunds and sends the payout to their bank.
7. Transaction history and monthly statements, downloadable as PDF.

Architecture and cyber controls
- Mobile app and merchant portal call a REST API behind an API gateway on AWS.
- Services: wallet, payments, promotions, refunds and settlement, each with its
  own PostgreSQL database.
- Authentication uses JWTs that expire after 24 hours. Wallet PIN is checked
  on the server.
- The API gateway applies a rate limit of 100 requests per minute per IP.
- Data is encrypted in transit (TLS 1.2) and at rest (AWS KMS).
- Audit logs are kept for admin console actions only.
```

The description deliberately leaves gaps, such as no mention of how webhooks are verified, how balances are updated, or how the promo "once per user" rule is enforced. A strong prompt makes the model reason about what is missing, not only what is stated.

## The task

Write a reusable prompt template that takes one input, `{system_description}`, free text describing a system such as the PayLoop scenario, and produces a business logic threat model.

The prompt must make the model work in three stages:

1. **Extract.** Process the entire description and list the external entities, the features (as workflows with their steps), the sensitive data handled, and the cyber controls that are stated. Also list controls that are missing or unclear.
2. **Map workflows to risks.** For each feature, identify the business rules it relies on (limits, approvals, one-time use, ordering of steps, who may act on what) and the points where those rules could be bypassed.
3. **Generate threats.** Produce exactly 10 business logic threats, drawn from the 12 categories below. Each must be tied to a named feature and a specific step in its workflow. Cover at least 6 different categories, and don't list the same weakness twice under different names.

The prompt must work for any system description, not just PayLoop. We will run it against a second scenario you haven't seen.

## Business logic threat categories

The candidate's prompt should give the model these categories as its checklist for stage 3.

| # | Category | What to look for |
|---|---|---|
| 1 | Out-of-order or skipped steps | A user calls a later step directly, or skips a required step such as verification or approval |
| 2 | Race conditions | Two requests read the same state before either writes, so a check passes twice |
| 3 | API misconfiguration and enforcement gaps | A rule is enforced in the UI or one endpoint but not in the API or another endpoint |
| 4 | Invalid or negative values | Negative, zero, huge, fractional or out-of-range amounts and quantities |
| 5 | Input validation | Fields whose meaning in this system makes bad input dangerous, based on the description |
| 6 | Permission and authorisation failures | Acting on another user's object, or a role doing something outside its limits |
| 7 | Idempotency and replay | The same request, message or webhook processed more than once |
| 8 | Resource exhaustion and quota abuse | Abusing free or limited resources, or exhausting capacity to block others |
| 9 | Concurrency | Parallel actions across sessions, devices or services leaving state inconsistent |
| 10 | Database atomicity | A multi-step update that can half-complete, such as a debit without the matching credit |
| 11 | Critical transaction integrity | Amounts, recipients or totals altered or miscalculated between steps |
| 12 | Sensitive data confidentiality | Business data exposed through features such as statements, exports, logs or error messages |

## Required output format

The prompt must make the model return valid JSON in this shape, so the output can be checked automatically:

```json
{
  "extraction": {
    "external_entities": ["..."],
    "features": [{"name": "...", "steps": ["..."], "business_rules": ["..."]}],
    "sensitive_data": ["..."],
    "stated_controls": ["..."],
    "missing_or_unclear_controls": ["..."]
  },
  "business_logic_threats": [
    {
      "id": "BL01",
      "category": "one of the 12 categories",
      "title": "...",
      "affected_feature": "...",
      "workflow_step": "the exact step that is abused",
      "business_rule_violated": "...",
      "attack_scenario": "step-by-step: what the attacker does",
      "business_impact": "...",
      "assumption": "what the description didn't say that this threat depends on",
      "severity": "Critical | High | Medium | Low",
      "mitigation": "..."
    }
  ]
}
```

The `assumption` field matters. Business logic threats often depend on details the description leaves out, and the model should say so rather than present a guess as fact.

## Deliverables

- [ ] The prompt template, with the system prompt and user prompt separated if you use both
- [ ] The raw model output for the PayLoop scenario, unedited
- [ ] A short note (half a page): which model you used, why you structured the prompt this way, how you'd stop the model producing generic or duplicate threats, and how you'd evaluate the prompt's quality over many scenarios

**Bonus (optional):** run the prompt twice and comment on how consistent the outputs are, or add a self-check step where the model reviews its own threats against the categories before answering.

