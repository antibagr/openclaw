---
summary: "Plan for generic static command matching in exec control-shell policy."
read_when:
  - Refactoring exec control-shell policy or dangerous command heuristics
  - Adding hard-coded deny or approval-required rules for static shell commands
  - Reviewing Tree-sitter command extraction versus CLI-specific argv matching
title: "Exec control policy matcher"
sidebarTitle: "Exec control policy"
---

# Exec control policy matcher

`exec-control-shell-policy.ts` should stay a narrow extra policy gate for
commands that are known to be dangerous or operationally wrong to run through
host exec. It should not become another allowlist implementation.

The policy model should be:

```text
shell command text
  -> Tree-sitter-backed static command extraction
  -> generic argv, option, and operand normalization
  -> hard-coded command policy rules
  -> allow, deny, or requires-approval
```

Tree-sitter owns shell structure. It can find static commands inside wrappers,
pipelines, chains, and quoted shell payloads such as:

```bash
bash -lc 'openclaw channels login --channel whatsapp'
```

The command matcher owns argv semantics. It should understand generic command
patterns like:

- executable name
- command words
- flags with required values
- flags with `--flag=value`
- positional operands
- static path operands

OpenClaw-specific policy is just one consumer of that matcher.

## Goals

- Express hard-coded dangerous command cases as data, not bespoke parser
  functions.
- Reuse the same matcher for OpenClaw CLI rules and generic shell command
  rules such as blocking reads under `~/.ssh`.
- Keep Tree-sitter as the static command extraction source.
- Keep dynamic shell values unresolved and approval-gated.
- Make new rules readable without knowing carrier wrappers or shell parsing
  details.

## Non-goals

- Do not evaluate environment variables, command substitutions, globs, or shell
  runtime expansion.
- Do not turn control-shell policy into the normal exec allowlist or safe-bin
  policy.
- Do not add a plugin or user configuration surface for these hard-coded rules
  in this refactor.
- Do not special-case `/approve` as an exec command. `/approve` is a chat/control
  action, not a binary policy rule.

## Rule shape

A rule should describe the static command shape it cares about:

```ts
type ControlCommandRule = {
  name: string;
  match: {
    executable?: string | readonly string[];
    command?: readonly string[];
    options?: Record<string, { value?: string | RegExp; present?: boolean }>;
    operands?: Array<{ pathUnder?: string; value?: string | RegExp }>;
  };
  decision: ControlShellPolicyDecision;
};
```

Examples:

```ts
{
  name: "interactive-channel-login",
  match: {
    executable: "openclaw",
    command: ["channels", "login"],
  },
  decision: { kind: "deny", message: INTERACTIVE_CHANNEL_LOGIN_DENY_MESSAGE },
}
```

```ts
{
  name: "read-ssh-secrets",
  match: {
    executable: ["cat", "less", "head", "tail"],
    operands: [{ pathUnder: "~/.ssh" }],
  },
  decision: {
    kind: "requires-approval",
    warning: "Reading SSH files requires explicit approval.",
  },
}
```

The matcher should support aliases by listing multiple rules or multiple command
paths, for example both `openclaw channels login` and `openclaw channel login`.

## Dynamic values

Dynamic shell values are not resolved:

```bash
bash -lc "$CMD"
cat "$HOME/.ssh/id_rsa"
echo "$(whoami)"
```

Tree-sitter can identify that these contain dynamic arguments or command
substitution, but host exec should not pretend it knows the runtime value.
Rules that need path certainty should match only static operands. Rules that
want to treat dynamic operands as risky can add an explicit dynamic-operand
policy later.

## First implementation slice

The first slice should keep behavior narrow:

- refactor existing OpenClaw channel-login and security-audit-suppression rules
  onto the generic matcher
- add a generic static path rule for reads under `~/.ssh`
- keep dynamic path forms unresolved for now
- keep the fallback line parser only as a last-resort candidate source after
  Tree-sitter extraction fails

Verification should include direct commands, package-runner-wrapped commands,
shell-wrapper payloads, read-only config inspection, config mutation, and static
`~/.ssh` read attempts.
