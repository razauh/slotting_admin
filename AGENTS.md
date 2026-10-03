# Repository Agent Instructions

These instructions apply to every AI agent, coding assistant, subagent, and
automation working in this repository. More-specific `AGENTS.md` files may add
rules for a subtree, but they must not weaken the Graphify guardrails below.

## Graph-first policy

This repository has a local code knowledge graph in `graphify-out/`. Treat the
graph as the mandatory first source of codebase context.

For **every user request that may require understanding, locating, explaining,
reviewing, debugging, testing, or modifying source code**, perform the Graphify
preflight and at least one task-specific Graphify query **before** reading any
source-code file.

This rule applies even when:

- the user names a particular source file;
- the requested change appears small or obvious;
- a likely implementation location is already known from memory;
- a previous task queried the graph;
- the task is delegated to a subagent;
- the request is only for a review, explanation, estimate, or plan;
- search results, error messages, or test output already mention source paths.

Each distinct user request starts a new graph-first cycle. Do not rely on a
query performed for an earlier request unless the current request is an
immediate continuation with exactly the same code-exploration objective.

## Hard guardrail: do not use a global Graphify installation

Graphify is installed only inside the project-local `.conda` environment. Never
run any of the following:

```text
graphify ...
python -m graphify ...
python3 -m graphify ...
uvx graphify ...
uv tool run graphify ...
```

Do not use a globally resolved `graphify`, `python`, or `python3`, even if one is
available on `PATH`. Do not install Graphify globally. Do not silently switch to
another virtual environment.

Invoke Graphify through exactly one of these project-local commands, in this
priority order:

1. Linux, macOS, or WSL executable:

   ```bash
   ./.conda/bin/graphify <arguments>
   ```

2. Linux, macOS, or WSL module fallback:

   ```bash
   ./.conda/bin/python -m graphify <arguments>
   ```

3. Windows Conda environment from Git Bash or MSYS2:

   ```bash
   ./.conda/Scripts/graphify.exe <arguments>
   ```

4. Windows Conda Python fallback from Git Bash or MSYS2:

   ```bash
   ./.conda/Scripts/python.exe -m graphify <arguments>
   ```

Using the executable directly is preferred over activating the environment.
Activation is not required and must not be assumed to persist between tool
calls.

## Mandatory preflight before reading source code

Run the following workflow from the repository root, which is the directory
containing this `AGENTS.md`, `.conda/`, and `graphify-out/`.

### 1. Confirm that the graph exists

Check without opening or dumping the graph:

```bash
test -d graphify-out && test -s graphify-out/graph.json
```

The authoritative queryable file is `graphify-out/graph.json`. The expected
human-facing companions are `graphify-out/GRAPH_REPORT.md` and
`graphify-out/graph.html`, but their absence does not permit bypassing the
queryable graph if `graph.json` exists.

Do not read the entire `graphify-out/graph.json` directly. It may be large, and
the Graphify CLI is the intended scoped interface.

### 2. Resolve the project-local Graphify command

Check the local candidates in the priority order listed above. It is acceptable
to run the chosen local command with `--version` when diagnosing availability.

If none of the local candidates exists or works:

- stop before reading source code;
- report that the project-local `.conda` Graphify installation is unavailable;
- include the exact candidate paths that were checked;
- do not fall back to a global executable;
- do not install or modify the environment unless the user explicitly
  authorizes environment changes.

### 3. Formulate a query from the current request

Convert the user's request into a focused natural-language question. The query
should name the feature, behavior, error, subsystem, symbol, or relationship
that must be understood.

Examples:

```bash
./.conda/bin/graphify query "Where is authentication implemented, and how does a login request reach session storage?" --budget 3000

./.conda/bin/graphify query "Which components validate uploaded files, and what calls them?" --budget 3000

./.conda/bin/graphify query "What is connected to PaymentService and which files participate in refund processing?" --budget 3000
```

Use the equivalent `.conda/bin/python -m graphify` or Windows-local form only
when the preferred local executable is unavailable.

### 4. Query before any raw code discovery

At least one Graphify command must complete before using tools that enumerate,
search, or read source code. Before the first query, do not use:

- `rg`, `grep`, `find`, `fd`, `git grep`, or similar source discovery;
- recursive directory listings intended to discover implementation files;
- IDE symbol search or workspace text search;
- direct reads of `.py`, `.pyi`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`,
  `.mts`, `.cts`, `.rs`, or other programming-language source files;
- test-source reads when the purpose is to infer implementation behavior;
- subagents as a way to bypass the graph-first requirement.

Simple metadata checks needed for preflight—such as checking whether
`graphify-out/graph.json` and local `.conda` executables exist—are allowed.

### 5. Use the right graph operation

Choose the smallest operation that answers the current question:

- `query "<question>"` for broad discovery and a relevant scoped subgraph;
- `query "<question>" --dfs` to follow one specific chain deeply;
- `path "<source>" "<target>"` to trace how two concepts connect;
- `explain "<node>"` to inspect one symbol and its immediate neighborhood.

Examples using the preferred local executable:

```bash
./.conda/bin/graphify query "How does an API request reach the database?" --budget 3000
./.conda/bin/graphify query "Trace cache invalidation after a user update" --dfs --budget 3000
./.conda/bin/graphify path "UserService" "DatabasePool"
./.conda/bin/graphify explain "RateLimiter"
```

Do not substitute a full read of `GRAPH_REPORT.md` for a task-specific query.
The report is useful for broad architecture orientation, but `query`, `path`,
and `explain` are the required scoped interfaces.

## Rules after the first query

After a successful task-specific query, raw source inspection is allowed, but
it must remain scoped by the graph evidence.

1. Start with files and symbols named in the Graphify result.
2. Read only the sections needed to verify behavior or make the requested
   change.
3. Expand to neighboring files only when the query result, imports, callers,
   tests, or runtime evidence justify doing so.
4. If the investigation changes direction or introduces a new subsystem,
   perform another Graphify query before exploring that subsystem.
5. Use raw code as the final authority for exact implementation details.
   Graphify narrows the search; it does not replace verification.

### Empty, weak, or ambiguous graph results

A poor result does not permit an immediate repository-wide search.

1. Rephrase the query once using concrete names from the request, error output,
   or first result.
2. Use `explain` for a likely symbol or `path` for a suspected relationship.
3. If the graph still lacks sufficient coverage, state that limitation in the
   working notes and perform the narrowest possible raw search.
4. Do not claim that an absent graph result proves that code or behavior does
   not exist.

### Confidence and provenance

Interpret Graphify edges according to their evidence tags:

- `EXTRACTED`: directly observed in source structure; strong navigation
  evidence, still verify exact behavior before editing.
- `INFERRED`: resolved or derived relationship; treat as a lead that requires
  source confirmation.
- `AMBIGUOUS`: plausible but unresolved; never use as the sole basis for a
  code change or definitive claim.

When Graphify returns `file:line` locations, use them to open the smallest
relevant source ranges first.

## Missing or unusable graph behavior

If `graphify-out/graph.json` is missing, empty, malformed, or unreadable:

- do not silently bypass Graphify and scan the source tree;
- report that the mandatory graph preflight cannot be completed;
- ask the user to run `initialize_graphify.sh`, or request permission to run it
  when initialization is within the task's intended scope;
- do not delete, reconstruct, or hand-edit files under `graphify-out/`;
- do not run a global Graphify installation.

If the graph exists but a local query fails, report the command form used and a
concise error summary. Do not expose secrets or dump environment variables.

## Graph freshness

The graph is a snapshot. Keep it synchronized with code changes.

### Before investigation

If there is evidence that source files changed after the graph was produced,
refresh the graph with the local environment before relying on it:

```bash
./.conda/bin/graphify update .
```

Use the approved local module or Windows fallback if needed. Never use bare
`graphify update .`.

Do not manually change Graphify output files to make them appear current.

### After modifying code

After any task that changes source code, run the local incremental update before
the final response:

```bash
./.conda/bin/graphify update .
```

This post-edit update is mandatory unless:

- the user explicitly forbids generated-file changes;
- the local Graphify command is unavailable;
- the update fails for an environmental or tool error.

When an exception applies, do not hide it. State clearly that the code graph was
not updated and why.

An update does not replace normal verification. Run the relevant tests,
formatters, linters, or type checks separately as required by the task.

## Review and debugging guardrails

For code review:

1. Query the feature or changed subsystem first.
2. Use `path` or `explain` to identify callers and downstream effects.
3. Inspect the diff and relevant raw code only after graph orientation.
4. Verify every finding against source or executable evidence.

For debugging:

1. Query the error, failing symbol, and affected behavior first.
2. Trace likely relationships with `path` or `--dfs`.
3. Read only the implicated implementation and tests.
4. Do not treat graph topology alone as proof of runtime causality.

For implementation:

1. Query the requested behavior and related subsystem.
2. Identify entry points, callers, dependencies, and relevant tests.
3. Inspect the scoped raw files.
4. Make the smallest coherent change.
5. Run normal validation.
6. Run the local `graphify update .` command.

## Subagent and delegation requirements

Any subagent asked to explore or modify code must receive these same
requirements in its task:

- check `graphify-out/graph.json` first;
- use only the project-local `.conda` Graphify command;
- perform a task-specific query before reading source;
- scope raw reads using graph results;
- update the graph after code modifications.

Do not delegate raw repository exploration before completing the graph
preflight. The parent agent remains responsible for ensuring delegated work did
not use a global Graphify executable or bypass the query-first rule.

## Allowed exceptions

The graph-first gate applies to source-code understanding. It does not require a
Graphify query for tasks limited strictly to:

- reading or editing this `AGENTS.md` file;
- manipulating a user-specified non-code artifact without deriving facts about
  the implementation;
- checking whether required Graphify files or local executables exist;
- reporting already captured command output without investigating code.

If a nominally non-code task starts requiring knowledge of implementation,
imports, runtime behavior, tests, or source locations, the graph-first gate
immediately applies.

## Required completion checklist

Before finishing any code-related request, confirm all of the following:

- [ ] I checked that `graphify-out/graph.json` exists and is non-empty.
- [ ] I used Graphify only from the repository's `.conda` environment.
- [ ] I did not invoke a bare/global `graphify`, `python`, or `python3` command
      for Graphify.
- [ ] I ran at least one query tailored to the current request before reading
      source code.
- [ ] I used graph results to scope source reads and searches.
- [ ] I verified inferred or ambiguous relationships against raw source or
      executable evidence.
- [ ] I ran the relevant tests or other normal validation.
- [ ] If I changed source code, I ran the local incremental Graphify update, or
      explicitly reported why it could not be run.

Failure to satisfy a checklist item must be disclosed in the final response;
it must never be silently ignored.


# Strict No-Comments / No-Docstrings Policy

## Purpose

This repository follows a strict **comment-free source code policy**.

Unless the user explicitly activates the override mechanism defined below, agents must **not create, add, modify, improve, rewrite, restore, or maintain comments or docstrings inside source code files**.

This rule applies even when adding comments would normally be considered good practice, improve readability, explain complex logic, document an API, satisfy a linter recommendation, or make generated code easier to understand.

The default behavior is always:

> **Do not add or edit comments or docstrings in source code.**

---

## 1. Prohibited Content

Do not introduce any explanatory comments into source code.

This includes, but is not limited to:

- Inline comments
- End-of-line comments
- Single-line comments
- Multi-line comments
- Block comments
- Docstrings
- Function documentation comments
- Method documentation comments
- Class documentation comments
- Module documentation comments
- Interface documentation comments
- Property comments
- Field comments
- Variable comments
- Parameter comments
- Return-value comments
- Exception documentation
- Algorithm explanations
- Implementation notes
- Developer notes
- TODO comments
- FIXME comments
- HACK comments
- NOTE comments
- WARNING comments
- Example comments
- Usage comments
- Section-divider comments
- Decorative comments
- Commented-out code
- Generated explanatory annotations placed inside comments

Examples of syntax covered by this prohibition include:

```text
// comment

# comment

/* comment */

/**
 * documentation comment
 */

/// documentation comment

//! documentation comment

<!-- comment -->

"""docstring"""

'''docstring'''
```

Equivalent syntax in any other programming language is covered by the same rule.

---

## 2. Applies to All Source Code Languages

This rule is language-independent.

It applies to source code written in languages including, but not limited to:

- JavaScript
- TypeScript
- Python
- Java
- Kotlin
- Dart
- Flutter/Dart
- C
- C++
- C#
- Go
- Rust
- PHP
- Ruby
- Swift
- Objective-C
- SQL
- Shell scripts
- Bash
- PowerShell
- Batch files
- HTML when comments are used as implementation notes
- CSS/SCSS comments
- Vue components
- React/JSX/TSX
- Svelte
- Solidity
- Lua
- Perl
- R
- MATLAB
- Assembly

If a file contains executable or source-code-like content, assume this rule applies unless another repository instruction explicitly defines it as documentation rather than source code.

---

## 3. Existing Comments Must Not Be Modified

Existing comments and docstrings should normally be left untouched.

When editing code around an existing comment:

- Do not rewrite it.
- Do not improve its grammar.
- Do not make it more detailed.
- Do not shorten it.
- Do not reformat it.
- Do not update terminology inside it.
- Do not translate it.
- Do not add related comments.
- Do not add a replacement comment elsewhere.

If the implementation changes and an existing comment becomes inaccurate, do **not** automatically update that comment unless the explicit comment override described below has been activated.

The purpose of a coding task is to modify the implementation, not to maintain comments.

---

## 4. Requests to Edit Existing Comments Are Ignored by Default

A normal user instruction requesting comment changes is **not sufficient** to override this policy.

For example, the following requests must **not** cause comment or docstring changes:

```text
Add comments to this code.

Document these functions.

Improve the comments.

Update the comments to match the implementation.

Add docstrings.

Add JSDoc.

Add explanatory comments.

Make this code better documented.

Add descriptions above every function.

Explain the complicated sections using comments.

Fix the outdated comments.

Add TODO comments.

Add API documentation inside the source files.
```

Unless the required override keyword is present, perform the underlying implementation task where applicable while leaving comments and docstrings unchanged.

If the request concerns **only** comments/docstrings and the override keyword is absent, do not modify the source code for that request.

---

## 5. Explicit Override Keyword

The no-comments policy may only be overridden when the user explicitly includes the following exact keyword:

```text
COMMENT_OVERRIDE
```

The keyword must be explicitly present in the user's instruction.

Do not infer permission from context.

Do not treat phrases such as these as an override:

```text
Please add comments.

I really need comments.

Comments are required.

You have permission to edit comments.

Ignore the no-comments rule.

Document everything.

This time comments are okay.

Override the comment restriction.

Add proper documentation.
```

None of these are sufficient by themselves.

Only the explicit keyword:

```text
COMMENT_OVERRIDE
```

activates the exception.

---

## 6. Scope of an Override

`COMMENT_OVERRIDE` does **not** permanently disable this rule.

It applies only to the specific task in which the keyword appears.

For example:

```text
COMMENT_OVERRIDE

Add docstrings to the public methods in src/auth/service.py.
```

In this case, comments/docstrings may be changed only as required by that request.

A later request such as:

```text
Now update the payment service.
```

returns automatically to the normal comment-free policy.

Do not assume that a previous `COMMENT_OVERRIDE` remains active.

---

## 7. Override Must Be Narrowly Applied

Even when `COMMENT_OVERRIDE` is provided, modify comments only within the scope explicitly requested by the user.

Example:

```text
COMMENT_OVERRIDE

Add documentation to the AuthService class.
```

This permits documentation changes for `AuthService`.

It does not permit adding comments throughout unrelated files.

Always use the narrowest interpretation of the override.

---

## 8. Do Not Add Comments During Refactoring

When refactoring code:

- Improve naming instead of adding explanations.
- Extract functions instead of explaining large code blocks.
- Simplify control flow instead of documenting confusing control flow.
- Use meaningful types instead of explanatory comments.
- Use descriptive constants instead of magic-value comments.
- Use clearer abstractions instead of implementation notes.

Do not add comments merely because a section is complicated.

Prefer making the code understandable through structure and naming.

---

## 9. Do Not Add Comments During Bug Fixes

Bug fixes must not introduce comments such as:

```text
// Fix for issue where user could submit twice.

// Prevent null pointer exception.

// Important: this must happen before authentication.

// Workaround for browser bug.
```

Implement the fix directly.

If context must be preserved, express it through:

- clear function names,
- tests,
- meaningful constants,
- type definitions,
- assertions,
- validation logic,
- commit messages,
- task documentation outside source files where appropriate.

---

## 10. Do Not Add Comments During Feature Development

New features must be implemented without explanatory source-code comments.

Do not automatically add:

- JSDoc
- Dart documentation comments
- Python docstrings
- JavaDoc
- XML documentation comments
- Rust documentation comments
- GoDoc comments
- PHPDoc
- API annotations whose only purpose is documentation

unless they are technically required for program behavior or an explicit `COMMENT_OVERRIDE` is supplied.

---

## 11. Do Not Add Comments to Tests

The same rule applies to test files.

Do not add comments explaining:

- Arrange / Act / Assert
- Given / When / Then
- Test setup
- Mock behavior
- Expected behavior
- Edge cases
- Regression reasons
- Assertions
- Test groups

For example, avoid:

```text
// Arrange

// Act

// Assert
```

Use descriptive test names and helper functions instead.

---

## 12. TDD Does Not Override This Rule

When implementing Test-Driven Development:

### RED

Write a clearly named failing test without comments.

### GREEN

Implement the minimum code necessary without comments.

### REFACTOR

Improve names, structure, abstractions, and duplication without introducing comments.

Comments are not part of the RED-GREEN-REFACTOR process unless `COMMENT_OVERRIDE` is explicitly supplied.

---

## 13. Do Not Generate Commented-Out Code

Never preserve obsolete code by commenting it out.

Do not produce:

```text
// oldImplementation();
```

or:

```text
/*
previous implementation
*/
```

Unused code should normally be removed rather than commented out, provided removal is within the scope of the requested task.

Version control should preserve historical implementations.

---

## 14. TODO / FIXME / HACK Are Also Prohibited

Do not introduce markers such as:

```text
TODO
FIXME
HACK
XXX
TEMP
WORKAROUND
NOTE
IMPORTANT
```

inside comments.

If unfinished work must be recorded, place it in the appropriate external planning mechanism, such as:

- issue tracker,
- task card,
- development plan,
- Markdown task document,
- project backlog,

rather than embedding it in source code.

---

## 15. Documentation Files Are Different From Source-Code Comments

This rule is intended primarily for comments and docstrings embedded within source code.

Normal documentation files may still contain explanatory prose when the task requires it.

Examples include:

```text
README.md
AGENTS.md
CONTRIBUTING.md
docs/*.md
architecture documents
task cards
audit reports
implementation plans
```

Do not interpret the no-comments rule as a prohibition against normal prose documentation.

However, code examples placed inside documentation should also avoid unnecessary comments unless comments are specifically needed to explain the example.

---

## 16. Required Machine Syntax Is Not Considered a Comment

Some files contain comment-like syntax that is technically required by a tool, interpreter, compiler, formatter, or operating system.

Examples may include:

```text
#!/usr/bin/env bash
```

or tool-specific directives that happen to use comment syntax.

These are allowed when they are required for execution, compilation, tooling, or configuration.

The prohibition concerns human-readable explanatory comments and documentation, not syntax required for software behavior.

Do not remove required directives merely because they resemble comments.

---

## 17. Linter or Framework Requirements

Do not automatically add comments because a linter, framework, code generator, or static-analysis tool recommends documentation.

First prefer configuring or satisfying the requirement without explanatory comments when reasonably possible.

If comments or docstrings are strictly required for successful compilation, code generation, runtime behavior, or an unavoidable repository validation rule, preserve the minimum technically required content.

Do not expand it into additional prose.

---

## 18. Generated Code

When generating new code files:

- Do not add file-header comments.
- Do not add author comments.
- Do not add copyright comments unless legally or technically required.
- Do not add generated-by comments.
- Do not add section comments.
- Do not add explanatory comments.
- Do not add docstrings.
- Do not add TODO markers.

Generated files should contain only the code and syntax needed for the implementation.

---

## 19. Do Not Add Comments for AI Readability

Never add comments solely to make code easier for another AI agent to understand.

Agents must understand the code from:

- implementation,
- types,
- function names,
- tests,
- repository structure,
- external documentation,
- task specifications,
- architecture documentation.

Do not use source comments as agent memory.

---

## 20. Handling Ambiguous Requests

If a request could be completed either by changing code or by adding comments, choose the implementation-based solution.

For example:

```text
Make this logic easier to understand.
```

Prefer:

- better naming,
- smaller functions,
- clearer control flow,
- improved abstractions.

Do not interpret this as permission to add comments.

---

## 21. No Opportunistic Comment Changes

When modifying a file for an unrelated reason, do not make opportunistic comment changes.

For example, while fixing a function, do not also:

- clean up nearby comments,
- reword comments,
- remove typos from comments,
- update docstrings,
- standardize comment formatting,
- add documentation to adjacent functions.

Keep comment-related changes completely outside the patch unless explicitly authorized with `COMMENT_OVERRIDE`.

---

## 22. Preserve Minimal Diffs Around Comments

Whenever possible, avoid touching lines containing existing comments.

This helps prevent:

- accidental comment rewrites,
- formatting-only comment changes,
- unnecessary diff noise,
- documentation changes outside the requested scope.

If formatting tools automatically alter comments, avoid manually expanding those changes.

---

## 23. Code Quality Without Comments

Code should remain readable without relying on comments.

Prefer:

```text
descriptive names
small functions
single-purpose methods
clear modules
explicit types
clear validation
well-named constants
descriptive tests
simple control flow
low nesting
meaningful abstractions
```

over explanatory comments.

A confusing implementation should normally be improved rather than explained with a comment.

---

## 24. Priority Rule

Unless `COMMENT_OVERRIDE` is explicitly present in the current user's request, apply the following priority:

1. Correct implementation.
2. Existing project architecture.
3. Existing tests and behavioral contracts.
4. Clear naming and code structure.
5. Minimal and focused changes.
6. **No new comments or docstrings.**
7. **No modification of existing comments or docstrings.**

---

## 25. Default Decision Rule

Whenever uncertain whether something counts as a comment or documentation inside source code, use the conservative interpretation:

> **Do not add it.**

Whenever uncertain whether the user has authorized comment changes:

> **Assume they have not.**

Whenever uncertain whether a previous override still applies:

> **Assume it does not.**

The user must explicitly provide:

```text
COMMENT_OVERRIDE
```

in the current task before explanatory comments or docstrings may be intentionally created or modified.
