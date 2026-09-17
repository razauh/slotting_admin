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
