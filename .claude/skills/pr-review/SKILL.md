---
name: pr-review
description: Have a Fable agent review a change for design and correctness, then fix what it finds. Use before a change is ready for review or before it lands, and again after a large change to it.
---

# Review a change

The agent that wrote a change does not review it alone. A second agent on Claude Fable reads the change with fresh context. The author then fixes the findings.

## Steps

1. Run the repository's own checks (format, lint, type check, tests). The review does not look for what these find.
2. Start one agent with the Agent tool and `model: "fable"`. Give it:
   - the repository path, the base and head of the change (such as `origin/main...HEAD`), and the pull request number if one exists
   - one or two sentences on what the change is for
   - the text of the sections "What to look for", "What not to report", and "How to report" below
   - this instruction: "Read the code and report findings. Do not edit files, commit, or post to GitHub."
3. Fix each **Blocking** finding.
4. For each **Design** finding, do the simpler design in this change when it is in scope. Do not add a workaround in its place. When the refactor is too large for this change, say why and name the follow-up.
5. If the fixes changed the design, run the review again. Stop when no Blocking or Design finding is left, or after three rounds.
6. Add a short "Review" section to the pull request text, or to the commit message when the repository pushes to `main`. List each finding and what you did about it.

## What to look for

Read the repository's `CLAUDE.md` (or `AGENTS.md`, or `.claude/rules/`) and the design docs it names first. They state the rules and the words of the project. Read the whole change, then the code around it. Judge the design that results, not only the lines that changed.

Be ambitious. Do not stop at "this could be a bit cleaner". Look for a restructure that keeps the behaviour and makes whole branches, flags, helpers, or layers disappear. A refactor that moves complexity to a new place but does not remove it is not a fix.

1. **Good, simple architecture.** If we designed this part again today, would it look like this? If a simpler design meets the goal, say so, even when it needs a refactor. Remove before you add: dead code, unused options, and guards for cases that cannot occur.
2. **No chains of workarounds.** A fix on top of a fix shows that the design is wrong. Find the root cause and fix it there. Flag these signs:
   - a new `if` for one caller, platform, or bug in a shared path
   - a second boolean that must stay in step with the first
   - a null check or try/catch that hides a crash instead of removing its cause
   - a workaround that needs a long comment to explain it

   When the code branches on the same question in many places, a missing model is the cause. Use a state machine, a discriminated union, or a lookup table so the branches go away.
3. **No new jargon.** A new term needs a strong reason and a clear definition in the docs. Prefer the project's existing words and common words. Flag a new name for a thing that already has a name.
4. **Simple names.** A name says what the caller gets. Use full words, no abbreviations. A name does not tell how the code works or where it came from.
5. **Boundaries that make removal easy.** Each part does one job behind a small interface. It must be possible to delete or replace a part and change only the code that calls it. Flag:
   - an import that goes the wrong way, or one part that knows the internals of another
   - feature logic in a shared module, or logic outside the layer that owns the concept
   - a near copy of a helper that the code base already has
   - a file that the change pushes past about 1000 lines
6. **Good interfaces.** An interface is small, hides real decisions, and is hard to use wrongly. It does not leak storage, transport, or wire types to the caller. Two paths that do the same job are a design problem. Remove a wrapper with one caller, an adapter with one implementation, and a layer that only passes calls through.
7. **Pure functions and clear data.** Prefer a function that takes its inputs and returns a value. Keep I/O, time, and randomness at the edges, and pass them in as arguments. Validate and parse outside data once, where it enters. Inside, trust the types and do not check again. Make wrong states impossible to build. Flag casts, `any`, and optional fields whose valid combinations need a comment.
8. **Correctness.** Look for bugs, races, data loss, state that an error can leave half updated, and security mistakes.
9. **Docs and tests.** A change that makes a doc or README wrong fixes it. A new rule or behaviour has a test that proves it. A test calls the code as a user does and checks a literal result. Flag a test that still passes when the code under test returns nothing.

## What not to report

- Format, lint, and type errors. The checks in step 1 find them.
- A taste preference that does not make the code simpler or safer.
- A problem that was in the code before this change, unless the change makes it worse.

## How to report

- Give each finding a `file:line`. Start it with **Blocking** (a bug, a security problem, or a doc that is now wrong) or **Design** (items 1 to 7).
- For a Design finding, say what is wrong, what a simpler design is, and what it removes.
- Prefer a few findings you are sure of to a long list. Report every Blocking and Design finding. Report at most three small items.
- Start with the number of findings of each kind, or with "No findings."
- Write in ASD-STE100 Simplified Technical English.

The review rules adapt the pstack skills `thermo-nuclear-code-quality-review` and its `principle-*` skills (github.com/cursor/plugins, pstack).
