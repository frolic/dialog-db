---
name: pr-review
description: Have a Fable agent review a change for design and correctness, then judge and fix what it finds. Use before a change is ready for review or before it lands, and again after a large change to it.
---

# Review a change

The agent that wrote a change does not review it alone. A second agent on Claude Fable reads the change with fresh context. The reviewer is strict on purpose, so some findings are wrong or too small. The author judges each finding before acting on it.

## Steps

1. Run the repository's own checks (format, lint, type check, tests). The review does not look for what these find.
2. Start one agent with the Agent tool and `model: "fable"`. Give it:
   - the repository path, the base and head of the change (such as `origin/main...HEAD`), and the pull request number if one exists
   - one or two sentences on what the change is for
   - the text of the sections "What to look for", "What not to report", and "How to report" below
   - this instruction: "Read the code and report findings. Do not edit files, commit, or post to GitHub."
3. Judge each finding as "Judge the findings" says. Then fix the findings you keep.
4. If the fixes changed the design, run the review again. Stop when no finding is left to fix, or after three rounds.
5. Add a short "Review" section to the pull request text, or to the commit message when the repository pushes to `main`. List each finding, what you did, and one line on why. Include the findings you dismissed, so a person can overrule you.

## What to look for

Read the repository's `CLAUDE.md` (or `AGENTS.md`, or `.claude/rules/`) and the design docs it names first. They state the rules and the words of the project. Read the whole change, then the code around it. Judge the design that results, not only the lines that changed. Use the items below that fit the change. A small fix does not need a design review. Do not question the goal of the change. Question how the change meets it.

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
- A different approach that you prefer, when you cannot show a concrete problem with the current one.
- A case that no caller or input can reach. Read the callers and the types before you report it.
- A new abstraction for code that changes in only one way today.
- A problem that was in the code before this change, unless the change makes it worse.

## How to report

- Start with the number of findings of each kind, or with "No findings." A review with no findings is a good result. Do not add small items to fill the review.
- Give each finding a `file:line`. Start it with **Blocking** (a bug, a security problem, or a doc that is now wrong) or **Design** (items 1 to 7). Report at most three small items, marked **Small**.
- For each finding, give the evidence. For a bug, name the caller or input that causes it and the steps from there to the failure. For a Design finding, say what is wrong, what a simpler design is, and what it removes.
- If you think a finding is real but you cannot show the path, say so. Do not state a guess as a fact.
- Write in ASD-STE100 Simplified Technical English.

## Judge the findings

You are the lead reviewer. The findings are not a list of tasks. The reviewer saw only the code. You also know the goal, what was tried before, and what the next change will do. Put each finding in one of four groups:

- **Fix.** The finding shows a real path to a bug, or a structural problem that this change adds. Fix it in this change. When the refactor is too large for this change, say why in the Review section and open an issue. Do not add a workaround in its place.
- **Ask.** The answer changes a goal, a public format, or something that cannot be undone. Ask a person, and continue with the safe choice where you can.
- **Note.** The finding is true but small for this stage, or it is about code that this change does not touch. Write it in the Review section, or open an issue when it needs work later.
- **Dismiss.** The finding is wrong, depends on a case that cannot occur, or is a preference. Give the reason in one line.

Use these tests:

- **Trace it.** For "what if X is null" or "what if this runs twice", find the real caller. If the types or an earlier check prevent the case, dismiss the finding.
- **Weigh it.** Compare the code a fix adds with what it prevents. A guard for an unlikely case is the kind of workaround the review exists to stop. Do not add it.
- **Take it seriously** when the finding names a concrete path, when you read it and think "yes, that is right", or when it shows a gap in what you understood. Before you dismiss a security or correctness finding, trace it yourself.

If more than five findings are in Fix, judge them again, harder. If more than five are still in Fix, read the next section.

## When the structure is wrong

Some findings say that the design is wrong, not a line. Do not add another fix of the same kind.

1. If the same finding comes back after you fixed it, or two fixes in a row fail on the same problem, write down in one sentence what the fixes assumed. Check if that assumption is true.
2. Ask: "If we wrote this part today with this requirement from the start, what would we build?"
3. If the answer is not clear, sketch two or three different designs and compare them. Prefer the one that removes the most code and the most rules a reader must know.

The review rules adapt these pstack skills (github.com/cursor/plugins): `thermo-nuclear-code-quality-review`, the rubric and lead judgment of `interrogate`, and the `principle-*` skills, mostly `attack-the-premise`, `fix-root-causes`, `redesign-from-first-principles`, `exhaust-the-design-space`, and `subtract-before-you-add`.
