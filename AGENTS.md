# agent-caps — pointers for coding agents

- What the project is and promises, and the crate layout: [README.md](README.md)
- Disclosure policy — read before anything ships:
  [PUBLIC_DEVELOPMENT.md](PUBLIC_DEVELOPMENT.md)
- Issue, branch, commit and PR conventions:
  [CONTRIBUTING.md](CONTRIBUTING.md)
- Security reports: [SECURITY.md](SECURITY.md)
- What changed in each release: [CHANGELOG.md](CHANGELOG.md)
- Documentation lives in RustDoc only (`cargo doc`), with no `docs/`
  directory: concepts, design, flow diagrams, configuration and file formats,
  command usage and known limits are in the crate and module docs. Code
  documentation outranks stale issue text.
  [CONTRIBUTING.md](CONTRIBUTING.md#documentation) says what goes where.
- The front page of that documentation, and the way into the design: the
  umbrella crate's doc, [crates/agent-caps/src/lib.rs](crates/agent-caps/src/lib.rs),
  then the model in
  [crates/agent-caps-core/src/domain/mod.rs](crates/agent-caps-core/src/domain/mod.rs).
- The requirements ledger (use cases, principles, functional requirements, and
  the rules for changing it) is the module doc of
  [crates/agent-caps/src/_requirements.rs](crates/agent-caps/src/_requirements.rs);
  `cargo test` checks it and every `UC<n>` / `FR<n>` cited in a doc comment
  ([crates/agent-caps/tests/requirements.rs](crates/agent-caps/tests/requirements.rs)).
- The recipes, `just check` among them: [Justfile](Justfile)
- The layer rules `cargo test` enforces: [arch-lint.toml](arch-lint.toml)
- This map is checked: `cargo test` fails when a link here points nowhere, or
  when a root document or recipe file is missing from it
  ([crates/agent-caps/tests/agents_map.rs](crates/agent-caps/tests/agents_map.rs)).
- Never work on `main`; one branch per issue, cut from `origin/main` after a
  fetch. `just worktree-new <type> <slug>` from the main checkout does that and
  runs `just branch-check`.
- `just check` is green. [CONTRIBUTING.md](CONTRIBUTING.md#verification) says
  what it covers.
- Review a change locally before it goes up — by a person or an AI agent — and
  say in the PR body who or what reviewed it.
  [CONTRIBUTING.md](CONTRIBUTING.md#working-with-coding-agents--the-recommended-pattern)
  lists the questions a review answers.
