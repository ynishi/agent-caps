# agent-caps

Policy catalog and judge for AI coding agents

## Crates

| crate | role |
|---|---|
| `agent-caps` | Umbrella: the name users depend on and the `agent-caps` command (`cargo install agent-caps`). Re-exports the core; the command and what only it needs are behind the default `cli` feature, so a library user writes `default-features = false`. |
| `agent-caps-core` | Core (SDK): `domain`, the pure model (policies, events, the state folded from them, the judgment). No I/O. |

A server that someone hosts for others becomes a crate of its own,
`agent-caps-server`, with its own binary, when it is needed.

The layer rules are in `arch-lint.toml` and run with `cargo test`. A crate or layer
that does not fit the project is deleted, together with its `arch-lint.toml` scope.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
