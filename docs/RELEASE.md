# Release checklist

## Versioning

1. Update `CHANGELOG.md`
2. Bump workspace crate versions (if used) and ensure `Cargo.lock` is up to date

## CI / local checks

```bash
cargo fmt
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --release
```

## Docker artifacts (optional)

```bash
docker build -f Dockerfile.fin-node -t ippan-l2/fin-node:<tag> .
```

## Tagging (example)

```bash
git tag -a vX.Y.Z -m "IPPAN-L2 vX.Y.Z"
```

