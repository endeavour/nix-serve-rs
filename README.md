# nix-serve-rs

Async Nix binary cache server written in Rust. It speaks the same HTTP protocol as
[nix-serve](https://github.com/edolstra/nix-serve) and does not use Starman or Perl.

Perl nix-serve hands each NAR download to one Starman worker. Starman defaults
to five workers and writes the response with a blocking `syswrite`. A handful
of slow clients fill that pool, the process stops calling `accept()`, and
narinfo lookups sit in the listen queue until clients time out.

nix-serve-rs keeps the accept loop on the async runtime. Each NAR is its own
task. narinfo lookups are not limited by in-flight downloads. `TCP_USER_TIMEOUT`
drops a client that stops acknowledging data instead of pinning a worker until
the kernel retransmit timeout.

## Protocol

| Request | Response |
| --- | --- |
| `GET /nix-cache-info` | `StoreDir`, `WantMassQuery`, `Priority` |
| `GET /<hash>.narinfo` | Path info, uncompressed NAR URL, optional signature |
| `GET /nar/<hash>-<narHash>.nar` | NAR body, `Content-Length` from the database |
| `GET /nar/<hash>.nar` | Same, without the hash check |
| `GET /log/<name>` | `nix log` for that store path |

NARs are serialized in-process, not by shelling out to `nix dump-path`. The
bytes match `nix store dump-path` / `nix nar pack`. Compression is `none`.

Path info comes from a short read-only query of the Nix SQLite database. The
connection is closed before the NAR is streamed, so a slow client does not hold
the store database lock.

## Signing

If `NIX_SECRET_KEY_FILE` or `--secret-key-file` is set, narinfo records are
signed with that key and existing signatures from the database are not copied.
The file is the same format nix-serve reads:

```
key-name:<base64 of 64-byte ed25519 secret>
```

The fingerprint is:

```
1;<store-path>;sha256:<nix32>;<nar-size>;<comma-separated full references>
```

Without a key file the server still runs, and any signatures already stored in
the database are passed through.

Generate a key with:

```sh
nix key generate-secret --key-name cache.example.org-1 > /path/to/secret
nix key convert-secret-to-public < /path/to/secret
```

Put the public key in the client's `trusted-public-keys`.

## Run

The process needs read access to the Nix database and the store. Signing also
needs read access to the secret key file.

```sh
nix-serve-rs --port 9500 --secret-key-file /run/secrets/nix-cache-key
```

Then:

```sh
curl http://127.0.0.1:9500/nix-cache-info
nix store ping --store http://127.0.0.1:9500
```

### Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `--port` | `5000` | TCP port. Ignored when `--listen` is set. |
| `--listen` | `[::]:<port>` | Bind address, for example `0.0.0.0:9500`. IPv6 binds dual-stack. |
| `--priority` | `30` | Priority advertised in `/nix-cache-info`. Lower is preferred. |
| `--store-dir` | `$NIX_STORE_DIR` or `/nix/store` | Store directory. |
| `--db` | `/nix/var/nix/db/db.sqlite` | Nix SQLite database. |
| `--secret-key-file` | `$NIX_SECRET_KEY_FILE` | Signing key. Optional. |
| `--write-timeout-secs` | `60` | Drop a connection whose sent data stays unacknowledged this long. |
| `--nar-concurrency` | `64` | Maximum NAR streams in flight. Extra NAR requests get HTTP 503. narinfo is not limited by this. |

`nix` must be on `PATH` for `/log/` requests.

Logs go to stderr. Set `RUST_LOG` to change verbosity (`info` by default).

## Build

```sh
cargo test
cargo build --release
```

Nix package:

```nix
nix-serve-rs = pkgs.callPackage ./package.nix { };
```

`package.nix` builds with `rustPlatform.buildRustPackage` and the checked-in
`Cargo.lock`.