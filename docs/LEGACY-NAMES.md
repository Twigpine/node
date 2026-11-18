# Names from before the rename

The project was called Gitlawb before it was renamed to Twigpine. Most of the
old name is gone from the code. What remains is listed here, each with the
reason it stays and when, if ever, it goes. Each kept definition in the code
carries a comment pointing at this file. Anything not on this list that still
says "gitlawb" is an oversight.

## Kept permanently

These are machine identifiers that people do not see, that every node on the
network has to agree on, or that are baked into signed or stored data. Renaming
them would need every node, including ones we do not run, to change in step,
or would invalidate data already stored, and would buy nothing a user can see.

| Name | Where | Why it stays |
|---|---|---|
| `refs/gitlawb/*` | `twigpine-node`: the internal-ref gate in `api/repos.rs`, `hideRefs` in `git/store.rs`, the mirror prune in `sync.rs`, issues in `git/issues.rs` | The namespace holds node-managed data (issues, request markers) in every repository, and nodes copy it from each other with `+refs/*:refs/*`. Renaming it means migrating that data on every node; during the change an older node would treat the new namespace as ordinary user refs. |
| `gitlawb/ref-update/v1` | `CERT_TYPE` in `twigpine-core/src/cert.rs` and `twigpine-attest/src/cert.rs`; the Arweave `Schema` tag written in `twigpine-node/src/arweave.rs` | Signed into every ref-update certificate. Peers refuse a type they do not know, and certificates already signed and anchored carry this one forever. |
| `gitlawb/encrypted-manifest/v1` | `twigpine-node/src/arweave.rs`; CLI Arweave discovery in `clone.rs` | Schema of anchored manifests, stored permanently. |
| `gitlawb/ref-updates/v1` | `REF_UPDATES_TOPIC` in `twigpine-node/src/p2p/mod.rs` | The gossip topic. A node on another topic hears nothing. |
| `/gitlawb/did/` | DHT record key in `twigpine-node/src/p2p/mod.rs` | Key prefix of DHT records other nodes look up. |
| `gitlawb/hkdf-salt/webhook-secret`, `gitlawb/webhook-secret/v1` | `twigpine-node/src/state.rs` | Salt and label of the key that seals webhook secrets at rest. Changing either means re-sealing every stored secret. |
| `gitlawb/hkdf-salt/ipfs-scan-token`, `gitlawb/ipfs-scan-token/v1` | `twigpine-node/src/state.rs` | Salt and label of the scan-token key. Changing them is safe (outstanding tokens would simply be re-issued) but buys nothing; kept beside the webhook pair for consistency. |
| `gitlawb/sig-nonce`, `gitlawb/sig-string` | Signature-ledger hashing in `twigpine-node/src/auth/mod.rs` | Domain labels of replay-ledger entries. Changing them across an upgrade would let a signature seen just before the upgrade be replayed just after it, within the signature-age window. |
| `gitlawb/recipients-tag/v1` | `twigpine-node/src/encrypted_pin.rs` | Tag over the recipient list of encrypted pins already stored. |
| `gitlawb/tasks-cursor-key/v1`, `-tag/v1`, `-stream/v1` | `twigpine-node/src/api/task_cursor.rs` | Key derivation and domain separation for task-list cursors. |
| `gitlawb-push-cursor:v1:` | `twigpine-node/src/api/events.rs` | Domain prefix of push-event cursors that clients hold. |
| `gitlawb-attest-sig/v1` | `SIGNING_DOMAIN` in `twigpine-attest/src/attestation.rs` | Signing domain of attestations; pinned by the canonical-vector tests. |
| `gitlawb-attempt` | `ATTEMPT_METADATA_KEY` in `twigpine-node/src/git/publish.rs`, read back in `git/tigris.rs` | Object-metadata key on objects already in storage. |
| `gitlawb-request:<id>` | Reflog action in `twigpine-node/src/api/repos.rs`, read by the recovery in `durable_outbox.rs` | Recovery matches reflog entries written before an upgrade. |
| `did:gitlawb` | `twigpine-core/src/did.rs` | A DID method the code accepts. Nothing creates one. Renaming an identity method is its own decision, not part of the rename. |
| `gitlawb://alpha` | Bootstrap UCAN resource in `twigpine-core/src/ucan.rs` | The resource of the network-join capability in bootstrap tokens. Nothing compares it with the `twigpine://` spelling. |

## Read under both names, written under the old one

Readers accept both spellings today, through `twigpine_core::url_scheme`.

| Name | Read | Written by | Writers switch |
|---|---|---|---|
| `gitlawb://` remote URLs | Helper and CLI | `twigpine clone`, `init`, `repo`, `mirror`, `quickstart`, the MCP tools | In a later release. Every install ships the helper under both names, but URLs are also shared in docs, the web and MCP output, so a machine with only an older helper cannot use a `twigpine://` URL. Switch once that is rare. |
| Arweave `App-Name: gitlawb` | CLI discovery queries both values | `twigpine-node/src/arweave.rs` | In a later release. An older CLI does not find anchors written under the new value. |
| The git remote named `gitlawb` | `twigpine status` looks for both names | `twigpine init` | With the remote URLs. |
| `gitlawb://repos/<owner>/<repo>` UCAN resources | Node, helper and CLI; the two spellings attenuate as one resource | `twigpine ucan delegate` and the MCP tool, which write the old spelling even when given the new one | Not planned. The node a user pushes to checks the resource, and that can be any node, including ones we do not run; people never see the string. |

## Temporary fallbacks, removed in 1.0

| Name | Where |
|---|---|
| `GITLAWB_*` settings | `twigpine-core/src/legacy_env.rs`, the Docker image's `ENV` defaults, `install.sh`, `install.ps1`, `docker-compose.yml` |
| `~/.gitlawb` | `twigpine-core/src/identity_path.rs` |
| `X-Gitlawb-*` headers | `twigpine-core/src/legacy_headers.rs` |
| `gl`, `git-remote-gitlawb`, `gitlawb-node` command names | Installers, Homebrew formula, Docker image, npm package. `git-remote-gitlawb` stays as long as `gitlawb://` remotes exist. |

## Not decided yet

- `gitlawb_*` metric names, with the infra change and whatever dashboards read them.
- The default database URL `postgresql://localhost/gitlawb` in `twigpine-node/src/config.rs`, and the database and user names in `docker-compose.yml`: existing databases carry these names.
- `infra/`, the macOS app and `bootstrap-peers.json`, which still set the old
  setting names and work through the fallback.
- The npm package name `@gitlawb/gl`, replaced by `@twigpine/cli` in its own change.

## Not ours

- `rapybus-gitlawb.com`, a host run by another operator.
