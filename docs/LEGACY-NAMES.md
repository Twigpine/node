# Names from before the rename

The project was called Gitlawb before it was renamed to Twigpine. Most of the
old name is gone from the code. What remains is listed here, each with the
reason it stays and when, if ever, it goes. Anything not on this list that
still says "gitlawb" is an oversight.

## Kept permanently

These are machine identifiers that people do not see, that every node on the
network has to agree on, or that are baked into signed or stored data. Renaming
them would need every node, including ones we do not run, to change in step,
and would buy nothing a user can see.

| Name | Where | Why it stays |
|---|---|---|
| `refs/gitlawb/*` | `twigpine-node`: the internal-ref gate in `api/repos.rs`, `hideRefs` in `git/store.rs`, the mirror prune in `sync.rs`, issues in `git/issues.rs` | The namespace holds node-managed data (issues, request markers) in every repository, and nodes copy it from each other with `+refs/*:refs/*`. Renaming it means migrating that data on every node; during the change an older node would treat the new namespace as ordinary user refs. |
| `gitlawb/ref-update/v1` | `twigpine-core/src/cert.rs` (`CERT_TYPE`), and the Arweave `Schema` tag in `twigpine-node/src/ans104.rs` and `arweave.rs` | Signed into every ref-update certificate. Peers refuse a type they do not know, and certificates already signed and anchored carry this one forever. |
| `gitlawb/encrypted-manifest/v1` | `twigpine-node/src/arweave.rs`, CLI Arweave discovery in `clone.rs` | Schema of anchored manifests, stored permanently. |
| `gitlawb/ref-updates/v1` | `twigpine-node/src/p2p/mod.rs` (`REF_UPDATES_TOPIC`) | The gossip topic. A node on another topic hears nothing. |
| `/gitlawb/did/` | `twigpine-node/src/p2p/mod.rs` (DHT record key) | Key prefix of DHT records other nodes look up. |
| `gitlawb/webhook-secret/v1`, `gitlawb/ipfs-scan-token/v1` | `twigpine-node/src/state.rs` | Key-derivation labels. Webhook secrets at rest are sealed under a key derived with this label; changing it means re-sealing them. |
| `gitlawb/recipients-tag/v1` | `twigpine-node/src/encrypted_pin.rs` | Tag over the recipient list of encrypted pins already stored. |
| `gitlawb/tasks-cursor-key/v1`, `-tag/v1`, `-stream/v1` | `twigpine-node/src/api/task_cursor.rs` | Key derivation and domain separation for task-list cursors. |
| `gitlawb-attest-sig/v1` | `twigpine-attest` (`SIGNING_DOMAIN`) | Signing domain of attestations; pinned by the canonical-vector tests. |
| `did:gitlawb` | `twigpine-core/src/did.rs` | A DID method the code accepts. Nothing creates one. Renaming an identity method is its own decision, not part of the rename. |

## Read under both names, written under the old one for now

Readers accept both spellings today. Writers switch in a later release, once
enough of the network reads the new one.

| Name | Read | Written by | Writers switch |
|---|---|---|---|
| `gitlawb://` remote URLs | Helper and CLI, through `twigpine_core::url_scheme` | `twigpine clone`, `init`, `repo`, `mirror`, `quickstart`, the MCP tools | The release after the one that reads both. Client-side only: every install ships the helper under both names. |
| `gitlawb://repos/<owner>/<repo>` UCAN resources | Node and helper, through `twigpine_core::url_scheme`; the two spellings attenuate as one resource | `twigpine ucan delegate`, the MCP tools | Once every bootstrap peer runs a release that reads both. The node hosting a repository is the one that checks it. |
| Arweave `App-Name: gitlawb` | CLI discovery queries both values | `twigpine-node/src/ans104.rs` | The release after the one that reads both. |
| The git remote named `gitlawb` | `twigpine status` looks for both names | `twigpine init` | With the remote URLs. |

## Temporary fallbacks, removed in 1.0

| Name | Where |
|---|---|
| `GITLAWB_*` settings | `twigpine-core/src/legacy_env.rs`, the Docker image's `ENV` defaults, `install.sh`, `install.ps1`, `docker-compose.yml` |
| `~/.gitlawb` | `twigpine-core/src/identity_path.rs` |
| `X-Gitlawb-*` headers | `twigpine-core/src/legacy_headers.rs` |
| `gl`, `git-remote-gitlawb`, `gitlawb-node` command names | Installers, Homebrew formula, Docker image, npm package. `git-remote-gitlawb` stays as long as `gitlawb://` remotes exist. |

## Not decided yet

- `gitlawb_*` metric names, with the infra change and whatever dashboards read them.
- `infra/`, the macOS app and `bootstrap-peers.json`, which still set the old
  setting names and work through the fallback.

## Not ours

- `rapybus-gitlawb.com`, a host run by another operator.
