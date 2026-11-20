# Model hosting

A node can host open-weight models: a model is a **fully public** repository
whose releases are signed manifests, with large files stored as
content-addressed blocks outside git. This page covers what ships today:
publishing and reading through the node, and independent consumer fetch from
Arweave and IPFS with no node in the loop.

## What a release is

`twigpine model publish` runs inside a local clone and:

1. Classifies files by the chunking threshold (10 MiB): smaller files stay
   ordinary git blobs, larger ones are packed into content blocks (up to
   128 MiB each) uploaded out of band under an upload session.
2. Commits `.twigpine/model-release.json` (the signed manifest) and
   `.twigpine/model-release.sig` (a detached Ed25519 signature over the exact
   manifest bytes), pushes, and posts a release claim to the node.
3. The node verifies the claim, marks the release `published`, and the
   durability worker then:
   - pins every content block, the reconstruction object, the manifest, each
     git-stored file, and a sha256-to-CID block map to the configured IPFS
     tiers, and
   - posts one compact anchor record to Arweave via Irys, carrying the
     manifest CID + sha256, reconstruction and block-map pointers, and the
     publisher's claim signature.

## Enabling it (operator)

Model hosting is off by default and the node behaves exactly as before
without it.

| Env var | Default | Meaning |
|---------|---------|---------|
| `TWIGPINE_MODEL_HOSTING_ENABLED` | `false` | Master switch; mounts the session/block/claim/read routes. |
| `TWIGPINE_MODEL_QUOTA_BYTES` | `274877906944` (256 GiB) | Per-identity quota for claimed blocks. |
| `TWIGPINE_MODEL_NODE_QUOTA_BYTES` | `1099511627776` (1 TiB) | Total model bytes the node will hold, open sessions included. |
| `TWIGPINE_MODEL_SESSION_TTL_SECS` | `43200` | Base upload-session lifetime; each accepted block renews it. |
| `TWIGPINE_MODEL_UNCLAIMED_TTL_SECS` | `86400` | Grace before blocks no release references are swept. Must exceed the session TTL. |
| `TWIGPINE_MODEL_MAX_SESSION_BYTES` | unset (uses the identity quota) | Optional cap on one identity's open sessions. |
| `TWIGPINE_BLOCKSTORE_DIR` | `./data/model-blocks` | Where blocks live with the filesystem backend. |
| `TWIGPINE_BLOCKSTORE_S3_BUCKET` | unset | Store blocks in S3 instead; reuses the `AWS_*` endpoint and credentials of the Tigris backend. |

## Off-node durability (the tiers that matter)

A published release only survives the node disappearing if its objects are
pinned somewhere off the node. The durability worker writes to every
configured tier:

- **Hot tier**: local Kubo daemon, `TWIGPINE_IPFS_API` (e.g.
  `http://127.0.0.1:5001`). Good for serving; a node-local daemon alone does
  not survive the host.
- **Warm tier**: Pinata or another pinning service, `TWIGPINE_PINATA_JWT`
  (and `TWIGPINE_PINATA_UPLOAD_URL`). This is what puts the objects on the
  public IPFS network where an independent consumer's gateway can read them.
- **Anchor tier**: Arweave via Irys, `TWIGPINE_IRYS_URL`
  (`https://devnet.irys.xyz` for devnet). The anchor is the discovery record
  `model fetch` searches for; without it there is nothing to find.

For a release you expect consumers to fetch without you, configure a warm
tier AND Irys. With neither, the release still serves through the node's own
APIs but nothing leaves the box.

Publishing is permanent: the anchor and pins are outbound records that
outlive the node and cannot be taken back. `twigpine model publish` asks for
confirmation before it claims.

## Reading

### HF-compatible API

A `huggingface_hub` client pointed at the node reads a published release like
an HF repo. The repo id is `<owner_did>/<name>` (the owner segment carries
the DID literally, colons and all):

```python
from huggingface_hub import snapshot_download
# HF_ENDPOINT=https://<node>/hf
snapshot_download(repo_id="did:key:z6Mk.../my-model")
```

Mounted routes: `GET /hf/api/models/{owner}/{repo}`,
`.../revision/{rev}`, `.../tree/{rev}[/{path}]`, `.../refs`, and
`/hf/{owner}/{repo}/resolve/{rev}/{path}` (resumable, range-aware).
Anonymous reads work on fully public repos; HF bearer tokens carry no
signature and read as anonymous.

One size limit to know: huggingface_hub 2.x refuses plain downloads of a
single file over 50 GiB, so `model publish` warns when a chunked file passes
that line.

### Independent fetch (no node)

`twigpine model fetch` rebuilds a release from Arweave and IPFS alone:

```
twigpine model fetch <owner_did>/<name> --expect-did <did> \
    [--revision <commit>] [--output <dir>] \
    [--arweave-gateway https://arweave.net] [--ipfs-gateway https://dweb.link]
```

The fetch searches the Arweave gateway's GraphQL for release anchors tagged
to the repo (newest first), then for each candidate downloads the manifest
and verifies the embedded signature **against the DID you pass in
`--expect-did`**, never a DID read out of the anchor, which is untrusted
text anyone can post. Anchors that fail selection (wrong repo, wrong owner
DID, wrong commit) or verification are skipped with a warning; the first
candidate whose manifest verifies is the release. Every object after that
(manifest, reconstruction, block map, content blocks, git files) is fetched
by CID and sha256-checked against the signed manifest's claims; a hash
failure stops the fetch naming the object.

The result is a directory laid out by manifest path (an HF-snapshot-like
tree), default `<repo-name>-<commit8>` under the current directory. The only
thing you must trust out of band is the publisher's DID; everything else is
verified content.

## Smoke check

With a node running the feature and both providers configured:

1. `twigpine model publish` from a small repo with one file over 10 MiB;
   confirm and wait for the release to reach `published`
   (`GET /api/v1/repos/{owner}/{repo}/models/releases/{commit}`).
2. Confirm the durability jobs drained: the release's pin rows land on the
   configured IPFS tiers and one anchor tx posts to Irys.
3. `HF_ENDPOINT=http://localhost:PORT/hf python -c "from huggingface_hub import snapshot_download; snapshot_download(repo_id='<owner_did>/<name>')"`.
4. Stop the node, then
   `twigpine model fetch <owner_did>/<name> --expect-did <did> --output /tmp/m`
   and diff the result against the original files.
