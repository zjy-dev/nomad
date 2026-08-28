# Phase 7 P7-B: Atomic Install Lifecycle Core

## Outcome

P7-B adds a library-only install lifecycle for verified Nomad Web bundles. It
does not add or change CLI commands. The public API is:

- install(config, bundle)
- upgrade(config, bundle)
- rollback(config)
- status(config)

The three mutating operations require a stopped runtime. The module always
calls authoritative read_run_state while holding the existing lifecycle lock;
there is no public caller-supplied None bypass. Any non-null run state fails
closed with INSTALL_LIFECYCLE_REQUIRES_STOP.

## Disk contract

All lifecycle-owned metadata is below the existing owner-only Nomad home:

    <home>/
      bundles/<bundle_digest>/          immutable verified bundle
      install/current.json             regular 0600 atomic selector and history
      install/staging/                 private 0700 transaction staging
      install/snapshots/<digest>/      private 0700 byte snapshots
      private/                         existing persistent product state

current.json is a regular file, never a symlink. A temporary owner-only file
is fully written and fsynced, then selected with os.replace, followed by an
install-directory fsync. The selector contains only schema, bundle digests,
snapshot digests, operation names, sequence numbers, and rollback links. It
contains no credentials, database bytes, paths supplied by users, or other
secret-bearing values.

Bundle directories are content-addressed by the digest returned from
bundle.verify_bundle. Publication follows this sequence:

1. Verify the source bundle.
2. Copy only manifest-listed files and manifest.json into private staging.
3. Open source files with O_NOFOLLOW, require regular single-link files and
   exact modes, and verify size and SHA-256 while copying.
4. Fsync every destination file and directory.
5. Verify the complete staged bundle again.
6. Publish with no-replace rename and fsync the bundle-store directory.
7. Verify the published bundle again before switching current.json.

An already-published digest is verified and reused. A repeated install or
upgrade to the current digest returns the existing status without extending
history.

## Upgrade and rollback transaction

Before an upgrade publishes or selects new code, it takes a read-only,
byte-for-byte snapshot of these persistent state files and their SQLite
sidecars when present:

- pairing-coordinator.sqlite3 and its wal/shm sidecars
- remote-mailbox.sqlite3 and its wal/shm sidecars
- relay-v2.sqlite3 and its wal/shm sidecars

Each input is opened read-only with O_NOFOLLOW, must be an owner-only regular
single-link file, and is checked for inode, size, and time stability across the
copy. The snapshot manifest records only relative allowlisted names, sizes, and
SHA-256 digests. Snapshot publication uses the same private staging, file and
directory fsync, no-replace rename, and post-publication verification rules.

The snapshot is an audit and compatibility artifact only. No lifecycle path
can restore it. Persistent pairing, mailbox, relay sequence/cursor, epoch, and
revocation truth is forward-only across upgrade failures and rollback. This
prevents old key/epoch state from being paired with a reused nonce or from
resurrecting revoked authority.

Rollback is therefore a code-pointer operation. The selector and its history
are one canonical current.json value committed with one atomic os.replace.
If the process is killed before that rename, readers observe the complete old
selector and history; after it, they observe the complete new selector and
history. Persistent databases are not part of this transaction and are never
modified by it.

Rollback is one-step and idempotent: a rollback history record consumes its
specific upgrade record. Calling rollback again without a new upgrade leaves
the selected version and history unchanged.

## Ownership and identity boundary

The lifecycle never deletes content-addressed bundles or arbitrary home
content. Cleanup is limited to transaction directories whose parent and
generated name match the private staging contract. No persistent database,
identity file, or unknown file is restored, replaced, or removed.

host-device-registry.sqlite3 and its wal/shm sidecars are deliberately
excluded. They are the remote identity and revocation authority, not
application version state. Install, upgrade, rollback, and their recovery paths
never snapshot, restore, or delete them. Remote revoke and uninstall remain
outside P7-B.

## Verification

Focused tests cover:

- exact allowlist copy, content-addressed publication, and repeated operations;
- source and installed tamper detection;
- source symlink, hardlink, and extra-file rejection;
- authoritative stopped-only enforcement with no public None bypass;
- history privacy and digest-only snapshot references;
- code-only rollback with nonce/cursor/revoke databases, sidecars, identity,
  and unknown files preserved byte-for-byte at their forward state;
- failure injection at source verification, state snapshot, copy, staged
  verify, bundle publication, selector switch, and post-switch boundaries;
- file and directory fsync, exclusive rename, and current-switch failures;
- rollback switch failure leaving a complete old selector and forward state;
- launcher start selection under the lifecycle lock and fail-closed explicit
  bundle versus current-selector conflict.

Validated commands:

    python3 -m py_compile tools/nomad_web/install_lifecycle.py testkit/nomad-web/test_install_lifecycle.py
    python3 -m unittest discover -s testkit/nomad-web -p 'test_install_lifecycle.py' -v
    python3 -m unittest discover -s testkit/nomad-web -p 'test_m3e_launcher.py' -v
    python3 -m unittest discover -s testkit/nomad-web -p 'test_product_host_bootstrap.py' -v
    python3 -m unittest discover -s testkit/nomad-web -p 'test_clean_home.py' -q

## Launcher integration

P7-B does not change tools/nomad_web/cli.py. Local start, remote start,
restart, and host-identity authorization already hold lifecycle_lock and now
select their bundle through select_bundle_for_start. The first explicit bundle
can initialize current.json while stopped. Thereafter the current selector is
authoritative: an explicit NOMAD_WEB_BUNDLE with a different verified digest
fails closed with EXPLICIT_BUNDLE_CURRENT_CONFLICT before process spawn.
The selected installed directory is returned as a verified canonical path.
This is required on macOS because /var aliases /private/var: Node canonicalizes
import.meta.url while retaining process.argv[1] verbatim, and a lexical alias
would otherwise make the Gateway direct-entry check silently skip startup.
Launcher uninstall recognizes the lifecycle-owned install directory but still
preserves its existing remote revoke-before-uninstall gate.
