# Stock OpenCode contract evidence

`capture_contract.py` is the only official mode. It fetches exact npm registry
metadata for `opencode-ai@1.18.16`, validates `npm pack` against registry SRI
and SHA-1, and separately validates the committed exact runtime lock. Every
non-root lock entry must match the official registry's exact version, tarball
URL, and SRI. The tool copies only the committed `package.json` and
`package-lock.json` into a fresh temporary directory, runs the following exact
install, and starts that npm-ci binary itself on a random loopback port:

```sh
npm ci --registry=https://registry.npmjs.org \
  --ignore-scripts=false --no-audit --no-fund
```

It then captures only
the health version, routes, SSE envelope shape, and snapshot schema shape.

There is intentionally no external `--base-url` or `--opencode-binary` option:
those cannot establish a binding between an arbitrary server and official npm
bits. npm/network failure prints a content-free `BLOCKED` JSON result and exits
non-zero; it never falls back to official evidence.

`locked-runtime/package.json` and `locked-runtime/package-lock.json` are public
supply-chain inputs: they contain only public npm package names, versions,
registry URLs, and integrity values. The runtime is always copied to a fresh
directory and installed with `npm ci`; dynamic `npm install <tarball>` is never
used for the selected installed packages.

Provenance records exact hashes for both committed inputs, the independently
packed registry tarball, all dependencies in the committed lock, and the
platform-selected dependencies actually installed. Closure digests are
canonical hashes of package name, exact version, and SRI, so temporary paths
never enter the evidence. Verification is deliberately platform-exact: OS,
architecture, and the complete npm version must match the fixture or it returns
a stable content-free `BLOCKED_ENVIRONMENT_COMPATIBILITY_MISMATCH`. A compatible
verification recalculates the manifest from the fixture and local committed
assets, then repeats the same locked `npm ci` capture and compares every field.

The execution provenance scope is explicitly limited to registry archives, the
exact committed lock, a fresh `npm ci`, platform-selected installed packages,
and the observed entrypoint that this capture spawns. The `.bin/opencode` path
must resolve inside that fresh runtime's `node_modules`; both the wrapper and
resolved target bytes are hashed as observations of the installed entrypoint.
These hashes do not claim that installed bytes equal registry archive bytes.
M1 does not attest all final executable or child-process code created or chosen
by install/postinstall behavior (`postinstall_final_code_attested` is false).

```sh
python3 testkit/stock-opencode/capture_contract.py \
  --output testkit/stock-opencode/official-stock-contract.json \
  --manifest testkit/stock-opencode/capture-manifest.json
```

The generated output is safe to inspect and can be committed only if it remains
shape-only. Identifier values are never retained; schema field names may be
retained only when they are not content-bearing. `evidence-classification.json` is the machine-readable boundary:
this no-credential capture proves stock contract facts, not question, permission,
diff, Stop, reconnect, or task outcome evidence. Those require a separate
Provider-backed disposable task and must still retain no user content.

Offline test command:

```sh
python3 -m unittest testkit/stock-opencode/test_capture_contract.py
```

Verify both the manifest and a fresh registry-bound capture:

```sh
python3 testkit/stock-opencode/capture_contract.py \
  --verify-fixture testkit/stock-opencode/official-stock-contract.json \
  --manifest testkit/stock-opencode/capture-manifest.json
```
