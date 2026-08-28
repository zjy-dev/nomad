# Provider E3 harness

This harness is the single Provider E3 entrypoint for the live `remote-local-evidence`
product path. It reuses the exact installed bundle launcher:

`bundle/bin/nomad-web --json start --remote-local-evidence`

Credential input is stdin-only. The harness writes the credential into one private
pipe for the launcher, and the official child path remains the only consumer.
The harness must not place the credential in argv, env vars, files, logs, state,
or evidence.

Usage:

```bash
printf '%s' "$PROVIDER_CREDENTIAL" | \
python3 testkit/provider-e3/run_provider_e3.py \
  --bundle /path/to/bundle \
  --provider OPENAI_API_KEY \
  --credential-stdin \
  --workspace /abs/disposable-workspace \
  --public-origin https://pair.example:18443 \
  --https-listen 192.0.2.10:18443 \
  --tls-cert-fd 11 \
  --tls-key-fd 12 \
  --evidence /tmp/nomad-provider-e3-evidence.json
```

Current boundary:

- P7-D does not invent TLS inputs. Operator `public-origin`, `https-listen`,
  `tls-cert-fd`, and `tls-key-fd` are required until P7-C provides the frozen
  operator flow.
- Missing TLS operator inputs is `BLOCK`.
- Writable actions go only through desktop Gateway `GET /api/commands/capability`
  and `POST /api/commands`.
- If a real question, permission, stop, reconnect trigger, or safe
  `OutcomeUnknown` trigger is not naturally observed, that scenario stays
  `NOT_RUN`.

Evidence is canonical, private, and content-free. The evidence file is created
with exclusive `O_EXCL` semantics and mode `0600`.
