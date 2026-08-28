import { useEffect, useMemo, useRef, useState } from "react";
import type {
  DesktopPairingClient,
  DesktopPairingCreatedJoin,
  DesktopPairingCurrentDevice,
  DesktopPairingJoinStatus,
  DesktopRemoteAccessResetResult,
  DesktopPairingRevokeResult,
  DesktopUninstallResult,
} from "./pairing-api";
import { DesktopPairingClientError } from "./pairing-api";

interface PairingConsoleProps {
  client: DesktopPairingClient;
}

interface ActiveJoinState {
  created: DesktopPairingCreatedJoin;
  status: DesktopPairingJoinStatus | null;
}

export function PairingConsole({ client }: PairingConsoleProps) {
  const [device, setDevice] = useState<DesktopPairingCurrentDevice | null>(
    null,
  );
  const [join, setJoin] = useState<ActiveJoinState | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revokeResult, setRevokeResult] =
    useState<DesktopPairingRevokeResult | null>(null);
  const [resetResult, setResetResult] =
    useState<DesktopRemoteAccessResetResult | null>(null);
  const [uninstallResult, setUninstallResult] =
    useState<DesktopUninstallResult | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);
  const [confirmUninstall, setConfirmUninstall] = useState(false);
  const revokeNowRef = useRef<HTMLButtonElement | null>(null);
  const resetNowRef = useRef<HTMLButtonElement | null>(null);
  const uninstallNowRef = useRef<HTMLButtonElement | null>(null);
  const pairButtonRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    let active = true;
    void Promise.all([client.getCurrentDevice()])
      .then(([currentDevice]) => {
        if (!active) return;
        setDevice(currentDevice);
        setError(null);
        setLoading(false);
      })
      .catch((reason: unknown) => {
        if (!active) return;
        setError(messageFromError(reason));
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [client]);

  useEffect(() => {
    if (!join) return;
    const joinId = join.created.join_id;
    let active = true;
    let timer: number | null = null;

    const schedule = (status: DesktopPairingJoinStatus) => {
      if (!active) return;
      if (isTerminal(status.state)) {
        if (status.state === "active") {
          void client
            .getCurrentDevice()
            .then((currentDevice) => {
              if (active) setDevice(currentDevice);
            })
            .catch(() => {});
        }
        return;
      }
      timer = window.setTimeout(() => {
        void tick();
      }, 1000);
    };

    const tick = async () => {
      try {
        const status = await client.getJoinStatus(joinId);
        if (!active) return;
        setJoin((current) =>
          current && current.created.join_id === status.join_id
            ? { ...current, status }
            : current,
        );
        if (
          status.state === "cancelled" ||
          status.state === "expired" ||
          status.state === "compensated"
        ) {
          setJoin(null);
          setBusy(null);
          window.setTimeout(() => pairButtonRef.current?.focus(), 0);
          return;
        }
        if (status.state === "active") {
          setDevice(await client.getCurrentDevice());
          return;
        }
        schedule(status);
      } catch (reason) {
        if (!active) return;
        setError(messageFromError(reason));
        return;
      }
    };

    void tick();
    return () => {
      active = false;
      if (timer !== null) window.clearTimeout(timer);
    };
  }, [client, join?.created.join_id]);

  const joinUrl = useMemo(() => {
    if (!join) return null;
    return join.created.join_url;
  }, [join]);

  const expiresAt =
    join?.status?.expires_at ?? join?.created.expires_at ?? null;
  const comparisonCode = join?.status?.comparison_code ?? null;
  const statusLabel = join?.status
    ? describeStatus(join.status.state)
    : "Waiting for your phone to open the one-time link.";
  const readyToApprove = Boolean(
    join?.status &&
    join.status.state === "started_awaiting_desktop_approval" &&
    join.status.challenge_id &&
    join.status.expected_epoch &&
    join.status.comparison_code,
  );

  async function handleCreate() {
    setBusy("create");
    setError(null);
    setRevokeResult(null);
    setResetResult(null);
    setUninstallResult(null);
    try {
      const created = await client.createJoin();
      setJoin({ created, status: null });
    } catch (reason) {
      setError(messageFromError(reason));
    } finally {
      setBusy(null);
    }
  }

  async function handleApprove() {
    if (
      !join?.status?.challenge_id ||
      !join.status.expected_epoch ||
      !join.status.comparison_code
    )
      return;
    setBusy("approve");
    setError(null);
    try {
      await client.approveJoin({
        joinId: join.created.join_id,
        challengeId: join.status.challenge_id,
        expectedEpoch: join.status.expected_epoch,
        comparisonCode: join.status.comparison_code,
      });
      const status = await client.getJoinStatus(join.created.join_id);
      setJoin({ created: join.created, status });
    } catch (reason) {
      setError(messageFromError(reason));
    } finally {
      setBusy(null);
    }
  }

  async function handleCancel() {
    if (!join) return;
    setBusy("cancel");
    setError(null);
    try {
      await client.cancelJoin(join.created.join_id);
      const status = await client.getJoinStatus(join.created.join_id);
      if (
        status.state === "cancelled" ||
        status.state === "expired" ||
        status.state === "compensated"
      ) {
        setJoin(null);
        window.setTimeout(() => pairButtonRef.current?.focus(), 0);
      } else {
        setJoin({ created: join.created, status });
      }
    } catch (reason) {
      setError(messageFromError(reason));
    } finally {
      setBusy(null);
    }
  }

  async function handleRevoke() {
    const current = device?.device;
    if (!current) return;
    setBusy("revoke");
    setError(null);
    try {
      const result = await client.revokeDevice({
        deviceAlias: current.device_alias,
        expectedEpoch: current.pairing_epoch,
      });
      setRevokeResult(result);
      setResetResult(null);
      setUninstallResult(null);
      setConfirmRevoke(false);
      setDevice(await client.getCurrentDevice());
    } catch (reason) {
      setError(messageFromError(reason));
    } finally {
      setBusy(null);
    }
  }

  useEffect(() => {
    if (confirmRevoke) {
      revokeNowRef.current?.focus();
    }
  }, [confirmRevoke]);

  useEffect(() => {
    if (confirmReset) {
      resetNowRef.current?.focus();
    }
  }, [confirmReset]);

  useEffect(() => {
    if (confirmUninstall) {
      uninstallNowRef.current?.focus();
    }
  }, [confirmUninstall]);

  async function handleReset() {
    setBusy("reset");
    setError(null);
    try {
      const result = await client.resetRemoteAccess();
      setResetResult(result);
      setRevokeResult(null);
      setUninstallResult(null);
      setJoin(null);
      setConfirmReset(false);
      setConfirmRevoke(false);
      setDevice(await client.getCurrentDevice());
    } catch (reason) {
      setError(messageFromError(reason));
    } finally {
      setBusy(null);
    }
  }

  async function handleUninstall() {
    setBusy("uninstall");
    setError(null);
    try {
      const result = await client.uninstall();
      setUninstallResult(result);
      setRevokeResult(null);
      setResetResult(null);
      setJoin(null);
      setDevice(null);
      setConfirmUninstall(false);
      setConfirmReset(false);
      setConfirmRevoke(false);
    } catch (reason) {
      setError(messageFromError(reason));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section
      className="pairing-console section"
      aria-labelledby="pairing-console-title"
    >
      <div className="section-header">
        <h2 className="section-title" id="pairing-console-title">
          Remote Pairing
        </h2>
        <span>
          {device?.paired
            ? "Phone paired"
            : join
              ? "Waiting to pair phone"
              : "No phone paired yet"}
        </span>
      </div>

      <div className="pairing-console__frame">
        <div className="pairing-console__hero">
          <span className="eyebrow">Single Active Phone</span>
          <h3>{device?.paired ? "Phone paired" : "Waiting to pair phone"}</h3>
          <p>
            {device?.paired
              ? "Phone paired. You can revoke it anytime from this Mac."
              : "Scan or open on your phone. Confirm only if both codes match."}
          </p>
        </div>

        {loading && (
          <div className="command-status" role="status">
            Loading desktop pairing state…
          </div>
        )}
        {error && (
          <div className="perm-block" role="alert" aria-live="assertive">
            <strong>Pairing blocked</strong>
            <div>{error}</div>
          </div>
        )}
        {revokeResult && (
          <div className="command-status" role="status" aria-live="polite">
            Phone access{" "}
            {revokeResult.status === "revoked"
              ? "was removed immediately."
              : "was already revoked earlier."}
          </div>
        )}
        {resetResult && (
          <div className="command-status" role="status" aria-live="polite">
            Remote access state was cleared. Installed bundle and Host identity
            were kept.
          </div>
        )}
        {uninstallResult && (
          <div className="command-status" role="status" aria-live="polite">
            Nomad was uninstalled. Remote access state was removed and Host
            identity was retained on this Mac.
          </div>
        )}

        {join && (
          <div className="pairing-card" data-testid="pairing-join-card">
            <div className="pairing-card__header">
              <span className="pairing-card__title">Pair phone</span>
              {expiresAt && <CountdownBadge expiresAt={expiresAt} />}
            </div>
            <div className="pairing-url-block">
              <label htmlFor="pairing-join-url">Open on your phone</label>
              <textarea
                id="pairing-join-url"
                readOnly
                value={joinUrl ?? ""}
                aria-label="Pairing link"
              />
            </div>
            <div
              className="pairing-code-block"
              aria-live="polite"
              aria-atomic="true"
            >
              <span className="eyebrow">Comparison Code</span>
              <strong>{comparisonCode ?? "••••••"}</strong>
              <small>
                {comparisonCode
                  ? "Confirm only if this matches your phone."
                  : "Waiting for your phone to open the one-time link."}
              </small>
            </div>
            <div className="pairing-status-line">{statusLabel}</div>
            <div className="hero-actions">
              <button
                className="btn btn--ghost"
                onClick={handleCancel}
                disabled={
                  busy !== null || isTerminal(join.status?.state ?? "created")
                }
              >
                Cancel
              </button>
              {readyToApprove && (
                <button
                  className="btn btn--primary"
                  onClick={handleApprove}
                  disabled={busy !== null}
                >
                  Codes match
                </button>
              )}
            </div>
          </div>
        )}

        {!join && !device?.paired && !loading && (
          <div className="pairing-card">
            <div className="pairing-card__header">
              <span className="pairing-card__title">No phone paired yet</span>
            </div>
            <p className="pairing-copy">
              Create a one-time pairing link and confirm the same 6-digit code
              on both screens.
            </p>
            <div className="hero-actions">
              <button
                ref={pairButtonRef}
                className="btn btn--primary"
                onClick={handleCreate}
                disabled={busy !== null}
              >
                Pair phone
              </button>
            </div>
          </div>
        )}

        {device?.paired && device.device && (
          <div className="pairing-card" data-testid="paired-device-card">
            <div className="pairing-card__header">
              <span className="pairing-card__title">Active phone</span>
              <span className="chip">{device.device.device_alias}</span>
            </div>
            <dl className="pairing-facts">
              <div>
                <dt>Device Alias</dt>
                <dd>{device.device.device_alias}</dd>
              </div>
              <div>
                <dt>Epoch</dt>
                <dd>{device.device.pairing_epoch}</dd>
              </div>
            </dl>
            {!confirmRevoke ? (
              <div className="hero-actions">
                <button
                  className="btn btn--danger-secondary"
                  onClick={() => setConfirmRevoke(true)}
                  disabled={busy !== null}
                >
                  Revoke phone
                </button>
              </div>
            ) : (
              <div
                className="pairing-inline-warning"
                role="dialog"
                aria-modal="false"
                aria-labelledby="pairing-revoke-title"
              >
                <p id="pairing-revoke-title" className="sr-only">
                  Confirm revoke phone
                </p>
                <p>
                  This removes this phone&apos;s access immediately. You can
                  pair again later.
                </p>
                <div className="hero-actions">
                  <button
                    className="btn btn--ghost"
                    onClick={() => setConfirmRevoke(false)}
                    disabled={busy !== null}
                  >
                    Keep access
                  </button>
                  <button
                    ref={revokeNowRef}
                    className="btn btn--danger"
                    onClick={handleRevoke}
                    disabled={busy !== null}
                  >
                    Revoke now
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        <div className="pairing-card" data-testid="remote-access-safety-card">
          <div className="pairing-card__header">
            <span className="pairing-card__title">Remote Access Safety</span>
            <span className="chip">Host identity retained</span>
          </div>
          <p className="pairing-copy">
            Use reset when browser state is lost or replaced. Use uninstall only
            when removing the local install. Neither action rotates Host
            identity here.
          </p>
          {!confirmReset ? (
            <div className="hero-actions">
              <button
                className="btn btn--ghost"
                onClick={() => {
                  setConfirmUninstall(false);
                  setConfirmReset(true);
                }}
                disabled={busy !== null}
              >
                Reset remote access
              </button>
            </div>
          ) : (
            <div
              className="pairing-inline-warning"
              role="dialog"
              aria-modal="false"
              aria-labelledby="pairing-reset-title"
            >
              <p id="pairing-reset-title" className="sr-only">
                Confirm reset remote access
              </p>
              <p>
                This stops Nomad first, clears paired-device and remote mailbox
                state, and keeps the installed bundle plus Host identity.
              </p>
              <div className="hero-actions">
                <button
                  className="btn btn--ghost"
                  onClick={() => setConfirmReset(false)}
                  disabled={busy !== null}
                >
                  Keep remote access
                </button>
                <button
                  ref={resetNowRef}
                  className="btn btn--danger-secondary"
                  onClick={handleReset}
                  disabled={busy !== null}
                >
                  Reset now
                </button>
              </div>
            </div>
          )}
          {!confirmUninstall ? (
            <div className="hero-actions">
              <button
                className="btn btn--danger-secondary"
                onClick={() => {
                  setConfirmReset(false);
                  setConfirmUninstall(true);
                }}
                disabled={busy !== null}
              >
                Uninstall Nomad
              </button>
            </div>
          ) : (
            <div
              className="pairing-inline-warning pairing-inline-warning--danger"
              role="dialog"
              aria-modal="false"
              aria-labelledby="pairing-uninstall-title"
            >
              <p id="pairing-uninstall-title" className="sr-only">
                Confirm uninstall Nomad
              </p>
              <p>
                This removes owned runtime and install state. Host identity is
                retained and may still require separate manual removal outside
                this screen.
              </p>
              <div className="hero-actions">
                <button
                  className="btn btn--ghost"
                  onClick={() => setConfirmUninstall(false)}
                  disabled={busy !== null}
                >
                  Keep installed
                </button>
                <button
                  ref={uninstallNowRef}
                  className="btn btn--danger"
                  onClick={handleUninstall}
                  disabled={busy !== null}
                >
                  Uninstall now
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function CountdownBadge({ expiresAt }: { expiresAt: string }) {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const seconds = Math.max(0, Math.ceil((Date.parse(expiresAt) - now) / 1000));
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return (
    <span
      className={`countdown-badge ${seconds === 0 ? "countdown-badge--expired" : ""}`}
    >
      {seconds === 0
        ? "Expired"
        : `${minutes}:${remainder.toString().padStart(2, "0")}`}
    </span>
  );
}

function isTerminal(state: DesktopPairingJoinStatus["state"]): boolean {
  return ["active", "cancelled", "expired", "compensated", "revoked"].includes(
    state,
  );
}

function describeStatus(state: DesktopPairingJoinStatus["state"]): string {
  switch (state) {
    case "created":
      return "Waiting for your phone to open the one-time link.";
    case "started_awaiting_desktop_approval":
      return "Only continue if the same six digits are visible on your phone.";
    case "desktop_approved":
      return "Desktop approved. Waiting for phone confirmation.";
    case "provisioned_pending_vault":
      return "Phone is writing secure browser state before activation.";
    case "active":
      return "Pairing completed and this phone is now active.";
    case "cancelled":
      return "Pairing was cancelled. Start again from this Mac.";
    case "expired":
      return "Pairing expired. Start pairing again from this Mac.";
    case "compensated":
      return "Pairing failed after activation and was rolled back safely.";
    case "revoked":
      return "This phone was revoked and can no longer access this Mac.";
  }
}

function messageFromError(reason: unknown): string {
  if (reason instanceof DesktopPairingClientError) {
    if (reason.code === "PAIRING_CSRF_UNAVAILABLE") return reason.message;
    if (reason.code === "PAIRING_HTTP_ERROR")
      return "Desktop pairing request was not accepted by the local Gateway.";
    if (reason.code === "PAIRING_INVALID_RESPONSE")
      return "Desktop pairing response is incompatible.";
    if (reason.code === "REMOTE_UNINSTALL_REVOKE_REQUIRED")
      return "Uninstall is blocked until remote access state is cleared first.";
  }
  return reason instanceof Error
    ? reason.message
    : "Desktop pairing is unavailable.";
}
