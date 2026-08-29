import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  BrowserVaultError,
  type BrowserVaultSession,
} from "../remote/browser-vault";
import type { PairingJoinStartResult } from "../remote/pairing-client";
import {
  RemoteSessionError,
  type RemoteSessionPort as RuntimeRemoteSessionPort,
} from "../remote/paired-session";
import { PairingConsole } from "./PairingConsole";
import {
  PhonePairingScreen,
  type PhonePairingClientPort,
  type PhoneVaultPort,
} from "./PhonePairingScreen";
import type { SessionView } from "../client/types";
import type {
  DesktopPairingClient,
  DesktopPairingCurrentDevice,
  DesktopPairingCreatedJoin,
  DesktopPairingJoinStatus,
  DesktopLifecycleStatus,
  DesktopRemoteAccessResetResult,
  DesktopPairingRevokeResult,
  DesktopUninstallResult,
} from "./pairing-api";
import { createDesktopPairingClient, DesktopPairingClientError } from "./pairing-api";

let root: Root | null = null;
let container: HTMLDivElement | null = null;

beforeAll(() => {
  (
    globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }
  ).IS_REACT_ACT_ENVIRONMENT = true;
  window.history.replaceState(null, "", "/");
});

afterEach(() => {
  if (root) act(() => root?.unmount());
  root = null;
  container?.remove();
  container = null;
  window.history.replaceState(null, "", "/");
});

async function render(node: JSX.Element) {
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => {
    root?.render(node);
  });
  return container;
}

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, resolve, reject };
}

function button(name: string): HTMLButtonElement {
  const match = [...(container?.querySelectorAll("button") ?? [])].find(
    (item) => item.textContent?.trim().includes(name),
  );
  if (!(match instanceof HTMLButtonElement))
    throw new Error(`Button not found: ${name}`);
  return match;
}

describe("PairingConsole", () => {
  it("creates a one-time join, shows the link, polls status, and exposes desktop approval", async () => {
    const join = createdJoin();
    const initialDevice = deferred<DesktopPairingCurrentDevice>();
    const pendingStatus = deferred<DesktopPairingJoinStatus>();
    const client: DesktopPairingClient = {
      getCurrentDevice: vi
        .fn()
        .mockImplementationOnce(() => initialDevice.promise)
        .mockImplementationOnce(async () => currentDevice(true)),
      createJoin: vi.fn(async () => join),
      getJoinStatus: vi
        .fn()
        .mockImplementationOnce(() => pendingStatus.promise)
        .mockImplementationOnce(async () =>
          joinStatus(join.join_id, "started_awaiting_desktop_approval"),
        ),
      approveJoin: vi.fn(async () => {}),
      cancelJoin: vi.fn(async () => {}),
      revokeDevice: vi.fn(async () => {
        throw new Error("unused");
      }) as DesktopPairingClient["revokeDevice"],
      resetRemoteAccess: vi.fn(async () => {
        throw new Error("unused");
      }) as DesktopPairingClient["resetRemoteAccess"],
      uninstall: vi.fn(async () => {
        throw new Error("unused");
      }) as DesktopPairingClient["uninstall"],
    };

    const output = await render(<PairingConsole client={client} />);
    expect(output.textContent).toContain("Loading desktop pairing state…");
    await act(async () => {
      initialDevice.resolve(currentDevice(false));
      await initialDevice.promise;
    });

    await act(async () => button("Pair phone").click());
    expect(client.getJoinStatus).toHaveBeenCalledWith(join.join_id);
    await act(async () => {
      pendingStatus.resolve(
        joinStatus(join.join_id, "started_awaiting_desktop_approval"),
      );
      await pendingStatus.promise;
    });

    expect(output.textContent).toContain(
      "Scan or open on your phone. Confirm only if both codes match.",
    );
    expect(output.textContent).toContain("042913");
    expect(
      (
        output.querySelector(
          'textarea[aria-label="Pairing link"]',
        ) as HTMLTextAreaElement
      ).value,
    ).toBe(join.join_url);
    expect(button("Codes match")).toBeInstanceOf(HTMLButtonElement);

    await act(async () => button("Codes match").click());
    expect(client.approveJoin).toHaveBeenCalledWith({
      joinId: join.join_id,
      challengeId: "challenge-0000000000000001",
      expectedEpoch: 1,
      comparisonCode: "042913",
    });
  });

  it("shows the active paired phone and requires explicit revoke confirmation", async () => {
    const initialDevice = deferred<DesktopPairingCurrentDevice>();
    const client: DesktopPairingClient = {
      getCurrentDevice: vi
        .fn()
        .mockImplementationOnce(() => initialDevice.promise)
        .mockImplementationOnce(async () => currentDevice(false)),
      createJoin: vi.fn(async () => {
        throw new Error("unused");
      }),
      getJoinStatus: vi.fn(async () => {
        throw new Error("unused");
      }),
      approveJoin: vi.fn(async () => {}),
      cancelJoin: vi.fn(async () => {}),
      revokeDevice: vi.fn(async (): Promise<DesktopPairingRevokeResult> => ({
        schema: "nomad.product-host.device-revoke.v1",
        principal_alias: "remote-paired-device",
        device_alias: "device-alpha-01",
        status: "revoked" as const,
        prior_epoch: 7,
        revoked_epoch: 8,
      })),
      resetRemoteAccess: vi.fn(async () => {
        throw new Error("unused");
      }) as DesktopPairingClient["resetRemoteAccess"],
      uninstall: vi.fn(async () => {
        throw new Error("unused");
      }) as DesktopPairingClient["uninstall"],
    };

    const output = await render(<PairingConsole client={client} />);
    await act(async () => {
      initialDevice.resolve(currentDevice(true));
      await initialDevice.promise;
    });

    expect(output.textContent).toContain("device-alpha-01");

    await act(async () => button("Revoke phone").click());
    expect(output.textContent).toContain(
      "This removes this phone's access immediately. You can pair again later.",
    );
    await act(async () => button("Revoke now").click());

    expect(client.revokeDevice).toHaveBeenCalledWith({
      deviceAlias: "device-alpha-01",
      expectedEpoch: 7,
    });
    expect(output.textContent).toContain(
      "Phone access was removed immediately.",
    );
  });

  it("supports stop-only remote-access reset and explicit uninstall copy", async () => {
    const initialDevice = deferred<DesktopPairingCurrentDevice>();
    const client: DesktopPairingClient = {
      getCurrentDevice: vi
        .fn()
        .mockImplementationOnce(() => initialDevice.promise)
        .mockImplementationOnce(async () => currentDevice(false))
        .mockImplementationOnce(async () => currentDevice(false)),
      createJoin: vi.fn(async () => {
        throw new Error("unused");
      }),
      getJoinStatus: vi.fn(async () => {
        throw new Error("unused");
      }),
      approveJoin: vi.fn(async () => {}),
      cancelJoin: vi.fn(async () => {}),
      revokeDevice: vi.fn(async () => {
        throw new Error("unused");
      }) as DesktopPairingClient["revokeDevice"],
      resetRemoteAccess: vi.fn(
        async (): Promise<DesktopRemoteAccessResetResult> => ({
          schema: "nomad.desktop.lifecycle-accepted.v1",
          state: "accepted",
          operation_id: "reset_0123456789abcdef",
        }),
      ),
      uninstall: vi.fn(async (): Promise<DesktopUninstallResult> => ({
        schema: "nomad.desktop.lifecycle-accepted.v1",
        state: "accepted",
        operation_id: "uninstall_0123456789abcdef",
      })),
      getLifecycleStatus: vi.fn(async (): Promise<DesktopLifecycleStatus> => ({
        schema: "nomad.desktop.lifecycle-status.v1",
        operation_id: "reset_0123456789abcdef",
        operation: "reset_remote_access", state: "closing", terminal: false,
        error: null, recovery: null,
      })),
    };

    const output = await render(<PairingConsole client={client} />);
    await act(async () => {
      initialDevice.resolve(currentDevice(true));
      await initialDevice.promise;
    });

    await act(async () => button("Reset remote access").click());
    expect(output.textContent).toContain(
      "clears paired-device and remote mailbox state",
    );
    await act(async () => button("Reset now").click());
    expect(client.resetRemoteAccess).toHaveBeenCalledTimes(1);
    expect(output.textContent).toContain(
      "installed bundle and Host identity are retained.",
    );
    expect(button("Reset remote access").disabled).toBe(true);
    expect(button("Uninstall Nomad").disabled).toBe(true);

    expect(client.uninstall).not.toHaveBeenCalled();
  });

  it("treats lifecycle network loss as unknown and locks destructive controls", async () => {
    const client: DesktopPairingClient = {
      getCurrentDevice: vi.fn(async () => currentDevice(false)),
      createJoin: vi.fn(async () => { throw new Error("unused"); }),
      getJoinStatus: vi.fn(async () => { throw new Error("unused"); }),
      approveJoin: vi.fn(async () => {}), cancelJoin: vi.fn(async () => {}),
      revokeDevice: vi.fn(async () => { throw new Error("unused"); }),
      resetRemoteAccess: vi.fn(async () => {
        throw new DesktopPairingClientError(
          "PAIRING_NETWORK_ERROR", "lost", "operation_0123456789",
        );
      }),
      uninstall: vi.fn(async () => { throw new Error("unused"); }),
    };
    const output = await render(<PairingConsole client={client} />); await flush();
    await act(async () => button("Reset remote access").click());
    await act(async () => button("Reset now").click());
    expect(output.textContent).toContain("Operation outcome unknown. Do not retry.");
    expect(output.textContent).toContain(
      "nomad-web operation-status --operation-id operation_0123456789",
    );
    expect(button("Reset now").disabled).toBe(true);
    expect(button("Uninstall Nomad").disabled).toBe(true);
  });
});

describe("PhonePairingScreen", () => {
  it("starts from the join route, verifies the remote session, and mounts the real shell", async () => {
    window.history.replaceState(
      null,
      "",
      "/j/join-1234567890abcdef1234567890abcdef",
    );
    const pendingStart = deferred<PairingJoinStartResult>();
    const runtime = remoteRuntimePort(remoteView());
    const pairingClient: PhonePairingClientPort = {
      startFromCurrentLocation: vi.fn(() => pendingStart.promise),
      confirm: vi.fn(async () => ({
        comparisonCode: "042913",
        session: browserSession(),
      })),
      cancelPending: vi.fn(),
      abortPending: vi.fn(async () => {}),
    };
    const vault: PhoneVaultPort = {
      restorePairedDevice: vi.fn(async () => {
        throw new BrowserVaultError("BROWSER_VAULT_EMPTY", "empty");
      }),
    };

    const output = await render(
      <PhonePairingScreen
        pairingClient={pairingClient}
        vault={vault}
        remoteSessionFactory={vi.fn(async () => runtime)}
      />,
    );
    await flush();
    expect(pairingClient.startFromCurrentLocation).toHaveBeenCalledTimes(1);
    await act(async () => {
      pendingStart.resolve(startResult());
      await pendingStart.promise;
    });

    expect(output.textContent).toContain(
      "Only confirm if this code matches your Mac",
    );
    expect(output.textContent).toContain("042913");

    await act(async () => button("Confirm").click());

    expect(pairingClient.confirm).toHaveBeenCalledTimes(1);
    expect(vi.mocked(runtime.poll)).toHaveBeenCalled();
    expect(output.textContent).toContain("Remote session connected");
    expect(output.textContent).toContain("Review request");
    expect(output.textContent).toContain("Activity");
    expect(output.textContent).not.toContain("Secure session not connected");
  });

  it("shows connecting while restore succeeds but remote verification is still pending", async () => {
    const attach = deferred<RuntimeRemoteSessionPort>();
    const pairingClient: PhonePairingClientPort = {
      startFromCurrentLocation: vi.fn(async () => startResult()),
      confirm: vi.fn(async () => ({
        comparisonCode: "042913",
        session: browserSession(),
      })),
      cancelPending: vi.fn(),
      abortPending: vi.fn(async () => {}),
    };
    const vault: PhoneVaultPort = {
      restorePairedDevice: vi.fn(async () => browserSession()),
    };

    const output = await render(
      <PhonePairingScreen
        pairingClient={pairingClient}
        vault={vault}
        remoteSessionFactory={vi.fn(() => attach.promise)}
      />,
    );
    await flush();
    expect(output.textContent).toContain("Connecting secure session");
    expect(output.textContent).toContain("Checking the secure remote session…");
  });

  it("shows the not-connected fallback when remote verification cannot prove a live projection", async () => {
    vi.useFakeTimers();
    try {
      const pairingClient: PhonePairingClientPort = {
        startFromCurrentLocation: vi.fn(async () => startResult()),
        confirm: vi.fn(async () => ({
          comparisonCode: "042913",
          session: browserSession(),
        })),
        cancelPending: vi.fn(),
        abortPending: vi.fn(async () => {}),
      };
      const vault: PhoneVaultPort = {
        restorePairedDevice: vi.fn(async () => browserSession()),
      };
      const runtime = remoteRuntimePort(null);

      const output = await render(
        <PhonePairingScreen
          pairingClient={pairingClient}
          vault={vault}
          remoteSessionFactory={vi.fn(async () => runtime)}
        />,
      );
      await act(async () => {
        await vi.runAllTimersAsync();
      });
      expect(output.textContent).not.toContain("Paired to your Mac");
      expect(output.textContent).toContain("Secure session not connected");
      expect(output.textContent).toContain("Retry connect");
      expect(output.textContent).not.toContain("Remote session connected");
    } finally {
      vi.useRealTimers();
    }
  });

  it("retries the same pending remote request on restore without creating a new semantic command", async () => {
    const retrySnapshot = remoteRuntimeSnapshot(remoteView(), {
      pending_command: {
        request_id: "req-01010101010101010101010101010101",
        action: "reply",
        command_seq: 19,
        snapshot_seq: 8,
        snapshot_digest: `sha256:${"a".repeat(64)}`,
        status: "published",
      },
    });
    const liveSnapshot = remoteRuntimeSnapshot(remoteView(), {
      pending_command: null,
    });
    let currentSnapshot = retrySnapshot;
    const retryPending = vi.fn(async () => {
      currentSnapshot = liveSnapshot;
      return liveSnapshot;
    });
    const runtime: RuntimeRemoteSessionPort = {
      getSnapshot: vi.fn(() => currentSnapshot),
      subscribe: vi.fn(() => () => {}),
      poll: vi.fn(async () => currentSnapshot),
      dispatch: vi.fn(async () => liveSnapshot),
      retryPending,
    };
    const pairingClient: PhonePairingClientPort = {
      startFromCurrentLocation: vi.fn(async () => startResult()),
      confirm: vi.fn(async () => ({
        comparisonCode: "042913",
        session: browserSession(),
      })),
      cancelPending: vi.fn(),
      abortPending: vi.fn(async () => {}),
    };
    const vault: PhoneVaultPort = {
      restorePairedDevice: vi.fn(async () => browserSession()),
    };

    const output = await render(
      <PhonePairingScreen
        pairingClient={pairingClient}
        vault={vault}
        remoteSessionFactory={vi.fn(async () => runtime)}
      />,
    );
    await flush();

    expect(retryPending).toHaveBeenCalledTimes(1);
    expect(runtime.dispatch).not.toHaveBeenCalled();
    expect(output.textContent).toContain("Remote session connected");
    expect(output.textContent).toContain("Review request");
  });

  it("shows revoked when remote verification fails closed with device revocation", async () => {
    const pairingClient: PhonePairingClientPort = {
      startFromCurrentLocation: vi.fn(async () => startResult()),
      confirm: vi.fn(async () => ({
        comparisonCode: "042913",
        session: browserSession(),
      })),
      cancelPending: vi.fn(),
      abortPending: vi.fn(async () => {}),
    };
    const vault: PhoneVaultPort = {
      restorePairedDevice: vi.fn(async () => browserSession()),
    };

    const output = await render(
      <PhonePairingScreen
        pairingClient={pairingClient}
        vault={vault}
        remoteSessionFactory={vi.fn(async () => {
          throw new RemoteSessionError("DEVICE_REVOKED", "revoked");
        })}
      />,
    );
    await flush();
    expect(output.textContent).toContain("Phone access removed");
    expect(output.textContent).toContain(
      "Pair again from your Mac to continue.",
    );
  });

  it("shows replaced-device recovery copy when remote verification reports replacement", async () => {
    const pairingClient: PhonePairingClientPort = {
      startFromCurrentLocation: vi.fn(async () => startResult()),
      confirm: vi.fn(async () => ({
        comparisonCode: "042913",
        session: browserSession(),
      })),
      cancelPending: vi.fn(),
      abortPending: vi.fn(async () => {}),
    };
    const vault: PhoneVaultPort = {
      restorePairedDevice: vi.fn(async () => browserSession()),
    };

    const output = await render(
      <PhonePairingScreen
        pairingClient={pairingClient}
        vault={vault}
        remoteSessionFactory={vi.fn(async () => {
          throw new RemoteSessionError("PAIRING_REPLACED", "replaced");
        })}
      />,
    );
    await flush();
    expect(output.textContent).toContain(
      "Another browser or device replaced this pairing.",
    );
  });

  it("shows cancelled recovery copy when remote verification reports cancellation", async () => {
    const pairingClient: PhonePairingClientPort = {
      startFromCurrentLocation: vi.fn(async () => startResult()),
      confirm: vi.fn(async () => ({
        comparisonCode: "042913",
        session: browserSession(),
      })),
      cancelPending: vi.fn(),
      abortPending: vi.fn(async () => {}),
    };
    const vault: PhoneVaultPort = {
      restorePairedDevice: vi.fn(async () => browserSession()),
    };

    const output = await render(
      <PhonePairingScreen
        pairingClient={pairingClient}
        vault={vault}
        remoteSessionFactory={vi.fn(async () => {
          throw new RemoteSessionError("PAIRING_CANCELLED", "cancelled");
        })}
      />,
    );
    await flush();
    expect(output.textContent).toContain("Pairing was cancelled on your Mac.");
  });

  it("shows the lost-key re-pair copy when vault restore fails closed", async () => {
    const pairingClient: PhonePairingClientPort = {
      startFromCurrentLocation: vi.fn(async () => startResult()),
      confirm: vi.fn(async () => ({
        comparisonCode: "042913",
        session: browserSession(),
      })),
      cancelPending: vi.fn(),
      abortPending: vi.fn(async () => {}),
    };
    const vault: PhoneVaultPort = {
      restorePairedDevice: vi.fn(async () => {
        throw new BrowserVaultError("BROWSER_VAULT_KEY_LOST", "lost");
      }),
    };

    const output = await render(
      <PhonePairingScreen pairingClient={pairingClient} vault={vault} />,
    );
    await flush();
    expect(output.textContent).toContain(
      "This browser lost its secure device keys. Pair again from your Mac to continue.",
    );
  });

  it("shows the lost-key re-pair copy when remote verification reports key loss", async () => {
    const pairingClient: PhonePairingClientPort = {
      startFromCurrentLocation: vi.fn(async () => startResult()),
      confirm: vi.fn(async () => ({
        comparisonCode: "042913",
        session: browserSession(),
      })),
      cancelPending: vi.fn(),
      abortPending: vi.fn(async () => {}),
    };
    const vault: PhoneVaultPort = {
      restorePairedDevice: vi.fn(async () => browserSession()),
    };

    const output = await render(
      <PhonePairingScreen
        pairingClient={pairingClient}
        vault={vault}
        remoteSessionFactory={vi.fn(async () => {
          throw new RemoteSessionError("KEY_LOST", "lost");
        })}
      />,
    );
    await flush();
    expect(output.textContent).toContain(
      "This browser lost its secure device keys. Pair again from your Mac to continue.",
    );
  });
});

describe("createDesktopPairingClient", () => {
  it("bootstraps desktop CSRF from the frozen Gateway route and never calls /internal/", async () => {
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    const fetchImpl: typeof fetch = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        requests.push({ url, init });

        if (url.endsWith("/api/desktop/security")) {
          return jsonResponse({
            schema: "nomad.gateway.desktop-security.v1",
            csrf_token: "csrf_token_00000001",
          });
        }
        if (url.endsWith("/api/desktop/devices/current")) {
          return jsonResponse(currentDevice(false));
        }
        if (url.endsWith("/api/desktop/pairing/create")) {
          return jsonResponse(createdJoin());
        }
        if (url.endsWith("/api/desktop/pairing/status")) {
          return jsonResponse(
            joinStatus(
              "join-1234567890abcdef1234567890abcdef",
              "started_awaiting_desktop_approval",
            ),
          );
        }
        if (url.endsWith("/api/desktop/pairing/approve")) {
          return emptyJsonResponse();
        }
        if (url.endsWith("/api/desktop/pairing/cancel")) {
          return emptyJsonResponse();
        }
        if (url.endsWith("/api/desktop/devices/revoke")) {
          return jsonResponse({
            schema: "nomad.product-host.device-revoke.v1",
            principal_alias: "remote-paired-device",
            device_alias: "device-alpha-01",
            status: "revoked",
            prior_epoch: 7,
            revoked_epoch: 8,
          } satisfies DesktopPairingRevokeResult);
        }

        throw new Error(`Unexpected request: ${url}`);
      },
    ) as typeof fetch;

    const client = createDesktopPairingClient({
      baseUrl: "https://nomad.local",
      fetchImpl,
    });

    await client.getCurrentDevice();
    await client.createJoin();
    await client.getJoinStatus("join-1234567890abcdef1234567890abcdef");
    await client.approveJoin({
      joinId: "join-1234567890abcdef1234567890abcdef",
      challengeId: "challenge-0000000000000001",
      expectedEpoch: 1,
      comparisonCode: "042913",
    });
    await client.cancelJoin("join-1234567890abcdef1234567890abcdef");
    await client.revokeDevice({
      deviceAlias: "device-alpha-01",
      expectedEpoch: 7,
    });

    expect(requests.map((request) => request.url)).toEqual([
      "https://nomad.local/api/desktop/security",
      "https://nomad.local/api/desktop/devices/current",
      "https://nomad.local/api/desktop/pairing/create",
      "https://nomad.local/api/desktop/pairing/status",
      "https://nomad.local/api/desktop/pairing/approve",
      "https://nomad.local/api/desktop/pairing/cancel",
      "https://nomad.local/api/desktop/devices/revoke",
    ]);
    expect(
      requests.every((request) => !request.url.includes("/internal/")),
    ).toBe(true);
    expect(requests[0]?.init?.method).toBe("GET");
    expect(
      (requests[1]?.init?.headers as Record<string, string>)["X-Nomad-CSRF"],
    ).toBe("csrf_token_00000001");
    expect(requests[1]?.init?.method).toBe("POST");
    expect(requests[1]?.init?.body).toBe("{}");
  });

  it("rejects widened create responses that still expose join_secret", async () => {
    const fetchImpl: typeof fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/desktop/security")) {
        return jsonResponse({
          schema: "nomad.gateway.desktop-security.v1",
          csrf_token: "csrf_token_00000001",
        });
      }
      return jsonResponse({
        ...createdJoin(),
        join_secret: "pair_secret_token_0000000000000000",
      });
    }) as typeof fetch;

    const client = createDesktopPairingClient({
      baseUrl: "https://nomad.local",
      fetchImpl,
    });

    await expect(client.createJoin()).rejects.toMatchObject({
      code: "PAIRING_INVALID_RESPONSE",
    });
  });

  it("surfaces bootstrap failure as CSRF unavailable and does not attempt desktop POSTs", async () => {
    const fetchImpl: typeof fetch = vi.fn(
      async () =>
        new Response("unavailable", {
          status: 503,
          headers: {
            "content-type": "text/plain",
          },
        }),
    ) as typeof fetch;

    const client = createDesktopPairingClient({
      baseUrl: "https://nomad.local",
      fetchImpl,
    });

    await expect(client.getCurrentDevice()).rejects.toMatchObject({
      code: "PAIRING_CSRF_UNAVAILABLE",
    });
    expect(vi.mocked(fetchImpl)).toHaveBeenCalledTimes(1);
    expect(String(vi.mocked(fetchImpl).mock.calls[0]?.[0])).toBe(
      "https://nomad.local/api/desktop/security",
    );
  });

  it("refreshes desktop security once when the server rejects a stale CSRF token", async () => {
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    let securityCalls = 0;
    const fetchImpl: typeof fetch = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        requests.push({ url, init });

        if (url.endsWith("/api/desktop/security")) {
          securityCalls += 1;
          return jsonResponse({
            schema: "nomad.gateway.desktop-security.v1",
            csrf_token:
              securityCalls === 1
                ? "csrf_token_00000001"
                : "csrf_token_00000002",
          });
        }
        if (url.endsWith("/api/desktop/devices/current")) {
          const csrf = (init?.headers as Record<string, string>)[
            "X-Nomad-CSRF"
          ];
          if (csrf === "csrf_token_00000001") {
            return new Response(JSON.stringify({ error: "CSRF_REJECTED" }), {
              status: 401,
              headers: { "content-type": "application/json" },
            });
          }
          return jsonResponse(currentDevice(false));
        }
        throw new Error(`Unexpected request: ${url}`);
      },
    ) as typeof fetch;

    const client = createDesktopPairingClient({
      baseUrl: "https://nomad.local",
      fetchImpl,
    });

    await expect(client.getCurrentDevice()).resolves.toEqual(
      currentDevice(false),
    );
    expect(requests.map((request) => request.url)).toEqual([
      "https://nomad.local/api/desktop/security",
      "https://nomad.local/api/desktop/devices/current",
      "https://nomad.local/api/desktop/security",
      "https://nomad.local/api/desktop/devices/current",
    ]);
    expect(
      (requests[1]?.init?.headers as Record<string, string>)["X-Nomad-CSRF"],
    ).toBe("csrf_token_00000001");
    expect(
      (requests[3]?.init?.headers as Record<string, string>)["X-Nomad-CSRF"],
    ).toBe("csrf_token_00000002");
  });

  it("calls desktop reset and uninstall through the public desktop routes only", async () => {
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    const fetchImpl: typeof fetch = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        requests.push({ url, init });
        if (url.endsWith("/api/desktop/security")) {
          return jsonResponse({
            schema: "nomad.gateway.desktop-security.v1",
            csrf_token: "csrf_token_00000001",
          });
        }
        if (url.endsWith("/api/desktop/remote-access/reset")) {
          const requestId = JSON.parse(String(init?.body)).request_id;
          return jsonResponse({
            schema: "nomad.desktop.lifecycle-accepted.v1",
            state: "accepted",
            operation_id: requestId,
          } satisfies DesktopRemoteAccessResetResult);
        }
        if (url.endsWith("/api/desktop/install/uninstall")) {
          const requestId = JSON.parse(String(init?.body)).request_id;
          return jsonResponse({
            schema: "nomad.desktop.lifecycle-accepted.v1",
            state: "accepted",
            operation_id: requestId,
          } satisfies DesktopUninstallResult);
        }
        throw new Error(`Unexpected request: ${url}`);
      },
    ) as typeof fetch;

    const client = createDesktopPairingClient({
      baseUrl: "https://nomad.local",
      fetchImpl,
    });

    await client.resetRemoteAccess();
    await client.uninstall();
    expect(requests.map((request) => request.url)).toEqual([
      "https://nomad.local/api/desktop/security",
      "https://nomad.local/api/desktop/remote-access/reset",
      "https://nomad.local/api/desktop/install/uninstall",
    ]);
    expect(
      requests.every((request) => !request.url.includes("/internal/")),
    ).toBe(true);
  });

  it("strictly decodes lifecycle status and binds the operation id", async () => {
    const fetchImpl: typeof fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/desktop/security")) return jsonResponse({ schema: "nomad.gateway.desktop-security.v1", csrf_token: "csrf_token_00000001" });
      if (url.endsWith("/api/desktop/lifecycle/status")) return jsonResponse({
        schema: "nomad.desktop.lifecycle-status.v1",
        operation_id: "operation_0123456789", operation: "uninstall",
        state: "outcome_unknown", terminal: true,
        error: "LIFECYCLE_OUTCOME_UNKNOWN", recovery: "RUN_OPERATION_STATUS",
      });
      throw new Error(`Unexpected request: ${url}`);
    }) as typeof fetch;
    const client = createDesktopPairingClient({ baseUrl: "https://nomad.local", fetchImpl });
    await expect(client.getLifecycleStatus!("operation_0123456789")).resolves.toMatchObject({ state: "outcome_unknown", recovery: "RUN_OPERATION_STATUS" });
    await expect(client.getLifecycleStatus!("operation_wrong_123456")).rejects.toMatchObject({ code: "PAIRING_INVALID_RESPONSE" });
  });

  it("preserves the allowlisted uninstall blocker from the desktop lifecycle route", async () => {
    const fetchImpl: typeof fetch = vi.fn(
      async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/api/desktop/security")) {
          return jsonResponse({
            schema: "nomad.gateway.desktop-security.v1",
            csrf_token: "csrf_token_00000001",
          });
        }
        if (url.endsWith("/api/desktop/install/uninstall")) {
          return new Response(
            JSON.stringify({ error: "REMOTE_UNINSTALL_REVOKE_REQUIRED" }),
            {
              status: 409,
              headers: { "content-type": "application/json" },
            },
          );
        }
        throw new Error(`Unexpected request: ${url}`);
      },
    ) as typeof fetch;

    const client = createDesktopPairingClient({
      baseUrl: "https://nomad.local",
      fetchImpl,
    });

    await expect(client.uninstall()).rejects.toMatchObject({
      code: "REMOTE_UNINSTALL_REVOKE_REQUIRED",
    });
  });

  it("keeps lifecycle error passthrough bounded to the strict allowlisted gateway envelope", async () => {
    const malformedCases = [
      JSON.stringify({ error: "REMOTE_UNINSTALL_REVOKE_REQUIRED", extra: true }),
      JSON.stringify({ error: "PAIRING_UNAVAILABLE" }),
      JSON.stringify({ message: "REMOTE_UNINSTALL_REVOKE_REQUIRED" }),
      "not-json",
    ];

    for (const body of malformedCases) {
      const fetchImpl: typeof fetch = vi.fn(
        async (input: RequestInfo | URL) => {
          const url = String(input);
          if (url.endsWith("/api/desktop/security")) {
            return jsonResponse({
              schema: "nomad.gateway.desktop-security.v1",
              csrf_token: "csrf_token_00000001",
            });
          }
          if (url.endsWith("/api/desktop/install/uninstall")) {
            return new Response(body, {
              status: 409,
              headers: { "content-type": "application/json" },
            });
          }
          throw new Error(`Unexpected request: ${url}`);
        },
      ) as typeof fetch;

      const client = createDesktopPairingClient({
        baseUrl: "https://nomad.local",
        fetchImpl,
      });

      await expect(client.uninstall()).rejects.toMatchObject({
        code: "PAIRING_HTTP_ERROR",
      });
    }
  });
});

function currentDevice(paired: boolean): DesktopPairingCurrentDevice {
  return {
    schema: "nomad.product-host.device-current.v1",
    principal_alias: "remote-paired-device",
    paired,
    device: paired
      ? { device_alias: "device-alpha-01", pairing_epoch: 7 }
      : null,
  };
}

function createdJoin(): DesktopPairingCreatedJoin {
  return {
    schema: "nomad.m3e.pairing.desktop-created.v1",
    join_id: "join-1234567890abcdef1234567890abcdef",
    expires_at: "2099-01-01T00:02:00.000Z",
    join_url:
      "https://nomad.example/j/join-1234567890abcdef1234567890abcdef#pair_secret_token_0000000000000000",
  };
}

function joinStatus(
  joinId: string,
  state: DesktopPairingJoinStatus["state"],
): DesktopPairingJoinStatus {
  return {
    schema: "nomad.m3e.pairing.status-response.v1",
    join_id: joinId,
    state,
    challenge_id:
      state === "started_awaiting_desktop_approval"
        ? "challenge-0000000000000001"
        : null,
    expected_epoch: state === "started_awaiting_desktop_approval" ? 1 : null,
    comparison_code:
      state === "started_awaiting_desktop_approval" ? "042913" : null,
    expires_at: "2099-01-01T00:02:00.000Z",
  };
}

function startResult(): PairingJoinStartResult {
  return {
    joinId: "join-1234567890abcdef1234567890abcdef",
    challengeId: "challenge-0000000000000001",
    comparisonCode: "042913",
    prospectiveEpoch: 1,
    expiresAt: "2099-01-01T00:02:00.000Z",
  };
}

function browserSession(): BrowserVaultSession {
  return {
    comparisonCode: "042913",
    bundle: {
      schema: "nomad.m3e.provisioning-bundle.v1",
      device_alias: "phone_alpha",
      pairing_epoch: 1,
      mailbox_id:
        "mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      relay_base_url: "https://relay.nomad.example",
      host_signing_public_key_sec1: "A".repeat(88),
      host_agreement_public_key_sec1: "B".repeat(88),
      wrapped_device_bearer: "wrapped-bearer",
      wrap_nonce: "wrap-nonce",
      issued_at: "2099-01-01T00:00:00.000Z",
    },
    signedProvisioningBundle: {
      schema: "nomad.m3e.signed-provisioning-bundle.v1",
      bundle: {
        schema: "nomad.m3e.provisioning-bundle.v1",
        device_alias: "phone_alpha",
        pairing_epoch: 1,
        mailbox_id:
          "mbx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relay_base_url: "https://relay.nomad.example",
        host_signing_public_key_sec1: "A".repeat(88),
        host_agreement_public_key_sec1: "B".repeat(88),
        wrapped_device_bearer: "wrapped-bearer",
        wrap_nonce: "wrap-nonce",
        issued_at: "2099-01-01T00:00:00.000Z",
      },
      provisioning_signature_p1363: "signature",
    },
    deviceBearer: "device-bearer",
    deviceSigningKeyPair: {} as CryptoKeyPair,
    deviceAgreementKeyPair: {} as CryptoKeyPair,
    transport: {
      host_to_device_applied_through_sequence: 0,
      device_to_host_next_sequence: 1,
    },
  };
}

function remoteRuntimePort(view: SessionView | null): RuntimeRemoteSessionPort {
  const snapshot = remoteRuntimeSnapshot(view);

  return {
    getSnapshot: vi.fn(() => snapshot),
    subscribe: vi.fn(() => () => {}),
    poll: vi.fn(async () => snapshot),
    dispatch: vi.fn(async () => snapshot),
    retryPending: vi.fn(async () => snapshot),
  };
}

function remoteRuntimeSnapshot(
  view: SessionView | null,
  overrides: Partial<ReturnType<RuntimeRemoteSessionPort["getSnapshot"]>> = {},
): ReturnType<RuntimeRemoteSessionPort["getSnapshot"]> {
  return {
    connection: view ? "live" : "reconnecting",
    last_good_projection: view
      ? {
          schema: "nomad.remote.projection.v1",
          snapshot: {
            schema: "nomad.product-host.snapshot.v1",
            host_instance_id: "host-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            snapshot_seq: view.state.lastAppliedSeq,
            digest: view.state.expectedDigest ?? `sha256:${"a".repeat(64)}`,
            snapshot: {
              session_alias: view.state.session.session_id,
              updated_at: view.state.session.updated_at,
              turn_state: view.state.session.turn_state,
              pending_input_alias: null,
              pending_permission_alias: null,
              diff_file_count: view.state.diffFileCount,
              writable: false,
              evidence_class:
                "official_registry_shape_only_not_provider_lifecycle" as const,
            },
          },
          capability: {
            schema: "nomad.product-host.command-capability.v1" as const,
            capability_id: "capability_00000001",
            snapshot_seq: view.state.lastAppliedSeq,
            snapshot_digest:
              view.state.expectedDigest ?? `sha256:${"a".repeat(64)}`,
            next_command_seq: 1,
            issued_at: "2099-01-01T00:00:00.000Z",
            expires_at: "2099-01-01T00:00:30.000Z",
            view: true,
            reply: null,
            deny: null,
            stop: null,
            allow_once: false,
          },
        }
      : null,
    last_receipt: null,
    pending_command: null,
    available_actions: view ? (["view"] as const) : ([] as const),
    error_code: null,
    ...overrides,
  } satisfies ReturnType<RuntimeRemoteSessionPort["getSnapshot"]>;
}

function remoteView(): SessionView {
  return {
    state: {
      session: {
        session_id: "sess-cccccccccccccccccccccccccccccccc",
        semantics_version: "1.0.0",
        turn_id: "turn-dddddddddddddddddddddddddddddddd",
        turn_state: "NeedsPermission",
        host_connectivity: "Online",
        client_freshness: "Live",
        updated_at: "2099-01-01T00:00:00.000Z",
      },
      events: [],
      timeline: [],
      tools: [],
      activePermissionId: "permission-ffffffffffffffffffffffffffffffff",
      diffFileCount: 1,
      lastAppliedSeq: 8,
      gapToSeq: null,
      digestStatus: "verified",
      expectedDigest: `sha256:${"a".repeat(64)}`,
      actualDigest: `sha256:${"a".repeat(64)}`,
      versionStatus: "ok",
      duplicatesDropped: 0,
      outcomeUnknownTools: [],
    },
    display: {
      title: "Controlled refactor",
      hostLabel: "MacBook Pilot Host",
      workspaceLabel: "Paired phone session",
      lastActivityLabel: "Paused before changing the workspace",
    },
    approval: null,
    changes: {
      status: "empty",
      source: null,
      baseline: null,
      files: [],
      reason:
        "The Host has not supplied a verified workspace diff for this session.",
    },
    provenance: "captured",
    mode: "official-local",
    writable: true,
  };
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function emptyJsonResponse(): Response {
  return new Response("{}", {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}
