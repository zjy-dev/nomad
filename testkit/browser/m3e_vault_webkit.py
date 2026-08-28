#!/usr/bin/env python3
"""Real-browser M3-E IndexedDB CryptoKey persistence proof."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from playwright.sync_api import BrowserType


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:4178")
    parser.add_argument("--browser", choices=("chromium", "webkit"), required=True)
    return parser.parse_args()


def run_vault_proof(browser_type: "BrowserType", base_url: str) -> dict[str, Any]:
    browser = browser_type.launch(headless=True)
    try:
        page = browser.new_page()
        page.goto(base_url, wait_until="networkidle")
        page.wait_for_load_state("networkidle")
        return page.evaluate(
            r"""async () => {
              const vaultModule = await import('/src/remote/browser-vault.ts');
              const cryptoModule = await import('/src/remote/crypto.ts');
              const { BrowserVault } = vaultModule;
              const {
                canonicalJson,
                computeKeyCommitment,
                deriveSharedSecret,
                exportPublicKeySec1,
                generateRuntimeP256AgreementKeyPair,
                generateRuntimeP256SigningKeyPair,
              } = cryptoModule;
              const subtle = crypto.subtle;
              const encoder = new TextEncoder();
              const dbName = 'nomad-m3e-playwright-' + crypto.randomUUID();

              const toBase64Url = (bytes) => {
                let binary = '';
                for (const byte of bytes) binary += String.fromCharCode(byte);
                return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
              };
              const bytesEqual = (left, right) => {
                if (left.byteLength !== right.byteLength) return false;
                let difference = 0;
                for (let index = 0; index < left.byteLength; index += 1) {
                  difference |= left[index] ^ right[index];
                }
                return difference === 0;
              };
              const deriveVaultKey = async (sharedSecret, mailboxId, epoch) => {
                const hkdfKey = await subtle.importKey('raw', Uint8Array.from(sharedSecret), 'HKDF', false, ['deriveBits']);
                const bits = await subtle.deriveBits({
                  name: 'HKDF',
                  hash: 'SHA-256',
                  salt: new Uint8Array([]),
                  info: encoder.encode('nomad.m3e.browser-vault.v1\n' + mailboxId + '\n' + String(epoch)),
                }, hkdfKey, 256);
                return new Uint8Array(bits);
              };
              const deleteDatabase = () => new Promise((resolve, reject) => {
                const request = indexedDB.deleteDatabase(dbName);
                request.onsuccess = () => resolve();
                request.onerror = () => reject(request.error ?? new Error('delete_failed'));
                request.onblocked = () => reject(new Error('delete_blocked'));
              });

              const hostSigning = await generateRuntimeP256SigningKeyPair();
              const hostAgreement = await generateRuntimeP256AgreementKeyPair();
              const deviceSigning = await generateRuntimeP256SigningKeyPair();
              const deviceAgreement = await generateRuntimeP256AgreementKeyPair();
              const hostSigningSec1 = await exportPublicKeySec1(hostSigning.publicKey);
              const hostAgreementSec1 = await exportPublicKeySec1(hostAgreement.publicKey);
              const deviceSigningSec1 = await exportPublicKeySec1(deviceSigning.publicKey);
              const deviceAgreementSec1 = await exportPublicKeySec1(deviceAgreement.publicKey);
              const mailboxId = 'mbx-' + '5c'.repeat(32);
              const epoch = 11;
              const bearer = 'browser-only-device-bearer';
              const nonce = crypto.getRandomValues(new Uint8Array(12));
              const sharedSecret = await deriveSharedSecret(hostAgreement.privateKey, deviceAgreement.publicKey);
              const vaultKey = await deriveVaultKey(sharedSecret, mailboxId, epoch);
              const aesKey = await subtle.importKey('raw', vaultKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
              const wrapped = await subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, encoder.encode(bearer));
              const bundle = {
                schema: 'nomad.m3e.provisioning-bundle.v1',
                device_alias: 'playwright_phone',
                pairing_epoch: epoch,
                mailbox_id: mailboxId,
                relay_base_url: 'https://relay.nomad.example',
                host_signing_public_key_sec1: toBase64Url(hostSigningSec1),
                host_agreement_public_key_sec1: toBase64Url(hostAgreementSec1),
                wrapped_device_bearer: toBase64Url(new Uint8Array(wrapped)),
                wrap_nonce: toBase64Url(nonce),
                issued_at: '2026-08-28T00:00:00Z',
              };
              const bundleSignature = await subtle.sign(
                { name: 'ECDSA', hash: 'SHA-256' },
                hostSigning.privateKey,
                encoder.encode(canonicalJson(bundle)),
              );
              const comparisonContext = {
                comparison_code: '314159',
                host_signing_commitment: await computeKeyCommitment(hostSigningSec1),
                host_agreement_commitment: await computeKeyCommitment(hostAgreementSec1),
                device_signing_commitment: await computeKeyCommitment(deviceSigningSec1),
                device_agreement_commitment: await computeKeyCommitment(deviceAgreementSec1),
              };
              const signedBundle = {
                schema: 'nomad.m3e.signed-provisioning-bundle.v1',
                bundle,
                provisioning_signature_p1363: toBase64Url(new Uint8Array(bundleSignature)),
              };

              const firstVault = new BrowserVault({
                databaseFactory: () => vaultModule.openBrowserVaultDatabase(dbName),
              });
              await firstVault.persistProvisionedDevice({
                deviceSigningKeyPair: deviceSigning,
                deviceAgreementKeyPair: deviceAgreement,
                signedProvisioningBundle: signedBundle,
                comparisonContext,
              });
              const namespaceKey = mailboxId + ':' + String(epoch);
              const namespaceCreated = await firstVault.compareAndSwapNamespaceRecord(
                'paired-session',
                namespaceKey,
                null,
                { marker: 'initial' },
              );
              await firstVault.close();

              const reopenedVault = new BrowserVault({
                databaseFactory: () => vaultModule.openBrowserVaultDatabase(dbName),
              });
              try {
                const restored = await reopenedVault.restorePairedDevice();
                const challenge = crypto.getRandomValues(new Uint8Array(32));
                const signature = await subtle.sign(
                  { name: 'ECDSA', hash: 'SHA-256' },
                  restored.deviceSigningKeyPair.privateKey,
                  challenge,
                );
                const signingVerified = await subtle.verify(
                  { name: 'ECDSA', hash: 'SHA-256' },
                  restored.deviceSigningKeyPair.publicKey,
                  signature,
                  challenge,
                );
                const restoredShared = await deriveSharedSecret(
                  restored.deviceAgreementKeyPair.privateKey,
                  hostAgreement.publicKey,
                );
                const hostShared = await deriveSharedSecret(
                  hostAgreement.privateKey,
                  restored.deviceAgreementKeyPair.publicKey,
                );
                const reopenedNamespace = await reopenedVault.loadNamespaceRecord(
                  'paired-session',
                  namespaceKey,
                );
                const concurrentCas = await Promise.all([
                  reopenedVault.compareAndSwapNamespaceRecord(
                    'paired-session', namespaceKey, 0, { writer: 'alpha' },
                  ),
                  reopenedVault.compareAndSwapNamespaceRecord(
                    'paired-session', namespaceKey, 0, { writer: 'beta' },
                  ),
                ]);
                const finalNamespace = await reopenedVault.loadNamespaceRecord(
                  'paired-session',
                  namespaceKey,
                );
                return {
                  status: 'PASS',
                  bearerUnwrapped: restored.deviceBearer === bearer,
                  signingNonExtractable: restored.deviceSigningKeyPair.privateKey.extractable === false,
                  agreementNonExtractable: restored.deviceAgreementKeyPair.privateKey.extractable === false,
                  signingVerified,
                  agreementDerived: bytesEqual(restoredShared, hostShared),
                  namespaceCreated,
                  namespaceReopenedAtRevisionZero: reopenedNamespace?.revision === 0,
                  namespaceConcurrentWinnerCount: concurrentCas.filter(Boolean).length,
                  namespaceFinalRevision: finalNamespace?.revision,
                };
              } finally {
                await reopenedVault.close();
                await deleteDatabase();
              }
            }"""
        )
    finally:
        browser.close()


def main() -> int:
    args = parse_args()
    try:
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError:
        print(json.dumps({
            "browser": args.browser,
            "code": "M3E_BROWSER_BLOCK_PLAYWRIGHT_MISSING",
            "status": "BLOCK",
        }, sort_keys=True))
        return 2

    try:
        playwright_version = importlib.metadata.version("playwright")
        with sync_playwright() as playwright:
            browser_type = getattr(playwright, args.browser)
            executable_path = browser_type.executable_path
            result = run_vault_proof(browser_type, args.base_url)
    except Exception as error:
        print(json.dumps({
            "browser": args.browser,
            "code": "M3E_BROWSER_BLOCK_EXECUTION",
            "error": str(error),
            "status": "BLOCK",
        }, sort_keys=True))
        return 2

    expected = {
        "status": "PASS",
        "bearerUnwrapped": True,
        "signingNonExtractable": True,
        "agreementNonExtractable": True,
        "signingVerified": True,
        "agreementDerived": True,
        "namespaceCreated": True,
        "namespaceReopenedAtRevisionZero": True,
        "namespaceConcurrentWinnerCount": 1,
        "namespaceFinalRevision": 1,
    }
    if result != expected:
        print(json.dumps({"browser": args.browser, "status": "FAIL", "result": result}, sort_keys=True))
        return 1
    print(json.dumps({
        "browser": args.browser,
        "browserExecutable": executable_path,
        "playwrightVersion": playwright_version,
        **result,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
