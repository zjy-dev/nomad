package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func validV2Frame(now time.Time, sequence uint64) OpaqueFrameV2 {
	return OpaqueFrameV2{
		Schema: OpaqueFrameV2Schema, CryptoSuite: V2CryptoSuite,
		MailboxID: "mbx-" + strings.Repeat("ab", 32), Direction: V2HostToDevice,
		Epoch: 1, Sequence: sequence, MessageID: "msg-" + strings.Repeat("cd", 16),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(10 * time.Minute).Unix(),
		Nonce:      base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(sequence)}, 12)),
		Ciphertext: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 32)),
	}
}

func TestOpaqueFrameV2CanonicalDigestAndAAD(t *testing.T) {
	f := validV2Frame(time.Unix(2_000_000_000, 0), 1)
	raw, err := f.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	parsed, digest, err := ParseOpaqueFrameV2(raw)
	if err != nil || parsed != f {
		t.Fatalf("parse=%+v err=%v", parsed, err)
	}
	if digest != sha256.Sum256(raw) {
		t.Fatal("digest is not over canonical bytes")
	}
	aad, err := f.AAD()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(aad, []byte(V2AADPrefix)) || bytes.Contains(aad, []byte("ciphertext")) || bytes.Contains(aad, []byte(f.Ciphertext)) {
		t.Fatalf("bad AAD %q", aad)
	}
}

func TestOpaqueFrameV2RejectsNonCanonicalAndMalformed(t *testing.T) {
	f := validV2Frame(time.Unix(2_000_000_000, 0), 1)
	raw, _ := json.Marshal(f)
	mutations := [][]byte{append([]byte(" "), raw...), append(raw, '\n'), bytes.Replace(raw, []byte("\"schema\":"), []byte("\"extra\":1,\"schema\":"), 1), bytes.Replace(raw, []byte("\"schema\":"), []byte("\"schema\":\"x\",\"schema\":"), 1)}
	for i, mutation := range mutations {
		if _, _, err := ParseOpaqueFrameV2(mutation); err == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
	f.Nonce = base64.RawURLEncoding.EncodeToString(make([]byte, 11))
	if err := f.ValidateStructure(); !errors.Is(err, ErrV2InvalidFrame) {
		t.Fatalf("nonce err=%v", err)
	}
}

func TestOpaqueFrameV2AdmissionWindow(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	f := validV2Frame(now, 1)
	if err := f.ValidateAt(now); err != nil {
		t.Fatal(err)
	}
	f.IssuedAt = now.Add(61 * time.Second).Unix()
	f.ExpiresAt = f.IssuedAt + 1
	if !errors.Is(f.ValidateAt(now), ErrV2Expired) {
		t.Fatal("future frame accepted")
	}
}

func TestParseOpaqueAckV2ExactCanonicalJSON(t *testing.T) {
	ack := OpaqueAckV2{Schema: OpaqueAckV2Schema, MailboxID: "mbx-" + strings.Repeat("ab", 32), Direction: V2HostToDevice, Epoch: 1, AckedThroughSequence: 7}
	raw, err := ack.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseOpaqueAckV2(raw)
	if err != nil || parsed != ack {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
	}
	reordered := []byte("{\"mailbox_id\":\"" + ack.MailboxID + "\",\"schema\":\"" + OpaqueAckV2Schema + "\",\"direction\":\"host_to_device\",\"epoch\":1,\"acked_through_sequence\":7}")
	mutations := [][]byte{
		append([]byte(" "), raw...),
		append(raw, '\n'),
		append(raw, []byte("{}")...),
		bytes.Replace(raw, []byte("\"schema\":"), []byte("\"unknown\":1,\"schema\":"), 1),
		bytes.Replace(raw, []byte("\"schema\":"), []byte("\"schema\":\"x\",\"schema\":"), 1),
		reordered,
	}
	for i, mutation := range mutations {
		if _, err := ParseOpaqueAckV2(mutation); err == nil {
			t.Fatalf("mutation %d accepted: %s", i, mutation)
		}
	}
}
