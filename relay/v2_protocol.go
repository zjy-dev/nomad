package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	OpaqueFrameV2Schema = "nomad.relay.opaque-frame.v2"
	OpaqueAckV2Schema   = "nomad.relay.opaque-ack.v2"
	V2ProvisionSchema   = "nomad.relay.mailbox-provision.v1"
	V2CryptoSuite       = "p256-hkdf-sha256-aes256gcm-v1"
	V2AADPrefix         = "nomad.remote-envelope.v2\n"
	V2MaxWireFrame      = 96 * 1024
	V2MaxTTLSeconds     = int64(10 * time.Minute / time.Second)
	V2ClockSkewSeconds  = int64(time.Minute / time.Second)
	V2MaxSafeInteger    = uint64(9_007_199_254_740_991)
)

type V2Direction string

const (
	V2HostToDevice V2Direction = "host_to_device"
	V2DeviceToHost V2Direction = "device_to_host"
)

type V2Role string

const (
	V2RoleHost   V2Role = "host"
	V2RoleDevice V2Role = "device"
)

var (
	ErrV2Malformed      = errors.New("relay v2: malformed canonical frame")
	ErrV2InvalidFrame   = errors.New("relay v2: invalid frame")
	ErrV2Expired        = errors.New("relay v2: frame outside admission window")
	ErrV2Forbidden      = errors.New("relay v2: role forbidden for direction")
	ErrV2Unauthorized   = errors.New("relay v2: bearer digest mismatch")
	ErrV2NotFound       = errors.New("relay v2: mailbox not found")
	ErrV2Revoked        = errors.New("relay v2: mailbox revoked")
	ErrV2Conflict       = errors.New("relay v2: frame tuple conflict")
	ErrV2Replay         = errors.New("relay v2: sequence, nonce, or time replay")
	ErrV2Capacity       = errors.New("relay v2: mailbox capacity exceeded")
	ErrV2RateLimited    = errors.New("relay v2: publish rate exceeded")
	ErrV2AckRegression  = errors.New("relay v2: ack cursor regression")
	ErrV2AlreadyExists  = errors.New("relay v2: mailbox already provisioned")
	ErrV2InvalidMailbox = errors.New("relay v2: invalid provisioned mailbox")
)

// OpaqueFrameV2 is the exact content-blind Relay v2 wire frame. Relay validates
// framing and admission metadata but never decrypts Ciphertext.
type OpaqueFrameV2 struct {
	Schema      string      `json:"schema"`
	CryptoSuite string      `json:"crypto_suite"`
	MailboxID   string      `json:"mailbox_id"`
	Direction   V2Direction `json:"direction"`
	Epoch       uint64      `json:"epoch"`
	Sequence    uint64      `json:"sequence"`
	MessageID   string      `json:"message_id"`
	IssuedAt    int64       `json:"issued_at"`
	ExpiresAt   int64       `json:"expires_at"`
	Nonce       string      `json:"nonce"`
	Ciphertext  string      `json:"ciphertext"`
}

type OpaqueAckV2 struct {
	Schema               string      `json:"schema"`
	MailboxID            string      `json:"mailbox_id"`
	Direction            V2Direction `json:"direction"`
	Epoch                uint64      `json:"epoch"`
	AckedThroughSequence uint64      `json:"acked_through_sequence"`
}

type V2ProvisionRequest struct {
	Schema                 string `json:"schema"`
	MailboxID              string `json:"mailbox_id"`
	Epoch                  uint64 `json:"epoch"`
	HostTokenDigest        string `json:"host_token_digest"`
	DeviceTokenDigest      string `json:"device_token_digest"`
	HostIdentityCommitment string `json:"host_identity_commitment"`
	DeviceKeyCommitment    string `json:"device_key_commitment"`
}

func (a OpaqueAckV2) CanonicalBytes() ([]byte, error) {
	if err := validateV2Ack(a); err != nil {
		return nil, err
	}
	return json.Marshal(a)
}

// ParseOpaqueAckV2 applies the same exact-canonical-JSON boundary as frames.
func ParseOpaqueAckV2(raw []byte) (OpaqueAckV2, error) {
	if len(raw) == 0 || len(raw) > V2MaxWireFrame {
		return OpaqueAckV2{}, ErrV2Malformed
	}
	var ack OpaqueAckV2
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ack); err != nil {
		return OpaqueAckV2{}, fmt.Errorf("%w: %v", ErrV2Malformed, err)
	}
	if dec.Decode(new(any)) == nil {
		return OpaqueAckV2{}, ErrV2Malformed
	}
	canonical, err := ack.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, canonical) {
		return OpaqueAckV2{}, ErrV2Malformed
	}
	return ack, nil
}

func validV2Direction(d V2Direction) bool {
	return d == V2HostToDevice || d == V2DeviceToHost
}

func validatePrefixedHex(value, prefix string, hexLen int) bool {
	if len(value) != len(prefix)+hexLen || value[:len(prefix)] != prefix {
		return false
	}
	decoded, err := hex.DecodeString(value[len(prefix):])
	return err == nil && len(decoded)*2 == hexLen
}

func ParseV2DigestHex(value string) (V2Digest, error) {
	var out V2Digest
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(out) || hex.EncodeToString(decoded) != value {
		return out, ErrV2InvalidMailbox
	}
	copy(out[:], decoded)
	return out, nil
}

func decodeRawURL(value string) ([]byte, error) {
	if value == "" || bytes.ContainsAny([]byte(value), "=\r\n \t") {
		return nil, ErrV2InvalidFrame
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrV2InvalidFrame
	}
	return decoded, nil
}

// ValidateStructure checks the frozen wire contract without applying a wall
// clock. Time-window admission is intentionally performed by the storage API.
func (f OpaqueFrameV2) ValidateStructure() error {
	if f.Schema != OpaqueFrameV2Schema || f.CryptoSuite != V2CryptoSuite ||
		!validatePrefixedHex(f.MailboxID, "mbx-", 64) || !validV2Direction(f.Direction) ||
		f.Epoch == 0 || f.Epoch > V2MaxSafeInteger || f.Sequence == 0 || f.Sequence > V2MaxSafeInteger || !validatePrefixedHex(f.MessageID, "msg-", 32) ||
		f.IssuedAt <= 0 || uint64(f.IssuedAt) > V2MaxSafeInteger || f.ExpiresAt <= f.IssuedAt || uint64(f.ExpiresAt) > V2MaxSafeInteger || f.ExpiresAt-f.IssuedAt > V2MaxTTLSeconds {
		return ErrV2InvalidFrame
	}
	nonce, err := decodeRawURL(f.Nonce)
	if err != nil || len(nonce) != 12 {
		return ErrV2InvalidFrame
	}
	ciphertext, err := decodeRawURL(f.Ciphertext)
	if err != nil || len(ciphertext) < 16 { // AES-GCM authentication tag.
		return ErrV2InvalidFrame
	}
	canonical, err := json.Marshal(f)
	if err != nil || len(canonical) > V2MaxWireFrame {
		return ErrV2InvalidFrame
	}
	return nil
}

func (f OpaqueFrameV2) ValidateAt(now time.Time) error {
	if err := f.ValidateStructure(); err != nil {
		return err
	}
	n := now.Unix()
	if f.IssuedAt > n+V2ClockSkewSeconds || f.ExpiresAt <= n-V2ClockSkewSeconds {
		return ErrV2Expired
	}
	return nil
}

// CanonicalBytes returns the only accepted JSON representation. Struct field
// order is part of the frozen v2 contract.
func (f OpaqueFrameV2) CanonicalBytes() ([]byte, error) {
	if err := f.ValidateStructure(); err != nil {
		return nil, err
	}
	return json.Marshal(f)
}

func (f OpaqueFrameV2) FrameDigest() ([32]byte, error) {
	canonical, err := f.CanonicalBytes()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

// ParseOpaqueFrameV2 rejects non-canonical JSON, including whitespace, key
// reordering, unknown keys and duplicate keys.
func ParseOpaqueFrameV2(raw []byte) (OpaqueFrameV2, [32]byte, error) {
	if len(raw) == 0 || len(raw) > V2MaxWireFrame {
		return OpaqueFrameV2{}, [32]byte{}, ErrV2Malformed
	}
	var frame OpaqueFrameV2
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&frame); err != nil {
		return OpaqueFrameV2{}, [32]byte{}, fmt.Errorf("%w: %v", ErrV2Malformed, err)
	}
	if dec.Decode(new(any)) == nil {
		return OpaqueFrameV2{}, [32]byte{}, ErrV2Malformed
	}
	canonical, err := frame.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, canonical) {
		return OpaqueFrameV2{}, [32]byte{}, ErrV2Malformed
	}
	return frame, sha256.Sum256(canonical), nil
}

// AAD returns the canonical metadata authenticated by AES-GCM.
func (f OpaqueFrameV2) AAD() ([]byte, error) {
	if err := f.ValidateStructure(); err != nil {
		return nil, err
	}
	metadata := struct {
		Schema      string      `json:"schema"`
		CryptoSuite string      `json:"crypto_suite"`
		MailboxID   string      `json:"mailbox_id"`
		Direction   V2Direction `json:"direction"`
		Epoch       uint64      `json:"epoch"`
		Sequence    uint64      `json:"sequence"`
		MessageID   string      `json:"message_id"`
		IssuedAt    int64       `json:"issued_at"`
		ExpiresAt   int64       `json:"expires_at"`
		Nonce       string      `json:"nonce"`
	}{f.Schema, f.CryptoSuite, f.MailboxID, f.Direction, f.Epoch, f.Sequence, f.MessageID, f.IssuedAt, f.ExpiresAt, f.Nonce}
	b, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	return append([]byte(V2AADPrefix), b...), nil
}

func validateV2Ack(ack OpaqueAckV2) error {
	if ack.Schema != OpaqueAckV2Schema || !validatePrefixedHex(ack.MailboxID, "mbx-", 64) ||
		!validV2Direction(ack.Direction) || ack.Epoch == 0 || ack.Epoch > V2MaxSafeInteger || ack.AckedThroughSequence == 0 || ack.AckedThroughSequence > V2MaxSafeInteger {
		return ErrV2InvalidFrame
	}
	return nil
}

func (p V2ProvisionRequest) Validate() error {
	hostTokenDigest, err := ParseV2DigestHex(p.HostTokenDigest)
	if err != nil {
		return err
	}
	deviceTokenDigest, err := ParseV2DigestHex(p.DeviceTokenDigest)
	if err != nil {
		return err
	}
	if _, err := ParseV2DigestHex(p.HostIdentityCommitment); err != nil {
		return err
	}
	if _, err := ParseV2DigestHex(p.DeviceKeyCommitment); err != nil {
		return err
	}
	if p.Schema != V2ProvisionSchema || !validatePrefixedHex(p.MailboxID, "mbx-", 64) || p.Epoch == 0 || p.Epoch > V2MaxSafeInteger ||
		digestIsZero(hostTokenDigest) || digestIsZero(deviceTokenDigest) || subtleCompareDigest(hostTokenDigest, deviceTokenDigest) {
		return ErrV2InvalidMailbox
	}
	return nil
}

func (p V2ProvisionRequest) CanonicalBytes() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

func (p V2ProvisionRequest) ProvisionedMailbox() (ProvisionedMailbox, error) {
	if err := p.Validate(); err != nil {
		return ProvisionedMailbox{}, err
	}
	hostTokenDigest, _ := ParseV2DigestHex(p.HostTokenDigest)
	deviceTokenDigest, _ := ParseV2DigestHex(p.DeviceTokenDigest)
	hostIdentityCommitment, _ := ParseV2DigestHex(p.HostIdentityCommitment)
	deviceKeyCommitment, _ := ParseV2DigestHex(p.DeviceKeyCommitment)
	return ProvisionedMailbox{
		MailboxID:              p.MailboxID,
		Epoch:                  p.Epoch,
		HostTokenDigest:        hostTokenDigest,
		DeviceTokenDigest:      deviceTokenDigest,
		HostIdentityCommitment: hostIdentityCommitment,
		DeviceKeyCommitment:    deviceKeyCommitment,
		State:                  "active",
	}, nil
}

func ParseV2ProvisionRequest(raw []byte) (V2ProvisionRequest, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return V2ProvisionRequest{}, ErrV2Malformed
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return V2ProvisionRequest{}, ErrV2Malformed
	}
	seen := make(map[string]json.RawMessage, 7)
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return V2ProvisionRequest{}, ErrV2Malformed
		}
		if _, exists := seen[key]; exists {
			return V2ProvisionRequest{}, ErrV2Malformed
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return V2ProvisionRequest{}, ErrV2Malformed
		}
		seen[key] = append([]byte(nil), value...)
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return V2ProvisionRequest{}, ErrV2Malformed
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return V2ProvisionRequest{}, ErrV2Malformed
	}
	keys := []string{
		"schema",
		"mailbox_id",
		"epoch",
		"host_token_digest",
		"device_token_digest",
		"host_identity_commitment",
		"device_key_commitment",
	}
	if len(seen) != len(keys) {
		return V2ProvisionRequest{}, ErrV2Malformed
	}
	for _, key := range keys {
		if _, ok := seen[key]; !ok {
			return V2ProvisionRequest{}, ErrV2Malformed
		}
	}
	var request V2ProvisionRequest
	if err := json.Unmarshal(seen["schema"], &request.Schema); err != nil {
		return V2ProvisionRequest{}, ErrV2Malformed
	}
	if err := json.Unmarshal(seen["mailbox_id"], &request.MailboxID); err != nil {
		return V2ProvisionRequest{}, ErrV2Malformed
	}
	if err := json.Unmarshal(seen["epoch"], &request.Epoch); err != nil {
		return V2ProvisionRequest{}, ErrV2Malformed
	}
	if err := json.Unmarshal(seen["host_token_digest"], &request.HostTokenDigest); err != nil {
		return V2ProvisionRequest{}, ErrV2Malformed
	}
	if err := json.Unmarshal(seen["device_token_digest"], &request.DeviceTokenDigest); err != nil {
		return V2ProvisionRequest{}, ErrV2Malformed
	}
	if err := json.Unmarshal(seen["host_identity_commitment"], &request.HostIdentityCommitment); err != nil {
		return V2ProvisionRequest{}, ErrV2Malformed
	}
	if err := json.Unmarshal(seen["device_key_commitment"], &request.DeviceKeyCommitment); err != nil {
		return V2ProvisionRequest{}, ErrV2Malformed
	}
	canonical, err := request.CanonicalBytes()
	if err != nil || !bytes.Equal(raw, canonical) {
		return V2ProvisionRequest{}, ErrV2Malformed
	}
	return request, nil
}
