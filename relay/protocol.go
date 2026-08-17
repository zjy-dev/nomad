package relay

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

const (
	// ProtocolVersion is the TEST-ONLY envelope version for local validation.
	// This is NOT a production security envelope — it has no E2EE, no key
	// rotation, and is for local reference only.
	ProtocolVersion uint16 = 1

	// Magic identifies a Nomad validation relay envelope.
	Magic uint32 = 0x4E4D4401 // "NMD\1"

	// HeaderSize is the fixed-size envelope header (48 bytes).
	// Layout: magic(4) + version(2) + flags(2) + deviceID(16) + nonce(8) +
	// timestamp(8) + sigLen(2) = 42 bytes + min 64-byte Ed25519 sig.
	// The envelope is a fixed header + variable Ed25519 signature.
	HeaderSize = 48

	// MaxFrameSize is the hard upper bound for any single frame payload (bytes).
	MaxFrameSize = 64 * 1024 // 64 KiB

	// MaxFramesPerSecond is the per-device frame rate limit.
	MaxFramesPerSecond = 10

	// MaxMailboxFrames is the maximum number of undelivered frames per device.
	MaxMailboxFrames = 1000

	// DefaultFrameTTL is the default time-to-live for mailbox frames.
	DefaultFrameTTL = 7 * 24 * time.Hour

	// ACKWindow is the time window for idempotent ACK tracking.
	ACKWindow = 30 * 24 * time.Hour

	// SigSize is the Ed25519 signature length.
	SigSize = ed25519.SignatureSize // 64

	// MinEnvelopeSize is the minimum valid envelope (header + sig).
	MinEnvelopeSize = HeaderSize + SigSize
)

// Flags
const (
	FlagRequest  uint16 = 0x0001
	FlagResponse uint16 = 0x0002
	FlagAck      uint16 = 0x0004
)

var (
	ErrFrameTooLarge    = errors.New("relay: frame exceeds MaxFrameSize")
	ErrFrameRateLimited = errors.New("relay: frame rate exceeded for device")
	ErrInvalidMagic     = errors.New("relay: invalid envelope magic")
	ErrInvalidVersion   = errors.New("relay: unsupported protocol version")
	ErrInvalidSignature = errors.New("relay: signature verification failed")
	ErrExpiredTimestamp = errors.New("relay: envelope timestamp expired")
	ErrMalformed        = errors.New("relay: malformed envelope")
	ErrDeviceNotFound   = errors.New("relay: device not registered")
	ErrNoContent        = errors.New("relay: no payload content")
	ErrCapacityExceeded = errors.New("relay: device mailbox capacity exceeded")
)

// DeviceID is a 16-byte opaque identifier for a relay device.
type DeviceID [16]byte

// Envelope is the wire-level wrapper for all relay frames.
//
// The envelope does NOT parse or interpret the Payload. The relay treats
// Payload as fully opaque bytes. Integrity is verified via Ed25519
// signature over the header + payload.
//
// This is a TEST-ONLY authentication mechanism. It is NOT a production
// E2EE implementation. Real security must come from a future SEC-003
// Security Envelope.
type Envelope struct {
	Magic     uint32
	Version   uint16
	Flags     uint16
	DeviceID  DeviceID
	Nonce     uint64
	Timestamp int64
	Payload   []byte
	Signature []byte
}

// PayloadHash returns the SHA-256 digest of payload bytes for logging (truncated hash only — never the payload).
func (e *Envelope) PayloadHash() []byte {
	h := sha256.Sum256(e.Payload)
	return h[:]
}

// NewEnvelope creates a new envelope for the given device with a fresh nonce and timestamp.
func NewEnvelope(deviceID DeviceID, flags uint16, payload []byte) *Envelope {
	var nonceBuf [8]byte
	rand.Read(nonceBuf[:])
	nonce := binary.BigEndian.Uint64(nonceBuf[:])

	return &Envelope{
		Magic:     Magic,
		Version:   ProtocolVersion,
		Flags:     flags,
		DeviceID:  deviceID,
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
		Payload:   payload,
	}
}

// Sign signs the envelope with the given Ed25519 private key.
// Signature covers: header bytes (with sigLen=SigSize) + payload.
func (e *Envelope) Sign(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("relay: invalid private key size")
	}
	// Ensure sigLen is set correctly before computing signing data.
	e.Signature = make([]byte, SigSize)
	signingData := e.signingData()
	e.Signature = ed25519.Sign(key, signingData)
	return nil
}

// Verify checks the envelope signature against the given public key.
func (e *Envelope) Verify(key crypto.PublicKey) error {
	if len(e.Signature) != SigSize {
		return ErrInvalidSignature
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return errors.New("relay: key is not Ed25519")
	}
	signingData := e.signingData()
	if !ed25519.Verify(pub, signingData, e.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

// signingData returns the bytes that are signed: the fixed header prefix (48 bytes) + payload.
func (e *Envelope) signingData() []byte {
	buf := make([]byte, HeaderSize+len(e.Payload))
	binary.BigEndian.PutUint32(buf[0:4], e.Magic)
	binary.BigEndian.PutUint16(buf[4:6], e.Version)
	binary.BigEndian.PutUint16(buf[6:8], e.Flags)
	copy(buf[8:24], e.DeviceID[:])
	binary.BigEndian.PutUint64(buf[24:32], e.Nonce)
	binary.BigEndian.PutUint64(buf[32:40], uint64(e.Timestamp))
	binary.BigEndian.PutUint16(buf[40:42], uint16(len(e.Signature)))
	// bytes 42..48 reserved (zero-filled)
	copy(buf[48:], e.Payload)
	return buf
}

// Marshal serializes the envelope to wire format.
func (e *Envelope) Marshal() []byte {
	sigLen := uint16(len(e.Signature))
	buf := make([]byte, int(HeaderSize)+int(sigLen)+len(e.Payload))
	binary.BigEndian.PutUint32(buf[0:4], e.Magic)
	binary.BigEndian.PutUint16(buf[4:6], e.Version)
	binary.BigEndian.PutUint16(buf[6:8], e.Flags)
	copy(buf[8:24], e.DeviceID[:])
	binary.BigEndian.PutUint64(buf[24:32], e.Nonce)
	binary.BigEndian.PutUint64(buf[32:40], uint64(e.Timestamp))
	binary.BigEndian.PutUint16(buf[40:42], sigLen)
	copy(buf[48:48+sigLen], e.Signature)
	copy(buf[48+sigLen:], e.Payload)
	return buf
}

// Unmarshal parses a wire-format buffer into an envelope.
// Returns ErrMalformed for too-short data, ErrInvalidMagic, or ErrInvalidVersion.
func Unmarshal(data []byte) (*Envelope, error) {
	if len(data) < MinEnvelopeSize {
		return nil, ErrMalformed
	}
	magic := binary.BigEndian.Uint32(data[0:4])
	if magic != Magic {
		return nil, ErrInvalidMagic
	}
	ver := binary.BigEndian.Uint16(data[4:6])
	if ver != ProtocolVersion {
		return nil, ErrInvalidVersion
	}
	flags := binary.BigEndian.Uint16(data[6:8])
	var deviceID DeviceID
	copy(deviceID[:], data[8:24])
	nonce := binary.BigEndian.Uint64(data[24:32])
	ts := int64(binary.BigEndian.Uint64(data[32:40]))
	sigLen := binary.BigEndian.Uint16(data[40:42])

	// Must have exactly sigLen signature bytes
	if len(data) < HeaderSize+int(sigLen) {
		return nil, ErrMalformed
	}
	sig := make([]byte, sigLen)
	copy(sig, data[48:48+sigLen])
	payload := make([]byte, len(data)-HeaderSize-int(sigLen))
	copy(payload, data[HeaderSize+int(sigLen):])

	return &Envelope{
		Magic:     magic,
		Version:   ver,
		Flags:     flags,
		DeviceID:  deviceID,
		Nonce:     nonce,
		Timestamp: ts,
		Payload:   payload,
		Signature: sig,
	}, nil
}

// Validate performs wire-level validation without interpreting payload.
func (e *Envelope) Validate() error {
	if e.Magic != Magic {
		return ErrInvalidMagic
	}
	if e.Version != ProtocolVersion {
		return ErrInvalidVersion
	}
	if len(e.Payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	if len(e.Signature) != SigSize {
		return ErrMalformed
	}
	return nil
}

// IsRequest returns true if the envelope is a request frame.
func (e *Envelope) IsRequest() bool { return e.Flags&FlagRequest != 0 }

// IsResponse returns true if the envelope is a response frame.
func (e *Envelope) IsResponse() bool { return e.Flags&FlagResponse != 0 }

// IsAck returns true if the envelope is an ACK frame.
func (e *Envelope) IsAck() bool { return e.Flags&FlagAck != 0 }
