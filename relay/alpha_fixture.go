package relay

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

const (
	alphaLocalDeviceIDHex  = "00112233445566778899aabbccddeeff"
	alphaLocalPublicKeyHex = "91e2a79a68c193280833693cd118d53d7e9cf571eb3bc8b3ade7a398b4068864"
)

// AlphaLocalFixture returns the fixed pre-registered local device fixture for
// the local Alpha read-only slice. It is not pairing and not production
// identity.
func AlphaLocalFixture() (DeviceID, ed25519.PublicKey, error) {
	var deviceID DeviceID
	rawID, err := hex.DecodeString(alphaLocalDeviceIDHex)
	if err != nil {
		return deviceID, nil, fmt.Errorf("relay: decode alpha local device id: %w", err)
	}
	if len(rawID) != len(deviceID) {
		return deviceID, nil, fmt.Errorf("relay: alpha local device id has %d bytes", len(rawID))
	}
	copy(deviceID[:], rawID)

	pub, err := hex.DecodeString(alphaLocalPublicKeyHex)
	if err != nil {
		return deviceID, nil, fmt.Errorf("relay: decode alpha local public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return deviceID, nil, fmt.Errorf("relay: alpha local public key has %d bytes", len(pub))
	}
	return deviceID, ed25519.PublicKey(pub), nil
}
