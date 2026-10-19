// SPDX-License-Identifier: GPL-3.0
// Generate the real signatures used by the mldsa87verify semantic test.
// Run in a temporary Go module requiring github.com/theQRL/go-qrllib v0.10.0:
//
//	go mod init fixtures
//	go get github.com/theQRL/go-qrllib@v0.10.0
//	go run /path/to/hyperion/scripts/generate_mldsa87_fixtures.go
//
// The JSON output contains hex-encoded fields; the seed is public test data.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"

	mldsa "github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
)

func main() {
	var seed [mldsa.SEED_BYTES]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	key, err := mldsa.NewMLDSA87FromSeed(seed)
	if err != nil {
		panic(err)
	}
	digest := make([]byte, 64)
	for i := range digest {
		digest[i] = byte(i)
	}
	pk := key.GetPK()
	result := map[string]string{
		"digest":    hex.EncodeToString(digest),
		"publicKey": hex.EncodeToString(pk[:]),
	}
	for name, context := range map[string][]byte{
		"default": []byte("QNS-SIGN-v1"),
		"empty":   nil,
		"max":     bytes.Repeat([]byte{0xa5}, 255),
	} {
		sig, err := key.SignDeterministic(context, digest)
		if err != nil {
			panic(err)
		}
		if !mldsa.Verify(context, digest, sig, key.PublicKey()) {
			panic("generated signature did not verify")
		}
		result[name] = hex.EncodeToString(sig[:])
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		panic(err)
	}
}
