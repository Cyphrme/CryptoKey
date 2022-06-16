package cryptokey

import (
	"fmt"
	"testing"

	"github.com/cyphrme/coze"
)

// BenchmarkNSV (New, Sign, Verify) will generate a new Crypto Key, sign a
// message with that key. verify the signature, and return the results.  It will
// also test verify digest.
// go test -bench=.
func BenchmarkNSV(b *testing.B) {
	var passCount = 0

	msg := []byte("Test message.")

	var algs = []coze.SigAlg{coze.ES224, coze.ES256, coze.ES384, coze.ES512, coze.Ed25519}

	for j := 0; j < b.N; j++ {
		for i := 0; i < len(algs); i++ {
			cryptoKey, err := NewCryptoKey(coze.SEAlg(algs[i]))
			if err != nil {
				panic("Could not generate a new valid Crypto Key.")
			}
			sig, err := cryptoKey.SignMsg(msg)
			if err != nil {
				panic(err)
			}

			valid := cryptoKey.VerifyMsg(msg, sig)
			if !valid {
				panic("The signature was invalid")
			}

			// Test VerifyDigest
			msgDigest := coze.Hash(coze.SigAlg(algs[i]).Hash(), msg)
			valid = cryptoKey.Verify(msgDigest, sig)
			if !valid {
				panic("The signature was invalid")
			}

			passCount++
		}
	}

	fmt.Printf("TestCryptoKeyNSV Pass Count: %+v \n", passCount)
}
