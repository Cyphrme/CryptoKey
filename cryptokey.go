// Package cryptokey is an encapsulation for cryptographic keys in Go.
package cryptokey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/cyphrme/coze"
)

// CryptoKey is a generalization of a singing or encryption cryptographic key:
// public, private, or a key pair.
type CryptoKey struct {
	Alg     coze.SEAlg
	Public  crypto.PublicKey
	Private crypto.PrivateKey
}

// NewCryptoKey generates a new CryptoKey.
func NewCryptoKey(alg coze.SEAlg) (ck *CryptoKey, err error) {

	var cryptoKey = new(CryptoKey)
	cryptoKey.Alg = alg

	switch coze.SigAlg(alg) {
	case coze.Ed25519, coze.Ed25519ph:
		// Note: Go's ed25519.PrivateKey is the seed || public key.
		cryptoKey.Public, cryptoKey.Private, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		return cryptoKey, nil
	case coze.ES224, coze.ES256, coze.ES384, coze.ES512:
		keyPair, err := ecdsa.GenerateKey(alg.Curve().EllipticCurve(), rand.Reader)
		if err != nil {
			return nil, err
		}

		cryptoKey.Public = keyPair.PublicKey
		cryptoKey.Private = keyPair
		return cryptoKey, nil
	default:
		return nil, errors.New("coze.NewCryptoKey: Unknown Alg")
	}
}

// Sign signs a precalculated digest.  On error, returns zero bytes. Digest's
// length must match c.Alg.Hash().Size().
func (c CryptoKey) Sign(digest []byte) (sig []byte, err error) {
	if len(digest) != c.Alg.Hash().Size() {
		return nil, errors.New(fmt.Sprintf("coze.enum: digest length does not match alg.hash.size. Len: %d, Alg: %s.", len(digest), c.Alg.String()))
	}

	switch c.Alg.SigAlg() {
	default:
		return nil, errors.New("coze.CryptoKey.Sign: Unknown Alg")
	case coze.ES224, coze.ES256, coze.ES384, coze.ES512:

		v, ok := c.Private.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("Not a valid ECDSA private key.")
		}

		// Note: ECDSA Sig is always R || S of a fixed size with left padding.  For
		// example, ES256 should always have a 64 byte signature.
		r, s, err := ecdsa.Sign(rand.Reader, v, digest)
		if err != nil {
			return nil, err
		}

		return coze.PadCon(r, s, c.Alg.SigAlg().SigSize()), nil

	case coze.Ed25519, coze.Ed25519ph:
		v, ok := c.Private.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("Not a valid EdDSA private key")
		}

		return ed25519.Sign(v, digest), nil
	}
}

// Verify verifies that a signature is valid with a given public CryptoKey
// and digest. `digest` should be the digest of the original msg to verify.
func (c CryptoKey) Verify(digest, sig []byte) (valid bool) {
	if len(sig) == 0 || len(digest) == 0 {
		return false
	}

	switch c.Alg.SigAlg() {
	default:
		return false
	case coze.ES224, coze.ES256, coze.ES384, coze.ES512:
		var size = c.Alg.SigAlg().SigSize() / 2
		r := big.NewInt(0).SetBytes(sig[:size])
		s := big.NewInt(0).SetBytes(sig[size:])

		v, ok := c.Public.(ecdsa.PublicKey)
		if !ok {
			return false
		}

		return ecdsa.Verify(&v, digest, r, s)
	case coze.Ed25519, coze.Ed25519ph:
		v, ok := c.Public.(ed25519.PublicKey)
		if !ok {
			return false
		}

		return ed25519.Verify(v, digest, sig)
	}
}

// SignMsg signs a pre-hash msg.  On error, returns zero bytes.
func (c CryptoKey) SignMsg(msg []byte) (sig []byte, err error) {
	return c.Sign(coze.Hash(c.Alg.Hash(), msg))
}

// Verify verifies that a signature with a given public CryptoKey and
// signed message.
func (c CryptoKey) VerifyMsg(msg, sig []byte) (valid bool) {
	return c.Verify(coze.Hash(c.Alg.Hash(), msg), sig)
}

// ToCryptoKey takes a Coze Key and returns a crypto key.
func ToCryptoKey(cozekey *coze.CozeKey) (ck *CryptoKey, err error) {
	if len(cozekey.X) == 0 {
		return nil, errors.New("coze: invalid CozeKey")
	}

	switch cozekey.Alg.SigAlg().Genus() {
	default:
		return nil, errors.New("unsupported alg: " + cozekey.Alg.String())
	case coze.Ecdsa:
		return ecDSACozeKeyToCryptoKey(cozekey), nil
	case coze.Eddsa:
		return edDSACozeKeyToCryptoKey(cozekey), nil
	}
}

func edDSACozeKeyToCryptoKey(ck *coze.CozeKey) (key *CryptoKey) {
	key = new(CryptoKey)
	key.Alg = ck.Alg
	key.Public = crypto.PublicKey(ck.X)
	b := make([]coze.B64, 64)
	d := append(b, ck.D, ck.X)
	key.Private = crypto.PublicKey(d)
	return key
}

// ecdsaCozeKeyToCryptoKey converts a Coze Key, public or private, to a
// CryptoKey.
func ecDSACozeKeyToCryptoKey(ck *coze.CozeKey) (key *CryptoKey) {
	key = new(CryptoKey)
	key.Alg = ck.Alg

	half := ck.Alg.XSize() / 2
	x := new(big.Int).SetBytes(ck.X[:half])
	y := new(big.Int).SetBytes(ck.X[half:])

	ec := ecdsa.PublicKey{
		Curve: ck.Alg.Curve().EllipticCurve(),
		X:     x,
		Y:     y,
	}

	key.Public = crypto.PublicKey(ec)

	// Private
	if len(ck.D) == 0 {
		return key
	}

	d := new(big.Int).SetBytes(ck.D)
	var private = ecdsa.PrivateKey{
		PublicKey: ec,
		D:         d,
	}
	key.Private = &private

	return key
}
