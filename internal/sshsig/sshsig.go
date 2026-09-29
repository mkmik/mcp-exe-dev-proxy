// Package sshsig implements the OpenSSH SSHSIG signature format, as produced
// by `ssh-keygen -Y sign` and described in OpenSSH's PROTOCOL.sshsig.
package sshsig

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	magic   = "SSHSIG"
	version = 1

	pemType = "SSH SIGNATURE"
)

// Signature is a parsed SSHSIG blob.
type Signature struct {
	PublicKey     ssh.PublicKey
	Namespace     string
	HashAlgorithm string
	Signature     *ssh.Signature
}

type wireSignature struct {
	Version       uint32
	PublicKey     []byte
	Namespace     string
	Reserved      []byte
	HashAlgorithm string
	Signature     []byte
}

type signedData struct {
	Namespace     string
	Reserved      []byte
	HashAlgorithm string
	Hash          []byte
}

type wireSSHSignature struct {
	Format string
	Blob   []byte
	Rest   []byte `ssh:"rest"`
}

func hasher(alg string) (hash.Hash, error) {
	switch alg {
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("sshsig: unsupported hash algorithm %q", alg)
	}
}

// toSign returns the blob that is actually signed by the key.
func toSign(namespace, hashAlg string, message []byte) ([]byte, error) {
	h, err := hasher(hashAlg)
	if err != nil {
		return nil, err
	}
	h.Write(message)
	return append([]byte(magic), ssh.Marshal(signedData{
		Namespace:     namespace,
		HashAlgorithm: hashAlg,
		Hash:          h.Sum(nil),
	})...), nil
}

// Parse decodes a raw (non-armored) SSHSIG blob.
func Parse(blob []byte) (*Signature, error) {
	if !bytes.HasPrefix(blob, []byte(magic)) {
		return nil, errors.New("sshsig: bad magic")
	}
	var w wireSignature
	if err := ssh.Unmarshal(blob[len(magic):], &w); err != nil {
		return nil, fmt.Errorf("sshsig: %w", err)
	}
	if w.Version != version {
		return nil, fmt.Errorf("sshsig: unsupported version %d", w.Version)
	}
	pub, err := ssh.ParsePublicKey(w.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("sshsig: public key: %w", err)
	}
	var s wireSSHSignature
	if err := ssh.Unmarshal(w.Signature, &s); err != nil {
		return nil, fmt.Errorf("sshsig: signature: %w", err)
	}
	return &Signature{
		PublicKey:     pub,
		Namespace:     w.Namespace,
		HashAlgorithm: w.HashAlgorithm,
		Signature:     &ssh.Signature{Format: s.Format, Blob: s.Blob, Rest: s.Rest},
	}, nil
}

// Unarmor decodes the PEM-armored output of `ssh-keygen -Y sign`.
func Unarmor(armored []byte) ([]byte, error) {
	b, _ := pem.Decode(armored)
	if b == nil || b.Type != pemType {
		return nil, errors.New("sshsig: no SSH SIGNATURE block found")
	}
	return b.Bytes, nil
}

// Armor encodes a raw SSHSIG blob the way ssh-keygen does.
func Armor(blob []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: blob})
}

// Verify checks that sig is a valid signature of message in namespace.
// It does not decide whether the signing key is trusted; the caller checks
// sig.PublicKey against its own list.
func (sig *Signature) Verify(namespace string, message []byte) error {
	if sig.Namespace != namespace {
		return fmt.Errorf("sshsig: namespace %q, want %q", sig.Namespace, namespace)
	}
	if strings.HasPrefix(sig.PublicKey.Type(), "ssh-rsa") && sig.Signature.Format == ssh.KeyAlgoRSA {
		// OpenSSH refuses SHA-1 RSA signatures for SSHSIG.
		return errors.New("sshsig: ssh-rsa (SHA-1) signatures are not accepted")
	}
	data, err := toSign(namespace, sig.HashAlgorithm, message)
	if err != nil {
		return err
	}
	if err := sig.PublicKey.Verify(data, sig.Signature); err != nil {
		return fmt.Errorf("sshsig: %w", err)
	}
	return nil
}

// Sign produces a raw SSHSIG blob of message using signer. It is the Go
// equivalent of `ssh-keygen -Y sign -n namespace`.
func Sign(signer ssh.Signer, namespace string, message []byte) ([]byte, error) {
	const hashAlg = "sha512"
	data, err := toSign(namespace, hashAlg, message)
	if err != nil {
		return nil, err
	}
	var s *ssh.Signature
	if as, ok := signer.(ssh.AlgorithmSigner); ok && signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		s, err = as.SignWithAlgorithm(nil, data, ssh.KeyAlgoRSASHA512)
	} else {
		s, err = signer.Sign(nil, data)
	}
	if err != nil {
		return nil, err
	}
	return append([]byte(magic), ssh.Marshal(wireSignature{
		Version:       version,
		PublicKey:     signer.PublicKey().Marshal(),
		Namespace:     namespace,
		HashAlgorithm: hashAlg,
		Signature:     ssh.Marshal(wireSSHSignature{Format: s.Format, Blob: s.Blob, Rest: s.Rest}),
	})...), nil
}

// EncodeBlob and DecodeBlob convert a raw SSHSIG blob to and from the
// single-line form used in HTTP headers.
func EncodeBlob(blob []byte) string { return base64.StdEncoding.EncodeToString(blob) }

func DecodeBlob(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
