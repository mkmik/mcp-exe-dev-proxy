package sshsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func signers(t *testing.T) map[string]ssh.Signer {
	t.Helper()
	_, edk, _ := ed25519.GenerateKey(rand.Reader)
	eck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsak, _ := rsa.GenerateKey(rand.Reader, 2048)
	out := map[string]ssh.Signer{}
	for name, k := range map[string]crypto.Signer{"ed25519": edk, "ecdsa": eck, "rsa": rsak} {
		s, err := ssh.NewSignerFromSigner(k)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = s
	}
	return out
}

func TestSignVerify(t *testing.T) {
	msg := []byte("POST\n/machine/token\n123\nnonce\n")
	for name, s := range signers(t) {
		t.Run(name, func(t *testing.T) {
			blob, err := Sign(s, "ns", msg)
			if err != nil {
				t.Fatal(err)
			}
			// Round-trip through the armored form too.
			raw, err := Unarmor(Armor(blob))
			if err != nil {
				t.Fatal(err)
			}
			sig, err := Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if ssh.FingerprintSHA256(sig.PublicKey) != ssh.FingerprintSHA256(s.PublicKey()) {
				t.Fatal("wrong public key")
			}
			if err := sig.Verify("ns", msg); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if err := sig.Verify("other", msg); err == nil {
				t.Fatal("verified with wrong namespace")
			}
			if err := sig.Verify("ns", append([]byte("x"), msg...)); err == nil {
				t.Fatal("verified tampered message")
			}
		})
	}
}

// TestOpenSSHInterop checks against the real ssh-keygen when available.
func TestOpenSSHInterop(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "id")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v %s", err, out)
	}
	msg := "hello\n"

	// ssh-keygen signs, we verify.
	cmd := exec.Command("ssh-keygen", "-q", "-Y", "sign", "-f", key, "-n", "ns")
	cmd.Stdin = strings.NewReader(msg)
	armored, err := cmd.Output()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := Unarmor(armored)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Verify("ns", []byte(msg)); err != nil {
		t.Fatalf("verify ssh-keygen signature: %v", err)
	}

	// We sign, ssh-keygen verifies.
	pem, _ := os.ReadFile(key)
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Sign(signer, "ns", []byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	sigFile := filepath.Join(dir, "sig")
	os.WriteFile(sigFile, Armor(blob), 0o600)
	allowed := filepath.Join(dir, "allowed")
	pub, _ := os.ReadFile(key + ".pub")
	os.WriteFile(allowed, append([]byte("test "), pub...), 0o600)
	cmd = exec.Command("ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "test", "-n", "ns", "-s", sigFile)
	cmd.Stdin = strings.NewReader(msg)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen verify: %v %s", err, out)
	}
}
