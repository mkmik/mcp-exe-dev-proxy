// Command mcp-exe-dev-proxy adds MCP-compliant OAuth, using exe.dev login as
// the identity source, in front of an unauthenticated MCP server.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/mkmik/mcp-exe-dev-proxy/internal/config"
	"github.com/mkmik/mcp-exe-dev-proxy/internal/identity"
	"github.com/mkmik/mcp-exe-dev-proxy/internal/server"
	"github.com/mkmik/mcp-exe-dev-proxy/internal/sshauth"
	"github.com/mkmik/mcp-exe-dev-proxy/internal/sshsig"
	"github.com/mkmik/mcp-exe-dev-proxy/internal/store"
)

const usage = `usage: mcp-exe-dev-proxy <command> [flags]

commands:
  serve           run the proxy
  token           print a short-lived access token minted with an SSH key
  revoke --all    revoke every token; all clients must log in again
  clients         list registered OAuth clients

Run "mcp-exe-dev-proxy <command> -h" for the command's flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "serve":
		err = serve(args)
	case "token":
		err = token(args)
	case "revoke":
		err = revoke(args)
	case "clients":
		err = clients(args)
	case "-h", "-help", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func configFlag(fs *flag.FlagSet) *string {
	def := config.DefaultPath
	if v := os.Getenv("MCP_EXE_DEV_PROXY_CONFIG"); v != "" {
		def = v
	}
	return fs.String("config", def, "config file (env MCP_EXE_DEV_PROXY_CONFIG)")
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := configFlag(fs)
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	st, err := store.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer st.Close()
	keys, err := sshauth.NewKeyring(cfg.AuthorizedKeys)
	if err != nil {
		return fmt.Errorf("authorized_keys: %w", err)
	}
	srv, err := server.New(cfg, st, keys, identity.ExeDev{}, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.RunGC(ctx, 10*time.Minute)

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No read or write timeouts: event streams stay open indefinitely.
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("listening", "addr", cfg.Listen, "public_url", cfg.PublicURL, "upstream", cfg.Upstream)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
}

func defaultKey() string {
	home, _ := os.UserHomeDir()
	for _, n := range []string{"id_ed25519", "id_ecdsa", "id_ed25519_sk", "id_ecdsa_sk", "id_rsa"} {
		p := filepath.Join(home, ".ssh", n)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return filepath.Join(home, ".ssh", "id_ed25519")
}

func token(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	proxyURL := fs.String("url", os.Getenv("MCP_EXE_DEV_PROXY_URL"), "public URL of the proxy (env MCP_EXE_DEV_PROXY_URL)")
	keyPath := fs.String("key", defaultKey(), "SSH key to sign with; a .pub file signs through ssh-agent")
	fs.Parse(args)
	if *proxyURL == "" {
		return errors.New("-url is required")
	}

	const path = "/machine/token"
	ts := time.Now().Unix()
	nonce := sshauth.NewNonce()
	msg := sshauth.Message(http.MethodPost, path, ts, nonce)

	cmd := exec.Command("ssh-keygen", "-q", "-Y", "sign", "-f", *keyPath, "-n", sshauth.Namespace)
	cmd.Stdin = bytes.NewReader(msg)
	cmd.Stderr = os.Stderr
	armored, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("ssh-keygen -Y sign: %w", err)
	}
	sig, err := sshsig.Unarmor(armored)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(*proxyURL, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", sshauth.Params{Timestamp: ts, Nonce: nonce, Sig: sig}.Header())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return fmt.Errorf("bad token response: %s", body)
	}
	fmt.Println(tr.AccessToken)
	return nil
}

func openStore(cfgPath string) (*store.Store, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	return store.Open(cfg.DB)
}

func revoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	cfgPath := configFlag(fs)
	all := fs.Bool("all", false, "revoke every access and refresh token")
	fs.Parse(args)
	if !*all {
		return errors.New("only revoke --all is supported")
	}
	st, err := openStore(*cfgPath)
	if err != nil {
		return err
	}
	defer st.Close()
	n, err := st.RevokeAll(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("revoked %d tokens\n", n)
	return nil
}

func clients(args []string) error {
	fs := flag.NewFlagSet("clients", flag.ExitOnError)
	cfgPath := configFlag(fs)
	fs.Parse(args)
	st, err := openStore(*cfgPath)
	if err != nil {
		return err
	}
	defer st.Close()
	cs, err := st.ListClients(context.Background())
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CLIENT ID\tNAME\tAUTH\tCREATED\tLAST USED\tREDIRECT URIS")
	for _, c := range cs {
		last := "never"
		if !c.LastUsedAt.IsZero() {
			last = c.LastUsedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", c.ID, c.Name, c.AuthMethod,
			c.CreatedAt.Format(time.RFC3339), last, strings.Join(c.RedirectURIs, " "))
	}
	return tw.Flush()
}
