package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

//go:embed assets
var assets embed.FS

const imageRepo = "elastic-stack-ubuntu"

var (
	versionRE = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	clusterRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
)

type options struct {
	esNodes     int
	kibanaNodes int
	version     string
	tailnet     string
	esMemGB     int
	kibanaMemGB int
	workDir     string
	cluster     string
}

func main() {
	opts := &options{}

	root := &cobra.Command{
		Use:          "elastic_stack_setup",
		Short:        "Self-managed Elastic Stack on apple/container with Tailscale TLS",
		SilenceUsage: true,
	}
	// The cluster name prefixes every container and tailnet hostname
	// (<cluster>-es-1, <cluster>-kibana-1). Changing it gives you fresh
	// hostnames, which also sidesteps Let's Encrypt's per-hostname limits.
	root.PersistentFlags().StringVarP(&opts.cluster, "cluster", "c", "elastic", "name prefix for containers and tailnet hostnames")

	up := &cobra.Command{
		Use:   "up",
		Short: "Build the image and start the cluster",
		RunE:  func(cmd *cobra.Command, args []string) error { return deploy(opts) },
	}
	f := up.Flags()
	f.IntVarP(&opts.esNodes, "es-nodes", "e", 1, "number of Elasticsearch nodes")
	f.IntVarP(&opts.kibanaNodes, "kibana-nodes", "k", 1, "number of Kibana instances")
	f.StringVarP(&opts.version, "version", "v", "", "Elastic Stack version, e.g. 9.4.3 (required)")
	f.StringVarP(&opts.tailnet, "tailnet", "t", "", "tailnet DNS name, e.g. tailb7f31.ts.net (required)")
	f.IntVar(&opts.esMemGB, "es-memory", 8, "memory per Elasticsearch node in GB (heap is half)")
	f.IntVar(&opts.kibanaMemGB, "kibana-memory", 4, "memory per Kibana instance in GB")
	f.StringVar(&opts.workDir, "workdir", "./elastic-deploy", "build files, transport certs, Tailscale state and credentials")
	_ = up.MarkFlagRequired("version")
	_ = up.MarkFlagRequired("tailnet")

	down := &cobra.Command{
		Use:   "down",
		Short: "Stop and delete the es-node-* and kibana-node-* containers",
		RunE:  func(cmd *cobra.Command, args []string) error { return teardown(opts) },
	}

	root.AddCommand(up, down)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func deploy(o *options) error {
	switch {
	case o.esNodes < 1:
		return errors.New("--es-nodes must be at least 1")
	case o.kibanaNodes < 0:
		return errors.New("--kibana-nodes cannot be negative")
	case o.esMemGB < 2 || o.kibanaMemGB < 2:
		return errors.New("--es-memory and --kibana-memory must be at least 2")
	case !versionRE.MatchString(o.version):
		return fmt.Errorf("--version %q should look like 9.4.3", o.version)
	case !clusterRE.MatchString(o.cluster):
		return fmt.Errorf("--cluster %q must be a DNS label: lowercase letters, digits and hyphens", o.cluster)
	}
	o.tailnet = strings.Trim(o.tailnet, ".")

	authKey := os.Getenv("TAILSCALE_AUTHKEY")
	switch {
	case authKey == "":
		return errors.New("TAILSCALE_AUTHKEY is not set; export a reusable auth key (tskey-auth-...)")
	case strings.HasPrefix(authKey, "tskey-api-"):
		return errors.New("TAILSCALE_AUTHKEY is an API access token; tailscale up needs an auth key (tskey-auth-...)")
	}
	if _, err := exec.LookPath("container"); err != nil {
		return errors.New("the apple/container CLI is not in PATH")
	}

	workDir, err := filepath.Abs(o.workDir)
	if err != nil {
		return err
	}
	buildDir := filepath.Join(workDir, "build")
	transportDir := filepath.Join(workDir, "transport-certs")

	esNames := nodeNames(o.cluster+"-es", o.esNodes)
	kbNames := nodeNames(o.cluster+"-kibana", o.kibanaNodes)
	for _, n := range append(append([]string{}, esNames...), kbNames...) {
		if containerExists(n) {
			return fmt.Errorf("container %s already exists; run `elastic_stack_setup down` first", n)
		}
	}

	if err := writeBuildContext(buildDir, o.version); err != nil {
		return err
	}
	if err := ensureTransportCerts(transportDir); err != nil {
		return err
	}

	adminPass, kibanaPass, encKey := randHex(16), randHex(16), randHex(32)
	credsPath := filepath.Join(workDir, "credentials.txt")
	creds := fmt.Sprintf("admin=%s\nkibana_svc=%s\n", adminPass, kibanaPass)
	if err := os.WriteFile(credsPath, []byte(creds), 0o600); err != nil {
		return err
	}

	image := fmt.Sprintf("%s:%s", imageRepo, o.version)
	fmt.Printf("Building %s (Ubuntu 26.04)...\n", image)
	if err := run("container", "build", "-t", image, "-f", filepath.Join(buildDir, "Containerfile"), buildDir); err != nil {
		return err
	}

	// Elasticsearch nodes start in order. Each new node seeds discovery from
	// the container IPs of the nodes already running, and Kibana later maps
	// every ES FQDN to its container IP.
	esHeapMB := o.esMemGB * 1024 / 2
	var seedIPs, hostMap, esURLs []string
	for i, name := range esNames {
		tsDir, err := stateDir(workDir, name)
		if err != nil {
			return err
		}
		hostPort := 9200 + i
		fmt.Printf("\nStarting %s (%dGB, heap %dMB)\n", name, o.esMemGB, esHeapMB)
		err = run("container", "run", "-d", "--name", name,
			"--memory", fmt.Sprintf("%dg", o.esMemGB),
			"-p", fmt.Sprintf("%d:9200", hostPort),
			"-v", tsDir+":/var/lib/tailscale",
			"-v", transportDir+":/transport-certs",
			"-e", "TAILSCALE_AUTHKEY="+authKey,
			"-e", "NODE_NAME="+name,
			"-e", "TAILNET="+o.tailnet,
			"-e", fmt.Sprintf("CLUSTER_SIZE=%d", o.esNodes),
			"-e", "ES_NODE_NAMES="+strings.Join(esNames, ","),
			"-e", "SEED_HOSTS="+strings.Join(seedIPs, ","),
			"-e", fmt.Sprintf("ES_HEAP=%dm", esHeapMB),
			"-e", "ADMIN_PASSWORD="+adminPass,
			"-e", "KIBANA_SYSTEM_PASSWORD="+kibanaPass,
			image, "/usr/local/bin/start-es.sh")
		if err != nil {
			return err
		}
		ip, err := containerIPv4(name)
		if err != nil {
			return err
		}
		fqdn := name + "." + o.tailnet
		seedIPs = append(seedIPs, ip)
		hostMap = append(hostMap, ip+"="+fqdn)
		esURLs = append(esURLs, fmt.Sprintf("%q", "https://"+fqdn+":9200"))
		fmt.Printf("  https://%s:9200  (container IP %s, localhost:%d)\n", fqdn, ip, hostPort)
	}

	kbHeapMB := o.kibanaMemGB * 1024 / 2
	for i, name := range kbNames {
		tsDir, err := stateDir(workDir, name)
		if err != nil {
			return err
		}
		hostPort := 5601 + i
		fmt.Printf("\nStarting %s (%dGB, Node heap %dMB)\n", name, o.kibanaMemGB, kbHeapMB)
		err = run("container", "run", "-d", "--name", name,
			"--memory", fmt.Sprintf("%dg", o.kibanaMemGB),
			"-p", fmt.Sprintf("%d:5601", hostPort),
			"-v", tsDir+":/var/lib/tailscale",
			"-e", "TAILSCALE_AUTHKEY="+authKey,
			"-e", "NODE_NAME="+name,
			"-e", "TAILNET="+o.tailnet,
			"-e", "ES_HOSTS_MAP="+strings.Join(hostMap, ","),
			"-e", "ES_URLS="+strings.Join(esURLs, ","),
			"-e", "KIBANA_SYSTEM_PASSWORD="+kibanaPass,
			"-e", "KIBANA_ENC_KEY="+encKey,
			"-e", fmt.Sprintf("KIBANA_HEAP_MB=%d", kbHeapMB),
			image, "/usr/local/bin/start-kibana.sh")
		if err != nil {
			return err
		}
		fmt.Printf("  https://%s.%s:5601  (localhost:%d)\n", name, o.tailnet, hostPort)
	}

	fmt.Printf("\nContainers are up; certs and cluster formation finish in the background.\n")
	fmt.Printf("Credentials: %s (superuser is admin)\n", credsPath)
	fmt.Printf("Watch progress: container logs -f %s\n", esNames[0])
	fmt.Printf("Tailscale logs:  container exec %s cat /var/log/tailscaled.log\n", esNames[0])
	return nil
}

func teardown(o *options) error {
	if !clusterRE.MatchString(o.cluster) {
		return fmt.Errorf("--cluster %q must be a DNS label: lowercase letters, digits and hyphens", o.cluster)
	}
	
	apiKey := os.Getenv("TAILSCALE_API_KEY")
	if apiKey == "" {
		fmt.Println("Warning: TAILSCALE_API_KEY is not set. Tailscale entries will not be removed via API.")
	}

	for _, prefix := range []string{o.cluster + "-kibana", o.cluster + "-es"} {
		for i := 1; ; i++ {
			name := fmt.Sprintf("%s-%d", prefix, i)
			if !containerExists(name) {
				break
			}
			fmt.Printf("Removing %s\n", name)
			_ = run("container", "stop", name) // fine if already stopped
			if err := run("container", "delete", name); err != nil {
				return err
			}

			// Wipe the local state directory to prevent identity conflicts on the next run
			statePath := filepath.Join(o.workDir, "tailscale", name)
			_ = os.RemoveAll(statePath)

			// Remove the device from the Tailscale admin con[118;1:3usole via API
			if apiKey != "" {
				fmt.Printf("Purging %s from Tailscale API...\n", name)
				if err := DeleteTailscaleDevice(context.Background(), apiKey, name); err != nil {
					fmt.Printf("Warning: Failed to delete %s from Tailscale: %v\n", name, err)
				}
			}
		}
	}
	return nil
}

// DeleteTailscaleDevice removes the tailnet device whose hostname (or machine
// name, e.g. "elastic-es-1") matches host. It refuses to delete on 0 or >1 matches.
func DeleteTailscaleDevice(ctx context.Context, apiKey, host string) error {
	do := func(method, path string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, method, "https://api.tailscale.com/api/v2"+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, bytes.TrimSpace(body))
		}
		return body, nil
	}

	body, err := do(http.MethodGet, "/tailnet/-/devices")
	if err != nil {
		return fmt.Errorf("listing devices: %w", err)
	}

	var list struct {
		Devices []struct {
			ID       string `json:"id"`
			Hostname string `json:"hostname"`
			Name     string `json:"name"` // e.g. elastic-es-1.tailXXXX.ts.net
		} `json:"devices"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return fmt.Errorf("decoding device list: %w", err)
	}

	var ids []string
	for _, d := range list.Devices {
		short, _, _ := strings.Cut(d.Name, ".")
		if d.Hostname == host || short == host {
			ids = append(ids, d.ID)
		}
	}

	switch len(ids) {
	case 0:
		return fmt.Errorf("no tailnet device named %q", host)
	case 1:
	default:
		return fmt.Errorf("%d tailnet devices match %q (%v), refusing to delete", len(ids), host, ids)
	}

	if _, err := do(http.MethodDelete, "/device/"+ids[0]); err != nil {
		return fmt.Errorf("deleting %s: %w", host, err)
	}
	return nil
}

func writeBuildContext(dir, version string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	files := map[string]os.FileMode{
		"Containerfile":   0o644,
		"ts-up.sh":        0o644,
		"start-es.sh":     0o755,
		"start-kibana.sh": 0o755,
	}
	for name, mode := range files {
		b, err := assets.ReadFile("assets/" + name)
		if err != nil {
			return err
		}
		if name == "Containerfile" {
			b = []byte(strings.ReplaceAll(string(b), "__STACK_VERSION__", version))
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, mode); err != nil {
			return err
		}
	}
	return nil
}

// ensureTransportCerts creates a private CA and one shared transport cert for
// node-to-node mTLS, reusing them if they already exist. The leaf carries both
// serverAuth and clientAuth, which Let's Encrypt certs no longer do.
func ensureTransportCerts(dir string) error {
	caPath := filepath.Join(dir, "ca.crt")
	crtPath := filepath.Join(dir, "transport.crt")
	keyPath := filepath.Join(dir, "transport.key")
	if fileExists(caPath) && fileExists(crtPath) && fileExists(keyPath) {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: "elastic_stack_setup transport CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: "es-transport"},
		DNSNames:     []string{"es-transport"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return err
	}

	if err := writePEM(caPath, "CERTIFICATE", caDER, 0o644); err != nil {
		return err
	}
	if err := writePEM(crtPath, "CERTIFICATE", leafDER, 0o644); err != nil {
		return err
	}
	return writePEM(keyPath, "PRIVATE KEY", leafKeyDER, 0o600)
}

func containerIPv4(name string) (string, error) {
	for i := 0; i < 30; i++ {
		out, err := exec.Command("container", "exec", name, "hostname", "-I").Output()
		if err == nil {
			for _, field := range strings.Fields(string(out)) {
				if ip := net.ParseIP(field); ip != nil && ip.To4() != nil {
					return field, nil
				}
			}
		}
		time.Sleep(time.Second)
	}
	return "", fmt.Errorf("could not get an IPv4 address for %s; check `container logs %s`", name, name)
}

func containerExists(name string) bool {
	out, err := exec.Command("container", "inspect", name).Output()
	if err != nil {
		return false
	}
	s := strings.TrimSpace(string(out))
	return s != "" && s != "[]"
}

// run streams output but never echoes args, since they carry secrets.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s failed: %w", name, args[0], err)
	}
	return nil
}

func nodeNames(prefix string, n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("%s-%d", prefix, i+1)
	}
	return names
}

func stateDir(workDir, node string) (string, error) {
	dir := filepath.Join(workDir, "tailscale", node)
	return dir, os.MkdirAll(dir, 0o700)
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), mode)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func randSerial() *big.Int {
	s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return s
}
