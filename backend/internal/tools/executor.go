package tools

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/nicolaka/netshoot/backend/pkg/models"
)

const defaultTimeout = 60 * time.Second
const longTimeout = 120 * time.Second

// Executor handles the execution of networking tools
type Executor struct {
	timeout time.Duration
}

// NewExecutor creates a new tool executor
func NewExecutor() *Executor {
	return &Executor{
		timeout: defaultTimeout,
	}
}

// Execute runs a command and returns the result
func (e *Executor) Execute(ctx context.Context, name string, args ...string) (*models.ToolResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	response := &models.ToolResponse{
		Tool:    name,
		Success: err == nil,
		Output:  stdout.String(),
	}

	if err != nil {
		response.Error = stderr.String()
		if exitError, ok := err.(*exec.ExitError); ok {
			response.ExitCode = exitError.ExitCode()
		} else {
			response.ExitCode = -1
		}
	}

	return response, nil
}

// ExecuteWithTimeout runs a command with a custom timeout
func (e *Executor) ExecuteWithTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) (*models.ToolResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	response := &models.ToolResponse{
		Tool:    name,
		Success: err == nil,
		Output:  stdout.String(),
	}

	if err != nil {
		response.Error = stderr.String()
		if exitError, ok := err.(*exec.ExitError); ok {
			response.ExitCode = exitError.ExitCode()
		} else {
			response.ExitCode = -1
		}
	}

	return response, nil
}

// sanitizeArg removes potentially dangerous characters from arguments
func sanitizeArg(s string) string {
	s = strings.ReplaceAll(s, ";", "")
	s = strings.ReplaceAll(s, "|", "")
	s = strings.ReplaceAll(s, "&", "")
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "$", "")
	s = strings.ReplaceAll(s, "(", "")
	s = strings.ReplaceAll(s, ")", "")
	return strings.TrimSpace(s)
}

// ========== Network Diagnostics ==========

// Ping executes a ping command
func (e *Executor) Ping(ctx context.Context, req *models.PingRequest) (*models.ToolResponse, error) {
	count := req.Count
	if count <= 0 {
		count = 4
	}
	if count > 20 {
		count = 20
	}

	args := []string{"-c", fmt.Sprintf("%d", count), sanitizeArg(req.Host)}
	return e.Execute(ctx, "ping", args...)
}

// Fping executes an fping command for multiple hosts
func (e *Executor) Fping(ctx context.Context, req *models.FpingRequest) (*models.ToolResponse, error) {
	count := req.Count
	if count <= 0 {
		count = 3
	}
	if count > 10 {
		count = 10
	}

	args := []string{"-c", fmt.Sprintf("%d", count)}
	for _, host := range req.Hosts {
		if len(args) > 12 {
			break // Limit number of hosts
		}
		args = append(args, sanitizeArg(host))
	}
	return e.Execute(ctx, "fping", args...)
}

// MTR executes an MTR command
func (e *Executor) MTR(ctx context.Context, req *models.MTRRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.ReportMode {
		args = append(args, "-r")
	}

	count := req.Count
	if count <= 0 {
		count = 10
	}
	if count > 50 {
		count = 50
	}
	args = append(args, "-c", fmt.Sprintf("%d", count))
	args = append(args, sanitizeArg(req.Host))

	return e.Execute(ctx, "mtr", args...)
}

// Traceroute executes a traceroute command
func (e *Executor) Traceroute(ctx context.Context, req *models.TracerouteRequest) (*models.ToolResponse, error) {
	args := []string{}

	maxHops := req.MaxHops
	if maxHops > 0 {
		if maxHops > 64 {
			maxHops = 64
		}
		args = append(args, "-m", fmt.Sprintf("%d", maxHops))
	}

	args = append(args, sanitizeArg(req.Host))

	return e.Execute(ctx, "traceroute", args...)
}

// TCPTraceroute executes a TCP traceroute command
func (e *Executor) TCPTraceroute(ctx context.Context, req *models.TCPTracerouteRequest) (*models.ToolResponse, error) {
	args := []string{sanitizeArg(req.Host)}

	if req.Port > 0 && req.Port <= 65535 {
		args = append(args, fmt.Sprintf("%d", req.Port))
	}

	return e.Execute(ctx, "tcptraceroute", args...)
}

// Trippy executes a trippy command (returns text mode output)
func (e *Executor) Trippy(ctx context.Context, req *models.TrippyRequest) (*models.ToolResponse, error) {
	// Trippy is TUI-based, so we run in report mode
	args := []string{"--mode", "stream", "-c", "10", sanitizeArg(req.Host)}
	return e.Execute(ctx, "trip", args...)
}

// ========== DNS Tools ==========

// DNSLookup executes a DNS lookup using drill
func (e *Executor) DNSLookup(ctx context.Context, req *models.DNSRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.Type != "" {
		args = append(args, sanitizeArg(req.Type))
	}

	args = append(args, sanitizeArg(req.Host))

	if req.Server != "" {
		args = append(args, "@"+sanitizeArg(req.Server))
	}

	return e.Execute(ctx, "drill", args...)
}

// Dig executes a dig command
func (e *Executor) Dig(ctx context.Context, req *models.DigRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.Server != "" {
		args = append(args, "@"+sanitizeArg(req.Server))
	}

	args = append(args, sanitizeArg(req.Host))

	if req.Type != "" {
		args = append(args, sanitizeArg(req.Type))
	}

	return e.Execute(ctx, "dig", args...)
}

// Nslookup executes an nslookup command
func (e *Executor) Nslookup(ctx context.Context, req *models.NslookupRequest) (*models.ToolResponse, error) {
	args := []string{sanitizeArg(req.Host)}

	if req.Server != "" {
		args = append(args, sanitizeArg(req.Server))
	}

	return e.Execute(ctx, "nslookup", args...)
}

// Host executes a host command
func (e *Executor) Host(ctx context.Context, req *models.HostRequest) (*models.ToolResponse, error) {
	args := []string{sanitizeArg(req.Host)}

	if req.Server != "" {
		args = append(args, sanitizeArg(req.Server))
	}

	return e.Execute(ctx, "host", args...)
}

// ========== Port Scanning & Network Discovery ==========

// Nmap executes an nmap scan
func (e *Executor) Nmap(ctx context.Context, req *models.NmapRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.ScanType != "" {
		args = append(args, sanitizeArg(req.ScanType))
	}

	if req.Ports != "" {
		args = append(args, "-p", sanitizeArg(req.Ports))
	}

	if req.FastScan {
		args = append(args, "-F")
	}

	if req.Verbose {
		args = append(args, "-v")
	}

	if req.Scripts != "" {
		args = append(args, "--script", sanitizeArg(req.Scripts))
	}

	args = append(args, sanitizeArg(req.Host))

	return e.ExecuteWithTimeout(ctx, longTimeout, "nmap", args...)
}

// Nping executes an nping command
func (e *Executor) Nping(ctx context.Context, req *models.NpingRequest) (*models.ToolResponse, error) {
	args := []string{}

	protocol := req.Protocol
	if protocol == "" {
		protocol = "tcp"
	}

	switch protocol {
	case "tcp":
		args = append(args, "--tcp")
	case "udp":
		args = append(args, "--udp")
	case "icmp":
		args = append(args, "--icmp")
	}

	if req.Port > 0 && req.Port <= 65535 {
		args = append(args, "-p", fmt.Sprintf("%d", req.Port))
	}

	count := req.Count
	if count <= 0 {
		count = 5
	}
	if count > 20 {
		count = 20
	}
	args = append(args, "-c", fmt.Sprintf("%d", count))

	args = append(args, sanitizeArg(req.Host))

	return e.Execute(ctx, "nping", args...)
}

// Netcat executes a netcat command
func (e *Executor) Netcat(ctx context.Context, req *models.NetcatRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.Verbose {
		args = append(args, "-v")
	}

	if req.Zero {
		args = append(args, "-z")
	}

	if req.UDP {
		args = append(args, "-u")
	}

	args = append(args, sanitizeArg(req.Host))

	if req.Port > 0 && req.Port <= 65535 {
		args = append(args, fmt.Sprintf("%d", req.Port))
	}

	return e.Execute(ctx, "nc", args...)
}

// ========== HTTP/Web Tools ==========

// Curl executes a curl request
func (e *Executor) Curl(ctx context.Context, req *models.CurlRequest) (*models.ToolResponse, error) {
	args := []string{"-s", "-S"}

	method := req.Method
	if method == "" {
		method = "GET"
	}
	args = append(args, "-X", method)

	if req.FollowRedirect {
		args = append(args, "-L")
	}

	if req.Insecure {
		args = append(args, "-k")
	}

	if req.Verbose {
		args = append(args, "-v")
	}

	for key, value := range req.Headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", sanitizeArg(key), sanitizeArg(value)))
	}

	if req.Body != "" {
		args = append(args, "-d", req.Body)
	}

	args = append(args, sanitizeArg(req.URL))

	return e.Execute(ctx, "curl", args...)
}

// HTTPie executes an HTTPie request
func (e *Executor) HTTPie(ctx context.Context, req *models.HTTPieRequest) (*models.ToolResponse, error) {
	method := req.Method
	if method == "" {
		method = "GET"
	}

	args := []string{method, sanitizeArg(req.URL)}

	for key, value := range req.Headers {
		args = append(args, fmt.Sprintf("%s:%s", sanitizeArg(key), sanitizeArg(value)))
	}

	for key, value := range req.Data {
		if req.JSON {
			args = append(args, fmt.Sprintf("%s:=%s", sanitizeArg(key), sanitizeArg(value)))
		} else {
			args = append(args, fmt.Sprintf("%s=%s", sanitizeArg(key), sanitizeArg(value)))
		}
	}

	return e.Execute(ctx, "http", args...)
}

// Ab executes an Apache Benchmark test
func (e *Executor) Ab(ctx context.Context, req *models.AbRequest) (*models.ToolResponse, error) {
	requests := req.Requests
	if requests <= 0 {
		requests = 100
	}
	if requests > 1000 {
		requests = 1000
	}

	concurrency := req.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}
	if concurrency > 100 {
		concurrency = 100
	}

	args := []string{
		"-n", fmt.Sprintf("%d", requests),
		"-c", fmt.Sprintf("%d", concurrency),
		sanitizeArg(req.URL),
	}

	return e.Execute(ctx, "ab", args...)
}

// Fortio executes a Fortio load test
func (e *Executor) Fortio(ctx context.Context, req *models.FortioRequest) (*models.ToolResponse, error) {
	args := []string{"load"}

	if req.Connections > 0 && req.Connections <= 64 {
		args = append(args, "-c", fmt.Sprintf("%d", req.Connections))
	}

	if req.Duration != "" {
		args = append(args, "-t", sanitizeArg(req.Duration))
	} else {
		args = append(args, "-t", "5s")
	}

	if req.QPS > 0 && req.QPS <= 1000 {
		args = append(args, "-qps", fmt.Sprintf("%d", req.QPS))
	}

	args = append(args, sanitizeArg(req.URL))

	return e.ExecuteWithTimeout(ctx, longTimeout, "fortio", args...)
}

// Websocat executes a websocat test (connection test only)
func (e *Executor) Websocat(ctx context.Context, req *models.WebsocatRequest) (*models.ToolResponse, error) {
	args := []string{"-t", sanitizeArg(req.URL)}
	return e.Execute(ctx, "websocat", args...)
}

// Grpcurl executes a grpcurl command
func (e *Executor) Grpcurl(ctx context.Context, req *models.GrpcurlRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.Plaintext {
		args = append(args, "-plaintext")
	}

	if req.Data != "" {
		args = append(args, "-d", req.Data)
	}

	args = append(args, sanitizeArg(req.Server))

	if req.Service != "" && req.Method != "" {
		args = append(args, fmt.Sprintf("%s/%s", sanitizeArg(req.Service), sanitizeArg(req.Method)))
	} else if req.Service != "" {
		args = append(args, "list", sanitizeArg(req.Service))
	} else {
		args = append(args, "list")
	}

	return e.Execute(ctx, "grpcurl", args...)
}

// ========== Packet Capture & Analysis ==========

// Tcpdump executes a tcpdump capture (limited)
func (e *Executor) Tcpdump(ctx context.Context, req *models.TcpdumpRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.Interface != "" {
		args = append(args, "-i", sanitizeArg(req.Interface))
	}

	count := req.Count
	if count <= 0 {
		count = 10
	}
	if count > 100 {
		count = 100
	}
	args = append(args, "-c", fmt.Sprintf("%d", count))

	if req.Verbose {
		args = append(args, "-v")
	}

	if req.Filter != "" {
		args = append(args, sanitizeArg(req.Filter))
	}

	return e.Execute(ctx, "tcpdump", args...)
}

// Tshark executes a tshark capture
func (e *Executor) Tshark(ctx context.Context, req *models.TsharkRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.Interface != "" {
		args = append(args, "-i", sanitizeArg(req.Interface))
	}

	count := req.Count
	if count <= 0 {
		count = 10
	}
	if count > 100 {
		count = 100
	}
	args = append(args, "-c", fmt.Sprintf("%d", count))

	if req.Fields != "" {
		args = append(args, "-T", "fields", "-e", sanitizeArg(req.Fields))
	}

	if req.Filter != "" {
		args = append(args, "-f", sanitizeArg(req.Filter))
	}

	return e.Execute(ctx, "tshark", args...)
}

// Ngrep executes an ngrep command
func (e *Executor) Ngrep(ctx context.Context, req *models.NgrepRequest) (*models.ToolResponse, error) {
	args := []string{"-q", "-c", "10"} // Quiet mode, 10 matches max

	if req.Interface != "" {
		args = append(args, "-d", sanitizeArg(req.Interface))
	}

	if req.Pattern != "" {
		args = append(args, sanitizeArg(req.Pattern))
	}

	if req.Filter != "" {
		args = append(args, sanitizeArg(req.Filter))
	}

	return e.Execute(ctx, "ngrep", args...)
}

// ========== Performance Testing ==========

// IPerf executes an iperf client test
func (e *Executor) IPerf(ctx context.Context, req *models.IPerfRequest) (*models.ToolResponse, error) {
	args := []string{"-c", sanitizeArg(req.Server)}

	if req.Port > 0 && req.Port <= 65535 {
		args = append(args, "-p", fmt.Sprintf("%d", req.Port))
	}

	duration := req.Duration
	if duration <= 0 {
		duration = 10
	}
	if duration > 60 {
		duration = 60
	}
	args = append(args, "-t", fmt.Sprintf("%d", duration))

	if req.Reverse {
		args = append(args, "-R")
	}

	if req.UDP {
		args = append(args, "-u")
	}

	return e.ExecuteWithTimeout(ctx, longTimeout, "iperf", args...)
}

// IPerf3 executes an iperf3 client test
func (e *Executor) IPerf3(ctx context.Context, req *models.IPerf3Request) (*models.ToolResponse, error) {
	args := []string{"-c", sanitizeArg(req.Server)}

	if req.Port > 0 && req.Port <= 65535 {
		args = append(args, "-p", fmt.Sprintf("%d", req.Port))
	}

	duration := req.Duration
	if duration <= 0 {
		duration = 10
	}
	if duration > 60 {
		duration = 60
	}
	args = append(args, "-t", fmt.Sprintf("%d", duration))

	if req.Reverse {
		args = append(args, "-R")
	}

	if req.UDP {
		args = append(args, "-u")
	}

	if req.JSON {
		args = append(args, "-J")
	}

	return e.ExecuteWithTimeout(ctx, longTimeout, "iperf3", args...)
}

// SpeedTest executes a speed test
func (e *Executor) SpeedTest(ctx context.Context, req *models.SpeedTestRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.Simple {
		args = append(args, "--simple")
	}

	if req.ServerID > 0 {
		args = append(args, "--server", fmt.Sprintf("%d", req.ServerID))
	}

	return e.ExecuteWithTimeout(ctx, longTimeout, "speedtest-cli", args...)
}

// ========== Network Configuration ==========

// IPRoute executes an ip route command
func (e *Executor) IPRoute(ctx context.Context, req *models.IPRouteRequest) (*models.ToolResponse, error) {
	args := []string{"route"}

	action := req.Action
	if action == "" {
		action = "show"
	}
	args = append(args, action)

	if req.Target != "" && action == "get" {
		args = append(args, sanitizeArg(req.Target))
	}

	return e.Execute(ctx, "ip", args...)
}

// IPAddr executes an ip addr command
func (e *Executor) IPAddr(ctx context.Context, req *models.IPAddrRequest) (*models.ToolResponse, error) {
	args := []string{"addr", "show"}

	if req.Interface != "" {
		args = append(args, "dev", sanitizeArg(req.Interface))
	}

	return e.Execute(ctx, "ip", args...)
}

// IPLink executes an ip link command
func (e *Executor) IPLink(ctx context.Context, req *models.IPLinkRequest) (*models.ToolResponse, error) {
	args := []string{"link", "show"}

	if req.Interface != "" {
		args = append(args, "dev", sanitizeArg(req.Interface))
	}

	return e.Execute(ctx, "ip", args...)
}

// IPNeigh executes an ip neigh command (ARP table)
func (e *Executor) IPNeigh(ctx context.Context, req *models.IPNeighRequest) (*models.ToolResponse, error) {
	args := []string{"neigh", "show"}

	if req.Interface != "" {
		args = append(args, "dev", sanitizeArg(req.Interface))
	}

	return e.Execute(ctx, "ip", args...)
}

// Netstat executes a netstat command
func (e *Executor) Netstat(ctx context.Context, req *models.NetstatRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.Listening {
		args = append(args, "-l")
	}
	if req.TCP {
		args = append(args, "-t")
	}
	if req.UDP {
		args = append(args, "-u")
	}
	if req.Numeric {
		args = append(args, "-n")
	}
	if req.Programs {
		args = append(args, "-p")
	}

	if len(args) == 0 {
		args = []string{"-tulpn"}
	}

	return e.Execute(ctx, "netstat", args...)
}

// SS executes an ss command
func (e *Executor) SS(ctx context.Context, req *models.SSRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.Listening {
		args = append(args, "-l")
	}
	if req.TCP {
		args = append(args, "-t")
	}
	if req.UDP {
		args = append(args, "-u")
	}
	if req.Processes {
		args = append(args, "-p")
	}
	if req.State != "" {
		args = append(args, "state", sanitizeArg(req.State))
	}

	if len(args) == 0 {
		args = []string{"-tulpn"}
	}

	return e.Execute(ctx, "ss", args...)
}

// Ethtool executes an ethtool command
func (e *Executor) Ethtool(ctx context.Context, req *models.EthtoolRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.Stats {
		args = append(args, "-S")
	}

	args = append(args, sanitizeArg(req.Interface))

	return e.Execute(ctx, "ethtool", args...)
}

// Bridge executes a bridge command
func (e *Executor) Bridge(ctx context.Context, req *models.BridgeRequest) (*models.ToolResponse, error) {
	command := req.Command
	if command == "" {
		command = "link"
	}

	args := []string{sanitizeArg(command), "show"}

	return e.Execute(ctx, "bridge", args...)
}

// ========== Firewall & Security ==========

// Iptables executes an iptables command
func (e *Executor) Iptables(ctx context.Context, req *models.IptablesRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.Table != "" {
		args = append(args, "-t", sanitizeArg(req.Table))
	}

	if req.List {
		args = append(args, "-L")
	} else {
		args = append(args, "-L")
	}

	if req.Numeric {
		args = append(args, "-n")
	}

	if req.Verbose {
		args = append(args, "-v")
	}

	return e.Execute(ctx, "iptables", args...)
}

// Nftables executes an nft command
func (e *Executor) Nftables(ctx context.Context, req *models.NftablesRequest) (*models.ToolResponse, error) {
	command := req.Command
	if command == "" {
		command = "list"
	}

	args := []string{sanitizeArg(command)}

	if req.Table != "" {
		args = append(args, "table", sanitizeArg(req.Table))
	} else if command == "list" {
		args = append(args, "ruleset")
	}

	return e.Execute(ctx, "nft", args...)
}

// Ipset executes an ipset command
func (e *Executor) Ipset(ctx context.Context, req *models.IpsetRequest) (*models.ToolResponse, error) {
	command := req.Command
	if command == "" {
		command = "list"
	}

	args := []string{sanitizeArg(command)}

	if req.SetName != "" {
		args = append(args, sanitizeArg(req.SetName))
	}

	return e.Execute(ctx, "ipset", args...)
}

// Conntrack executes a conntrack command
func (e *Executor) Conntrack(ctx context.Context, req *models.ConntrackRequest) (*models.ToolResponse, error) {
	args := []string{"-L"}

	if req.Protocol != "" {
		args = append(args, "-p", sanitizeArg(req.Protocol))
	}

	if req.Source != "" {
		args = append(args, "-s", sanitizeArg(req.Source))
	}

	return e.Execute(ctx, "conntrack", args...)
}

// ========== SSL/TLS ==========

// OpenSSL executes an openssl command
func (e *Executor) OpenSSL(ctx context.Context, req *models.OpenSSLRequest) (*models.ToolResponse, error) {
	args := []string{}

	command := req.Command
	if command == "" {
		command = "s_client"
	}
	args = append(args, sanitizeArg(command))

	if command == "s_client" && req.Host != "" {
		port := req.Port
		if port <= 0 {
			port = 443
		}
		args = append(args, "-connect", fmt.Sprintf("%s:%d", sanitizeArg(req.Host), port))
		args = append(args, "-servername", sanitizeArg(req.Host))
		args = append(args, "-brief") // Use brief output instead of redirecting stdin
	}

	return e.Execute(ctx, "openssl", args...)
}

// ========== SNMP ==========

// SNMPGet executes an snmpget command
func (e *Executor) SNMPGet(ctx context.Context, req *models.SNMPRequest) (*models.ToolResponse, error) {
	version := req.Version
	if version == "" {
		version = "2c"
	}

	community := req.Community
	if community == "" {
		community = "public"
	}

	oid := req.OID
	if oid == "" {
		oid = "system"
	}

	args := []string{
		"-v", sanitizeArg(version),
		"-c", sanitizeArg(community),
		sanitizeArg(req.Host),
		sanitizeArg(oid),
	}

	return e.Execute(ctx, "snmpget", args...)
}

// SNMPWalk executes an snmpwalk command
func (e *Executor) SNMPWalk(ctx context.Context, req *models.SNMPRequest) (*models.ToolResponse, error) {
	version := req.Version
	if version == "" {
		version = "2c"
	}

	community := req.Community
	if community == "" {
		community = "public"
	}

	oid := req.OID
	if oid == "" {
		oid = "system"
	}

	args := []string{
		"-v", sanitizeArg(version),
		"-c", sanitizeArg(community),
		sanitizeArg(req.Host),
		sanitizeArg(oid),
	}

	return e.Execute(ctx, "snmpwalk", args...)
}

// ========== DHCP ==========

// DHCPing executes a dhcping command
func (e *Executor) DHCPing(ctx context.Context, req *models.DHCPingRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.Server != "" {
		args = append(args, "-s", sanitizeArg(req.Server))
	}

	if req.Interface != "" {
		args = append(args, "-i", sanitizeArg(req.Interface))
	}

	return e.Execute(ctx, "dhcping", args...)
}

// ========== Email (SMTP) ==========

// Swaks executes a swaks SMTP test
func (e *Executor) Swaks(ctx context.Context, req *models.SwaksRequest) (*models.ToolResponse, error) {
	args := []string{"--server", sanitizeArg(req.Server)}

	if req.Port > 0 && req.Port <= 65535 {
		args = append(args, "--port", fmt.Sprintf("%d", req.Port))
	}

	if req.From != "" {
		args = append(args, "--from", sanitizeArg(req.From))
	}

	if req.To != "" {
		args = append(args, "--to", sanitizeArg(req.To))
	}

	if req.TLS {
		args = append(args, "--tls")
	}

	return e.Execute(ctx, "swaks", args...)
}

// ========== Container Tools ==========

// Calicoctl executes a calicoctl command
func (e *Executor) Calicoctl(ctx context.Context, req *models.CalicoctlRequest) (*models.ToolResponse, error) {
	args := []string{sanitizeArg(req.Command)}

	if req.Resource != "" {
		args = append(args, sanitizeArg(req.Resource))
	}

	if req.Name != "" {
		args = append(args, sanitizeArg(req.Name))
	}

	return e.Execute(ctx, "calicoctl", args...)
}

// ========== Traffic Monitoring ==========

// Iftop executes an iftop command (text mode)
func (e *Executor) Iftop(ctx context.Context, req *models.IftopRequest) (*models.ToolResponse, error) {
	args := []string{"-t", "-s", "5"} // Text mode, 5 seconds

	if req.Interface != "" {
		args = append(args, "-i", sanitizeArg(req.Interface))
	}

	if req.Duration > 0 && req.Duration <= 30 {
		args = append(args, "-s", fmt.Sprintf("%d", req.Duration))
	}

	return e.Execute(ctx, "iftop", args...)
}

// ========== Load Balancing ==========

// Ipvsadm executes an ipvsadm command
func (e *Executor) Ipvsadm(ctx context.Context, req *models.IpvsadmRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.List {
		args = append(args, "-L")
	} else {
		args = append(args, "-L")
	}

	if req.Numeric {
		args = append(args, "-n")
	}

	return e.Execute(ctx, "ipvsadm", args...)
}

// ========== Utility ==========

// Socat executes a socat command (limited for safety)
func (e *Executor) Socat(ctx context.Context, req *models.SocatRequest) (*models.ToolResponse, error) {
	args := []string{"-d", "-d", sanitizeArg(req.Address1), sanitizeArg(req.Address2)}
	return e.Execute(ctx, "socat", args...)
}

// File executes a file type detection
func (e *Executor) File(ctx context.Context, req *models.FileRequest) (*models.ToolResponse, error) {
	return e.Execute(ctx, "file", sanitizeArg(req.Path))
}

// Jq executes a jq JSON processing command
func (e *Executor) Jq(ctx context.Context, req *models.JqRequest) (*models.ToolResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	// Use jq directly with input from stdin via a string
	args := []string{sanitizeArg(req.Filter)}
	cmd := exec.CommandContext(ctx, "jq", args...)
	cmd.Stdin = strings.NewReader(req.Input)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	response := &models.ToolResponse{
		Tool:    "jq",
		Success: err == nil,
		Output:  stdout.String(),
	}

	if err != nil {
		response.Error = stderr.String()
		if exitError, ok := err.(*exec.ExitError); ok {
			response.ExitCode = exitError.ExitCode()
		} else {
			response.ExitCode = -1
		}
	}

	return response, nil
}

// Whois executes a whois lookup
func (e *Executor) Whois(ctx context.Context, req *models.WhoisRequest) (*models.ToolResponse, error) {
	return e.Execute(ctx, "whois", sanitizeArg(req.Domain))
}

// IPInfo returns IP information using curl to external service
func (e *Executor) IPInfo(ctx context.Context) (*models.ToolResponse, error) {
	return e.Execute(ctx, "curl", "-s", "https://ipinfo.io/json")
}

// ========== Routing Protocols ==========

// Bird executes a BIRD routing daemon command
func (e *Executor) Bird(ctx context.Context, req *models.BirdRequest) (*models.ToolResponse, error) {
	command := req.Command
	if command == "" {
		command = "show status"
	}
	return e.Execute(ctx, "birdc", sanitizeArg(command))
}

// ========== SSH ==========

// SSHKeyscan executes an ssh-keyscan command
func (e *Executor) SSHKeyscan(ctx context.Context, req *models.SSHKeyscanRequest) (*models.ToolResponse, error) {
	args := []string{}

	if req.Port > 0 && req.Port <= 65535 {
		args = append(args, "-p", fmt.Sprintf("%d", req.Port))
	}

	if req.Type != "" {
		args = append(args, "-t", sanitizeArg(req.Type))
	}

	args = append(args, sanitizeArg(req.Host))

	return e.Execute(ctx, "ssh-keyscan", args...)
}

// ========== Generic Command ==========

// Generic executes a generic command (with restrictions)
func (e *Executor) Generic(ctx context.Context, req *models.GenericRequest) (*models.ToolResponse, error) {
	// Whitelist of allowed commands
	allowedCommands := map[string]bool{
		"ping": true, "fping": true, "mtr": true, "traceroute": true, "tcptraceroute": true,
		"drill": true, "dig": true, "nslookup": true, "host": true,
		"nmap": true, "nping": true, "nc": true,
		"curl": true, "http": true, "ab": true, "fortio": true, "websocat": true, "grpcurl": true,
		"tcpdump": true, "tshark": true, "ngrep": true,
		"iperf": true, "iperf3": true, "speedtest-cli": true,
		"ip": true, "netstat": true, "ss": true, "ethtool": true, "bridge": true,
		"iptables": true, "nft": true, "ipset": true, "conntrack": true,
		"openssl": true, "snmpget": true, "snmpwalk": true, "dhcping": true, "swaks": true,
		"calicoctl": true, "iftop": true, "ipvsadm": true,
		"socat": true, "file": true, "jq": true, "whois": true, "birdc": true,
		"ssh-keyscan": true,
	}

	if !allowedCommands[req.Command] {
		return &models.ToolResponse{
			Tool:     req.Command,
			Success:  false,
			Error:    "Command not allowed",
			ExitCode: -1,
		}, nil
	}

	timeout := time.Duration(req.Timeout) * time.Second
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout > longTimeout {
		timeout = longTimeout
	}

	sanitizedArgs := make([]string, len(req.Args))
	for i, arg := range req.Args {
		sanitizedArgs[i] = sanitizeArg(arg)
	}

	return e.ExecuteWithTimeout(ctx, timeout, req.Command, sanitizedArgs...)
}

// GetAvailableTools returns a list of all available tools
func (e *Executor) GetAvailableTools() []models.ToolInfo {
	return []models.ToolInfo{
		// Network Diagnostics
		{Name: "ping", Description: "Send ICMP ECHO_REQUEST to network hosts", Usage: "POST /api/ping", Examples: []string{"ping -c 4 google.com"}, Category: "diagnostics"},
		{Name: "fping", Description: "Send ICMP ECHO_REQUEST to multiple hosts", Usage: "POST /api/fping", Examples: []string{"fping -c 3 host1 host2 host3"}, Category: "diagnostics"},
		{Name: "mtr", Description: "Network diagnostic tool combining ping and traceroute", Usage: "POST /api/mtr", Examples: []string{"mtr -r -c 10 google.com"}, Category: "diagnostics"},
		{Name: "traceroute", Description: "Print the route packets trace to network host", Usage: "POST /api/traceroute", Examples: []string{"traceroute google.com"}, Category: "diagnostics"},
		{Name: "tcptraceroute", Description: "TCP traceroute to bypass firewalls", Usage: "POST /api/tcptraceroute", Examples: []string{"tcptraceroute google.com 443"}, Category: "diagnostics"},
		{Name: "trippy", Description: "TUI network diagnostics tool", Usage: "POST /api/trippy", Examples: []string{"trip google.com"}, Category: "diagnostics"},

		// DNS Tools
		{Name: "drill", Description: "DNS lookup using drill (ldns)", Usage: "POST /api/dns", Examples: []string{"drill google.com", "drill MX google.com"}, Category: "dns"},
		{Name: "dig", Description: "DNS lookup using dig", Usage: "POST /api/dig", Examples: []string{"dig google.com", "dig @8.8.8.8 google.com MX"}, Category: "dns"},
		{Name: "nslookup", Description: "Query Internet name servers", Usage: "POST /api/nslookup", Examples: []string{"nslookup google.com"}, Category: "dns"},
		{Name: "host", Description: "DNS lookup utility", Usage: "POST /api/host", Examples: []string{"host google.com"}, Category: "dns"},

		// Port Scanning & Network Discovery
		{Name: "nmap", Description: "Network exploration and security auditing", Usage: "POST /api/nmap", Examples: []string{"nmap -p 80,443 google.com", "nmap -F google.com"}, Category: "scanning"},
		{Name: "nping", Description: "Network packet generation tool", Usage: "POST /api/nping", Examples: []string{"nping --tcp -p 80 google.com"}, Category: "scanning"},
		{Name: "netcat", Description: "TCP/UDP connection and listening tool", Usage: "POST /api/netcat", Examples: []string{"nc -vz google.com 80"}, Category: "scanning"},

		// HTTP/Web Tools
		{Name: "curl", Description: "Transfer data from or to a server", Usage: "POST /api/curl", Examples: []string{"curl -s https://google.com"}, Category: "http"},
		{Name: "httpie", Description: "User-friendly HTTP client", Usage: "POST /api/httpie", Examples: []string{"http GET https://httpbin.org/get"}, Category: "http"},
		{Name: "ab", Description: "Apache HTTP server benchmarking tool", Usage: "POST /api/ab", Examples: []string{"ab -n 100 -c 10 http://example.com/"}, Category: "http"},
		{Name: "fortio", Description: "Load testing library and command line tool", Usage: "POST /api/fortio", Examples: []string{"fortio load http://example.com"}, Category: "http"},
		{Name: "websocat", Description: "WebSocket client and server", Usage: "POST /api/websocat", Examples: []string{"websocat ws://echo.websocket.org"}, Category: "http"},
		{Name: "grpcurl", Description: "Command-line tool for gRPC servers", Usage: "POST /api/grpcurl", Examples: []string{"grpcurl -plaintext localhost:50051 list"}, Category: "http"},

		// Packet Capture & Analysis
		{Name: "tcpdump", Description: "Packet analyzer", Usage: "POST /api/tcpdump", Examples: []string{"tcpdump -i eth0 -c 10"}, Category: "capture"},
		{Name: "tshark", Description: "Network protocol analyzer", Usage: "POST /api/tshark", Examples: []string{"tshark -i eth0 -c 10"}, Category: "capture"},
		{Name: "ngrep", Description: "Network grep", Usage: "POST /api/ngrep", Examples: []string{"ngrep -q 'HTTP'"}, Category: "capture"},

		// Performance Testing
		{Name: "iperf", Description: "Network bandwidth testing", Usage: "POST /api/iperf", Examples: []string{"iperf -c server -t 10"}, Category: "performance"},
		{Name: "iperf3", Description: "Network bandwidth testing (v3)", Usage: "POST /api/iperf3", Examples: []string{"iperf3 -c server -t 10"}, Category: "performance"},
		{Name: "speedtest", Description: "Test internet bandwidth", Usage: "POST /api/speedtest", Examples: []string{"speedtest-cli --simple"}, Category: "performance"},

		// Network Configuration
		{Name: "ip-route", Description: "Show/manipulate routing table", Usage: "POST /api/ip/route", Examples: []string{"ip route show"}, Category: "config"},
		{Name: "ip-addr", Description: "Show/manipulate IP addresses", Usage: "POST /api/ip/addr", Examples: []string{"ip addr show"}, Category: "config"},
		{Name: "ip-link", Description: "Show/manipulate network devices", Usage: "POST /api/ip/link", Examples: []string{"ip link show"}, Category: "config"},
		{Name: "ip-neigh", Description: "Show/manipulate ARP table", Usage: "POST /api/ip/neigh", Examples: []string{"ip neigh show"}, Category: "config"},
		{Name: "netstat", Description: "Network statistics", Usage: "POST /api/netstat", Examples: []string{"netstat -tulpn"}, Category: "config"},
		{Name: "ss", Description: "Socket statistics", Usage: "POST /api/ss", Examples: []string{"ss -tulpn"}, Category: "config"},
		{Name: "ethtool", Description: "Query/control network driver settings", Usage: "POST /api/ethtool", Examples: []string{"ethtool eth0"}, Category: "config"},
		{Name: "bridge", Description: "Show/manipulate bridge addresses", Usage: "POST /api/bridge", Examples: []string{"bridge link show"}, Category: "config"},

		// Firewall & Security
		{Name: "iptables", Description: "Administration tool for IPv4 packet filtering", Usage: "POST /api/iptables", Examples: []string{"iptables -L -n"}, Category: "firewall"},
		{Name: "nftables", Description: "Netfilter tables", Usage: "POST /api/nftables", Examples: []string{"nft list ruleset"}, Category: "firewall"},
		{Name: "ipset", Description: "Administration tool for IP sets", Usage: "POST /api/ipset", Examples: []string{"ipset list"}, Category: "firewall"},
		{Name: "conntrack", Description: "Connection tracking", Usage: "POST /api/conntrack", Examples: []string{"conntrack -L"}, Category: "firewall"},

		// SSL/TLS
		{Name: "openssl", Description: "OpenSSL command line tool", Usage: "POST /api/openssl", Examples: []string{"openssl s_client -connect google.com:443"}, Category: "ssl"},

		// SNMP
		{Name: "snmpget", Description: "SNMP GET request", Usage: "POST /api/snmpget", Examples: []string{"snmpget -v2c -c public host system.sysDescr.0"}, Category: "snmp"},
		{Name: "snmpwalk", Description: "SNMP WALK request", Usage: "POST /api/snmpwalk", Examples: []string{"snmpwalk -v2c -c public host system"}, Category: "snmp"},

		// DHCP
		{Name: "dhcping", Description: "DHCP server test", Usage: "POST /api/dhcping", Examples: []string{"dhcping -s 192.168.1.1"}, Category: "dhcp"},

		// Email (SMTP)
		{Name: "swaks", Description: "Swiss Army Knife for SMTP", Usage: "POST /api/swaks", Examples: []string{"swaks --to user@example.com --server mail.example.com"}, Category: "email"},

		// Container Tools
		{Name: "calicoctl", Description: "Calico CLI tool", Usage: "POST /api/calicoctl", Examples: []string{"calicoctl get nodes"}, Category: "container"},

		// Traffic Monitoring
		{Name: "iftop", Description: "Display bandwidth usage on an interface", Usage: "POST /api/iftop", Examples: []string{"iftop -t -s 5"}, Category: "monitoring"},

		// Load Balancing
		{Name: "ipvsadm", Description: "IPVS administration tool", Usage: "POST /api/ipvsadm", Examples: []string{"ipvsadm -L -n"}, Category: "loadbalancing"},

		// Utility
		{Name: "socat", Description: "Multipurpose relay", Usage: "POST /api/socat", Examples: []string{"socat TCP:localhost:80 -"}, Category: "utility"},
		{Name: "file", Description: "Determine file type", Usage: "POST /api/file", Examples: []string{"file /etc/passwd"}, Category: "utility"},
		{Name: "jq", Description: "Command-line JSON processor", Usage: "POST /api/jq", Examples: []string{"echo '{\"a\":1}' | jq '.a'"}, Category: "utility"},
		{Name: "whois", Description: "Domain registration lookup", Usage: "POST /api/whois", Examples: []string{"whois google.com"}, Category: "utility"},

		// Routing Protocols
		{Name: "bird", Description: "BIRD routing daemon CLI", Usage: "POST /api/bird", Examples: []string{"birdc show status"}, Category: "routing"},

		// SSH
		{Name: "ssh-keyscan", Description: "Gather SSH public keys", Usage: "POST /api/ssh-keyscan", Examples: []string{"ssh-keyscan github.com"}, Category: "ssh"},

		// IP Info
		{Name: "ipinfo", Description: "Get public IP information", Usage: "GET /api/ipinfo", Examples: []string{"curl ipinfo.io/json"}, Category: "utility"},

		// Generic Command
		{Name: "generic", Description: "Execute any whitelisted command", Usage: "POST /api/exec", Examples: []string{"curl -s google.com"}, Category: "utility"},
	}
}
