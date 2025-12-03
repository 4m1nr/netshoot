package models

// ToolRequest represents a generic request to execute a networking tool
type ToolRequest struct {
	Tool    string            `json:"tool"`
	Args    []string          `json:"args,omitempty"`
	Options map[string]string `json:"options,omitempty"`
	Target  string            `json:"target,omitempty"`
}

// ToolResponse represents the response from a tool execution
type ToolResponse struct {
	Tool     string `json:"tool"`
	Success  bool   `json:"success"`
	Output   string `json:"output"`
	Error    string `json:"error,omitempty"`
	ExitCode int    `json:"exit_code"`
}

// ToolInfo represents information about an available tool
type ToolInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Usage       string   `json:"usage"`
	Examples    []string `json:"examples"`
	Category    string   `json:"category"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string   `json:"status"`
	Version   string   `json:"version"`
	Tools     []string `json:"tools"`
}

// ========== Network Diagnostics ==========

// PingRequest represents a ping request
type PingRequest struct {
	Host  string `json:"host"`
	Count int    `json:"count,omitempty"`
}

// FpingRequest represents an fping request (for multiple hosts)
type FpingRequest struct {
	Hosts []string `json:"hosts"`
	Count int      `json:"count,omitempty"`
}

// MTRRequest represents an MTR request
type MTRRequest struct {
	Host       string `json:"host"`
	ReportMode bool   `json:"report_mode,omitempty"`
	Count      int    `json:"count,omitempty"`
}

// TracerouteRequest represents a traceroute request
type TracerouteRequest struct {
	Host    string `json:"host"`
	MaxHops int    `json:"max_hops,omitempty"`
}

// TCPTracerouteRequest represents a TCP traceroute request
type TCPTracerouteRequest struct {
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
}

// TrippyRequest represents a trippy (TUI traceroute) request
type TrippyRequest struct {
	Host string `json:"host"`
}

// ========== DNS Tools ==========

// DNSRequest represents a DNS lookup request (using drill)
type DNSRequest struct {
	Host   string `json:"host"`
	Type   string `json:"type,omitempty"` // A, AAAA, MX, NS, etc.
	Server string `json:"server,omitempty"`
}

// DigRequest represents a dig request (bind-tools)
type DigRequest struct {
	Host   string `json:"host"`
	Type   string `json:"type,omitempty"`
	Server string `json:"server,omitempty"`
}

// NslookupRequest represents an nslookup request
type NslookupRequest struct {
	Host   string `json:"host"`
	Server string `json:"server,omitempty"`
}

// HostRequest represents a host command request
type HostRequest struct {
	Host   string `json:"host"`
	Server string `json:"server,omitempty"`
}

// ========== Port Scanning & Network Discovery ==========

// NmapRequest represents an nmap request
type NmapRequest struct {
	Host       string `json:"host"`
	Ports      string `json:"ports,omitempty"`
	ScanType   string `json:"scan_type,omitempty"` // -sT, -sS, -sU, etc.
	Scripts    string `json:"scripts,omitempty"`
	Verbose    bool   `json:"verbose,omitempty"`
	FastScan   bool   `json:"fast_scan,omitempty"`
}

// NpingRequest represents an nping request
type NpingRequest struct {
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // tcp, udp, icmp
	Count    int    `json:"count,omitempty"`
}

// NetcatRequest represents a netcat request
type NetcatRequest struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	UDP     bool   `json:"udp,omitempty"`
	Verbose bool   `json:"verbose,omitempty"`
	Zero    bool   `json:"zero,omitempty"` // Zero-I/O mode (scanning)
}

// ========== HTTP/Web Tools ==========

// CurlRequest represents a curl request
type CurlRequest struct {
	URL         string            `json:"url"`
	Method      string            `json:"method,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	FollowRedirect bool           `json:"follow_redirect,omitempty"`
	Insecure    bool              `json:"insecure,omitempty"`
	Verbose     bool              `json:"verbose,omitempty"`
}

// HTTPieRequest represents an HTTPie request
type HTTPieRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Data    map[string]string `json:"data,omitempty"`
	JSON    bool              `json:"json,omitempty"`
}

// AbRequest represents an Apache Benchmark request
type AbRequest struct {
	URL         string `json:"url"`
	Requests    int    `json:"requests,omitempty"`
	Concurrency int    `json:"concurrency,omitempty"`
}

// FortioRequest represents a Fortio load testing request
type FortioRequest struct {
	URL         string `json:"url"`
	Connections int    `json:"connections,omitempty"`
	Duration    string `json:"duration,omitempty"`
	QPS         int    `json:"qps,omitempty"`
}

// WebsocatRequest represents a websocat request
type WebsocatRequest struct {
	URL string `json:"url"`
}

// GrpcurlRequest represents a grpcurl request
type GrpcurlRequest struct {
	Server    string `json:"server"`
	Service   string `json:"service,omitempty"`
	Method    string `json:"method,omitempty"`
	Plaintext bool   `json:"plaintext,omitempty"`
	Data      string `json:"data,omitempty"`
}

// ========== Packet Capture & Analysis ==========

// TcpdumpRequest represents a tcpdump request
type TcpdumpRequest struct {
	Interface string `json:"interface,omitempty"`
	Filter    string `json:"filter,omitempty"`
	Count     int    `json:"count,omitempty"`
	Verbose   bool   `json:"verbose,omitempty"`
}

// TsharkRequest represents a tshark request
type TsharkRequest struct {
	Interface string `json:"interface,omitempty"`
	Filter    string `json:"filter,omitempty"`
	Count     int    `json:"count,omitempty"`
	Fields    string `json:"fields,omitempty"`
}

// NgrepRequest represents an ngrep request
type NgrepRequest struct {
	Interface string `json:"interface,omitempty"`
	Pattern   string `json:"pattern,omitempty"`
	Filter    string `json:"filter,omitempty"`
}

// ========== Performance Testing ==========

// IPerfRequest represents an iperf request
type IPerfRequest struct {
	Server   string `json:"server"`
	Port     int    `json:"port,omitempty"`
	Duration int    `json:"duration,omitempty"`
	Reverse  bool   `json:"reverse,omitempty"`
	UDP      bool   `json:"udp,omitempty"`
}

// IPerf3Request represents an iperf3 request
type IPerf3Request struct {
	Server   string `json:"server"`
	Port     int    `json:"port,omitempty"`
	Duration int    `json:"duration,omitempty"`
	Reverse  bool   `json:"reverse,omitempty"`
	UDP      bool   `json:"udp,omitempty"`
	JSON     bool   `json:"json,omitempty"`
}

// SpeedTestRequest represents a speedtest request
type SpeedTestRequest struct {
	ServerID int  `json:"server_id,omitempty"`
	Simple   bool `json:"simple,omitempty"`
}

// ========== Network Configuration ==========

// IPRouteRequest represents an ip route request
type IPRouteRequest struct {
	Action string `json:"action,omitempty"` // show, get
	Target string `json:"target,omitempty"`
}

// IPAddrRequest represents an ip addr request
type IPAddrRequest struct {
	Interface string `json:"interface,omitempty"`
}

// IPLinkRequest represents an ip link request
type IPLinkRequest struct {
	Interface string `json:"interface,omitempty"`
}

// IPNeighRequest represents an ip neigh request (ARP table)
type IPNeighRequest struct {
	Interface string `json:"interface,omitempty"`
}

// NetstatRequest represents a netstat request
type NetstatRequest struct {
	Listening bool `json:"listening,omitempty"`
	TCP       bool `json:"tcp,omitempty"`
	UDP       bool `json:"udp,omitempty"`
	Numeric   bool `json:"numeric,omitempty"`
	Programs  bool `json:"programs,omitempty"`
}

// SSRequest represents an ss (socket statistics) request
type SSRequest struct {
	Listening bool   `json:"listening,omitempty"`
	TCP       bool   `json:"tcp,omitempty"`
	UDP       bool   `json:"udp,omitempty"`
	Processes bool   `json:"processes,omitempty"`
	State     string `json:"state,omitempty"`
}

// EthtoolRequest represents an ethtool request
type EthtoolRequest struct {
	Interface string `json:"interface"`
	Stats     bool   `json:"stats,omitempty"`
}

// BridgeRequest represents a bridge command request
type BridgeRequest struct {
	Command string `json:"command,omitempty"` // link, fdb, mdb, vlan
}

// ========== Firewall & Security ==========

// IptablesRequest represents an iptables request
type IptablesRequest struct {
	Table   string `json:"table,omitempty"` // filter, nat, mangle, raw
	List    bool   `json:"list,omitempty"`
	Numeric bool   `json:"numeric,omitempty"`
	Verbose bool   `json:"verbose,omitempty"`
}

// NftablesRequest represents an nftables request
type NftablesRequest struct {
	Command string `json:"command,omitempty"` // list, add, delete
	Table   string `json:"table,omitempty"`
}

// IpsetRequest represents an ipset request
type IpsetRequest struct {
	Command string `json:"command,omitempty"` // list, test
	SetName string `json:"set_name,omitempty"`
}

// ConntrackRequest represents a conntrack request
type ConntrackRequest struct {
	List     bool   `json:"list,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Source   string `json:"source,omitempty"`
}

// ========== SSL/TLS ==========

// OpenSSLRequest represents an openssl request
type OpenSSLRequest struct {
	Command string `json:"command"` // s_client, x509, etc.
	Host    string `json:"host,omitempty"`
	Port    int    `json:"port,omitempty"`
}

// ========== SNMP ==========

// SNMPRequest represents an SNMP request
type SNMPRequest struct {
	Host      string `json:"host"`
	Community string `json:"community,omitempty"`
	OID       string `json:"oid,omitempty"`
	Version   string `json:"version,omitempty"` // 1, 2c, 3
}

// ========== DHCP ==========

// DHCPingRequest represents a dhcping request
type DHCPingRequest struct {
	Server    string `json:"server,omitempty"`
	Interface string `json:"interface,omitempty"`
}

// ========== Email (SMTP) ==========

// SwaksRequest represents a swaks (SMTP test) request
type SwaksRequest struct {
	Server string `json:"server"`
	Port   int    `json:"port,omitempty"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	TLS    bool   `json:"tls,omitempty"`
}

// ========== Container Tools ==========

// CtopRequest represents a ctop request (container monitoring)
type CtopRequest struct {
	// ctop is interactive, so we just check if it's available
}

// CalicoctlRequest represents a calicoctl request
type CalicoctlRequest struct {
	Command  string `json:"command"` // get, describe, etc.
	Resource string `json:"resource,omitempty"`
	Name     string `json:"name,omitempty"`
}

// ========== Traffic Monitoring ==========

// IftopRequest represents an iftop request
type IftopRequest struct {
	Interface string `json:"interface,omitempty"`
	Duration  int    `json:"duration,omitempty"` // seconds to run
}

// IptrafRequest represents an iptraf-ng request
type IptrafRequest struct {
	Interface string `json:"interface,omitempty"`
}

// ========== Load Balancing ==========

// IpvsadmRequest represents an ipvsadm request
type IpvsadmRequest struct {
	List    bool `json:"list,omitempty"`
	Numeric bool `json:"numeric,omitempty"`
}

// ========== Debugging ==========

// StraceRequest represents a strace request
type StraceRequest struct {
	Command string `json:"command"`
	Args    []string `json:"args,omitempty"`
}

// LtraceRequest represents an ltrace request
type LtraceRequest struct {
	Command string `json:"command"`
	Args    []string `json:"args,omitempty"`
}

// ========== Utility ==========

// SocatRequest represents a socat request
type SocatRequest struct {
	Address1 string `json:"address1"`
	Address2 string `json:"address2"`
}

// FileRequest represents a file type detection request
type FileRequest struct {
	Path string `json:"path"`
}

// JqRequest represents a jq JSON processing request
type JqRequest struct {
	Filter string `json:"filter"`
	Input  string `json:"input"`
}

// WhoisRequest represents a whois request
type WhoisRequest struct {
	Domain string `json:"domain"`
}

// ========== Routing Protocols ==========

// BirdRequest represents a BIRD routing daemon request
type BirdRequest struct {
	Command string `json:"command"` // show route, show protocols, etc.
}

// ========== Namespace Tools ==========

// NsenterRequest represents an nsenter request
type NsenterRequest struct {
	Target    string `json:"target"`     // PID or namespace path
	Namespace string `json:"namespace"`  // net, mnt, pid, etc.
	Command   string `json:"command"`
}

// ========== SSH ==========

// SSHRequest represents an SSH request (for testing connectivity)
type SSHRequest struct {
	Host       string `json:"host"`
	Port       int    `json:"port,omitempty"`
	User       string `json:"user,omitempty"`
	Command    string `json:"command,omitempty"`
	KeyCheck   bool   `json:"key_check,omitempty"`
}

// SSHKeyscanRequest represents an ssh-keyscan request
type SSHKeyscanRequest struct {
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
	Type string `json:"type,omitempty"` // rsa, dsa, ecdsa, ed25519
}

// ========== Generic Command ==========

// GenericRequest represents a generic command execution request
type GenericRequest struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Timeout int      `json:"timeout,omitempty"` // seconds
}
