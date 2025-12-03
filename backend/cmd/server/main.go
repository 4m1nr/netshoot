package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nicolaka/netshoot/backend/internal/handlers"
	"github.com/nicolaka/netshoot/backend/internal/middleware"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	h := handlers.NewHandler()

	// Create rate limiter: 100 requests per minute per IP
	rateLimiter := middleware.NewRateLimiter(100, time.Minute)

	// Create router
	mux := http.NewServeMux()

	// Health and info endpoints
	mux.HandleFunc("GET /api/health", h.Health)
	mux.HandleFunc("GET /api/tools", h.GetTools)

	// Network Diagnostics
	mux.HandleFunc("POST /api/ping", h.Ping)
	mux.HandleFunc("POST /api/fping", h.Fping)
	mux.HandleFunc("POST /api/mtr", h.MTR)
	mux.HandleFunc("POST /api/traceroute", h.Traceroute)
	mux.HandleFunc("POST /api/tcptraceroute", h.TCPTraceroute)
	mux.HandleFunc("POST /api/trippy", h.Trippy)

	// DNS Tools
	mux.HandleFunc("POST /api/dns", h.DNS)
	mux.HandleFunc("POST /api/drill", h.DNS) // Alias
	mux.HandleFunc("POST /api/dig", h.Dig)
	mux.HandleFunc("POST /api/nslookup", h.Nslookup)
	mux.HandleFunc("POST /api/host", h.Host)

	// Port Scanning & Network Discovery
	mux.HandleFunc("POST /api/nmap", h.Nmap)
	mux.HandleFunc("POST /api/nping", h.Nping)
	mux.HandleFunc("POST /api/netcat", h.Netcat)
	mux.HandleFunc("POST /api/nc", h.Netcat) // Alias

	// HTTP/Web Tools
	mux.HandleFunc("POST /api/curl", h.Curl)
	mux.HandleFunc("POST /api/httpie", h.HTTPie)
	mux.HandleFunc("POST /api/http", h.HTTPie) // Alias
	mux.HandleFunc("POST /api/ab", h.Ab)
	mux.HandleFunc("POST /api/fortio", h.Fortio)
	mux.HandleFunc("POST /api/websocat", h.Websocat)
	mux.HandleFunc("POST /api/grpcurl", h.Grpcurl)

	// Packet Capture & Analysis
	mux.HandleFunc("POST /api/tcpdump", h.Tcpdump)
	mux.HandleFunc("POST /api/tshark", h.Tshark)
	mux.HandleFunc("POST /api/ngrep", h.Ngrep)

	// Performance Testing
	mux.HandleFunc("POST /api/iperf", h.IPerf)
	mux.HandleFunc("POST /api/iperf3", h.IPerf3)
	mux.HandleFunc("POST /api/speedtest", h.SpeedTest)

	// Network Configuration
	mux.HandleFunc("POST /api/ip/route", h.IPRoute)
	mux.HandleFunc("POST /api/ip/addr", h.IPAddr)
	mux.HandleFunc("POST /api/ip/link", h.IPLink)
	mux.HandleFunc("POST /api/ip/neigh", h.IPNeigh)
	mux.HandleFunc("POST /api/netstat", h.Netstat)
	mux.HandleFunc("POST /api/ss", h.SS)
	mux.HandleFunc("POST /api/ethtool", h.Ethtool)
	mux.HandleFunc("POST /api/bridge", h.Bridge)

	// Firewall & Security
	mux.HandleFunc("POST /api/iptables", h.Iptables)
	mux.HandleFunc("POST /api/nftables", h.Nftables)
	mux.HandleFunc("POST /api/nft", h.Nftables) // Alias
	mux.HandleFunc("POST /api/ipset", h.Ipset)
	mux.HandleFunc("POST /api/conntrack", h.Conntrack)

	// SSL/TLS
	mux.HandleFunc("POST /api/openssl", h.OpenSSL)

	// SNMP
	mux.HandleFunc("POST /api/snmpget", h.SNMPGet)
	mux.HandleFunc("POST /api/snmpwalk", h.SNMPWalk)

	// DHCP
	mux.HandleFunc("POST /api/dhcping", h.DHCPing)

	// Email (SMTP)
	mux.HandleFunc("POST /api/swaks", h.Swaks)

	// Container Tools
	mux.HandleFunc("POST /api/calicoctl", h.Calicoctl)

	// Traffic Monitoring
	mux.HandleFunc("POST /api/iftop", h.Iftop)

	// Load Balancing
	mux.HandleFunc("POST /api/ipvsadm", h.Ipvsadm)

	// Utility
	mux.HandleFunc("POST /api/socat", h.Socat)
	mux.HandleFunc("POST /api/file", h.File)
	mux.HandleFunc("POST /api/jq", h.Jq)
	mux.HandleFunc("POST /api/whois", h.Whois)
	mux.HandleFunc("GET /api/ipinfo", h.IPInfo)

	// Routing Protocols
	mux.HandleFunc("POST /api/bird", h.Bird)
	mux.HandleFunc("POST /api/birdc", h.Bird) // Alias

	// SSH
	mux.HandleFunc("POST /api/ssh-keyscan", h.SSHKeyscan)

	// Generic Command Execution
	mux.HandleFunc("POST /api/exec", h.Exec)

	// Apply middleware
	handler := middleware.Logger(
		middleware.CORS(
			rateLimiter.Middleware(mux),
		),
	)

	// Start server
	addr := fmt.Sprintf(":%s", port)
	log.Printf("Netshoot API server starting on %s", addr)
	log.Printf("Available endpoints: GET /api/health, GET /api/tools")

	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
