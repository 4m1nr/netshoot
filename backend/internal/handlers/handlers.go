package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/nicolaka/netshoot/backend/internal/tools"
	"github.com/nicolaka/netshoot/backend/pkg/models"
)

// Handler handles HTTP requests for the netshoot API
type Handler struct {
	executor *tools.Executor
}

// NewHandler creates a new handler
func NewHandler() *Handler {
	return &Handler{
		executor: tools.NewExecutor(),
	}
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error response
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// Health returns the health status
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	tools := h.executor.GetAvailableTools()
	toolNames := make([]string, len(tools))
	for i, t := range tools {
		toolNames[i] = t.Name
	}

	writeJSON(w, http.StatusOK, models.HealthResponse{
		Status:  "healthy",
		Version: "1.0.0",
		Tools:   toolNames,
	})
}

// GetTools returns the list of available tools
func (h *Handler) GetTools(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.executor.GetAvailableTools())
}

// ========== Network Diagnostics ==========

// Ping handles ping requests
func (h *Handler) Ping(w http.ResponseWriter, r *http.Request) {
	var req models.PingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "Host is required")
		return
	}

	resp, err := h.executor.Ping(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Fping handles fping requests
func (h *Handler) Fping(w http.ResponseWriter, r *http.Request) {
	var req models.FpingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if len(req.Hosts) == 0 {
		writeError(w, http.StatusBadRequest, "At least one host is required")
		return
	}

	resp, err := h.executor.Fping(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// MTR handles mtr requests
func (h *Handler) MTR(w http.ResponseWriter, r *http.Request) {
	var req models.MTRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "Host is required")
		return
	}

	resp, err := h.executor.MTR(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Traceroute handles traceroute requests
func (h *Handler) Traceroute(w http.ResponseWriter, r *http.Request) {
	var req models.TracerouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "Host is required")
		return
	}

	resp, err := h.executor.Traceroute(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// TCPTraceroute handles TCP traceroute requests
func (h *Handler) TCPTraceroute(w http.ResponseWriter, r *http.Request) {
	var req models.TCPTracerouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "Host is required")
		return
	}

	resp, err := h.executor.TCPTraceroute(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Trippy handles trippy requests
func (h *Handler) Trippy(w http.ResponseWriter, r *http.Request) {
	var req models.TrippyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "Host is required")
		return
	}

	resp, err := h.executor.Trippy(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== DNS Tools ==========

// DNS handles DNS lookup requests using drill
func (h *Handler) DNS(w http.ResponseWriter, r *http.Request) {
	var req models.DNSRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "Host is required")
		return
	}

	resp, err := h.executor.DNSLookup(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Dig handles dig requests
func (h *Handler) Dig(w http.ResponseWriter, r *http.Request) {
	var req models.DigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "Host is required")
		return
	}

	resp, err := h.executor.Dig(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Nslookup handles nslookup requests
func (h *Handler) Nslookup(w http.ResponseWriter, r *http.Request) {
	var req models.NslookupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "Host is required")
		return
	}

	resp, err := h.executor.Nslookup(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Host handles host command requests
func (h *Handler) Host(w http.ResponseWriter, r *http.Request) {
	var req models.HostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "Host is required")
		return
	}

	resp, err := h.executor.Host(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== Port Scanning & Network Discovery ==========

// Nmap handles nmap requests
func (h *Handler) Nmap(w http.ResponseWriter, r *http.Request) {
	var req models.NmapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "Host is required")
		return
	}

	resp, err := h.executor.Nmap(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Nping handles nping requests
func (h *Handler) Nping(w http.ResponseWriter, r *http.Request) {
	var req models.NpingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "Host is required")
		return
	}

	resp, err := h.executor.Nping(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Netcat handles netcat requests
func (h *Handler) Netcat(w http.ResponseWriter, r *http.Request) {
	var req models.NetcatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "Host is required")
		return
	}

	resp, err := h.executor.Netcat(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== HTTP/Web Tools ==========

// Curl handles curl requests
func (h *Handler) Curl(w http.ResponseWriter, r *http.Request) {
	var req models.CurlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, "URL is required")
		return
	}

	resp, err := h.executor.Curl(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// HTTPie handles HTTPie requests
func (h *Handler) HTTPie(w http.ResponseWriter, r *http.Request) {
	var req models.HTTPieRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, "URL is required")
		return
	}

	resp, err := h.executor.HTTPie(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Ab handles Apache Benchmark requests
func (h *Handler) Ab(w http.ResponseWriter, r *http.Request) {
	var req models.AbRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, "URL is required")
		return
	}

	resp, err := h.executor.Ab(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Fortio handles Fortio requests
func (h *Handler) Fortio(w http.ResponseWriter, r *http.Request) {
	var req models.FortioRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, "URL is required")
		return
	}

	resp, err := h.executor.Fortio(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Websocat handles websocat requests
func (h *Handler) Websocat(w http.ResponseWriter, r *http.Request) {
	var req models.WebsocatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, "URL is required")
		return
	}

	resp, err := h.executor.Websocat(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Grpcurl handles grpcurl requests
func (h *Handler) Grpcurl(w http.ResponseWriter, r *http.Request) {
	var req models.GrpcurlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Server == "" {
		writeError(w, http.StatusBadRequest, "Server is required")
		return
	}

	resp, err := h.executor.Grpcurl(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== Packet Capture & Analysis ==========

// Tcpdump handles tcpdump requests
func (h *Handler) Tcpdump(w http.ResponseWriter, r *http.Request) {
	var req models.TcpdumpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.Tcpdump(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Tshark handles tshark requests
func (h *Handler) Tshark(w http.ResponseWriter, r *http.Request) {
	var req models.TsharkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.Tshark(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Ngrep handles ngrep requests
func (h *Handler) Ngrep(w http.ResponseWriter, r *http.Request) {
	var req models.NgrepRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.Ngrep(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== Performance Testing ==========

// IPerf handles iperf requests
func (h *Handler) IPerf(w http.ResponseWriter, r *http.Request) {
	var req models.IPerfRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Server == "" {
		writeError(w, http.StatusBadRequest, "Server is required")
		return
	}

	resp, err := h.executor.IPerf(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// IPerf3 handles iperf3 requests
func (h *Handler) IPerf3(w http.ResponseWriter, r *http.Request) {
	var req models.IPerf3Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Server == "" {
		writeError(w, http.StatusBadRequest, "Server is required")
		return
	}

	resp, err := h.executor.IPerf3(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// SpeedTest handles speedtest requests
func (h *Handler) SpeedTest(w http.ResponseWriter, r *http.Request) {
	var req models.SpeedTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.SpeedTest(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== Network Configuration ==========

// IPRoute handles ip route requests
func (h *Handler) IPRoute(w http.ResponseWriter, r *http.Request) {
	var req models.IPRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.IPRoute(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// IPAddr handles ip addr requests
func (h *Handler) IPAddr(w http.ResponseWriter, r *http.Request) {
	var req models.IPAddrRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.IPAddr(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// IPLink handles ip link requests
func (h *Handler) IPLink(w http.ResponseWriter, r *http.Request) {
	var req models.IPLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.IPLink(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// IPNeigh handles ip neigh requests
func (h *Handler) IPNeigh(w http.ResponseWriter, r *http.Request) {
	var req models.IPNeighRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.IPNeigh(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Netstat handles netstat requests
func (h *Handler) Netstat(w http.ResponseWriter, r *http.Request) {
	var req models.NetstatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.Netstat(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// SS handles ss requests
func (h *Handler) SS(w http.ResponseWriter, r *http.Request) {
	var req models.SSRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.SS(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Ethtool handles ethtool requests
func (h *Handler) Ethtool(w http.ResponseWriter, r *http.Request) {
	var req models.EthtoolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Interface == "" {
		writeError(w, http.StatusBadRequest, "Interface is required")
		return
	}

	resp, err := h.executor.Ethtool(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Bridge handles bridge command requests
func (h *Handler) Bridge(w http.ResponseWriter, r *http.Request) {
	var req models.BridgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.Bridge(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== Firewall & Security ==========

// Iptables handles iptables requests
func (h *Handler) Iptables(w http.ResponseWriter, r *http.Request) {
	var req models.IptablesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.Iptables(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Nftables handles nftables requests
func (h *Handler) Nftables(w http.ResponseWriter, r *http.Request) {
	var req models.NftablesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.Nftables(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Ipset handles ipset requests
func (h *Handler) Ipset(w http.ResponseWriter, r *http.Request) {
	var req models.IpsetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.Ipset(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Conntrack handles conntrack requests
func (h *Handler) Conntrack(w http.ResponseWriter, r *http.Request) {
	var req models.ConntrackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.Conntrack(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== SSL/TLS ==========

// OpenSSL handles openssl requests
func (h *Handler) OpenSSL(w http.ResponseWriter, r *http.Request) {
	var req models.OpenSSLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.OpenSSL(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== SNMP ==========

// SNMPGet handles snmpget requests
func (h *Handler) SNMPGet(w http.ResponseWriter, r *http.Request) {
	var req models.SNMPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "Host is required")
		return
	}

	resp, err := h.executor.SNMPGet(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// SNMPWalk handles snmpwalk requests
func (h *Handler) SNMPWalk(w http.ResponseWriter, r *http.Request) {
	var req models.SNMPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "Host is required")
		return
	}

	resp, err := h.executor.SNMPWalk(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== DHCP ==========

// DHCPing handles dhcping requests
func (h *Handler) DHCPing(w http.ResponseWriter, r *http.Request) {
	var req models.DHCPingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.DHCPing(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== Email (SMTP) ==========

// Swaks handles swaks requests
func (h *Handler) Swaks(w http.ResponseWriter, r *http.Request) {
	var req models.SwaksRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Server == "" {
		writeError(w, http.StatusBadRequest, "Server is required")
		return
	}

	resp, err := h.executor.Swaks(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== Container Tools ==========

// Calicoctl handles calicoctl requests
func (h *Handler) Calicoctl(w http.ResponseWriter, r *http.Request) {
	var req models.CalicoctlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Command == "" {
		writeError(w, http.StatusBadRequest, "Command is required")
		return
	}

	resp, err := h.executor.Calicoctl(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== Traffic Monitoring ==========

// Iftop handles iftop requests
func (h *Handler) Iftop(w http.ResponseWriter, r *http.Request) {
	var req models.IftopRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.Iftop(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== Load Balancing ==========

// Ipvsadm handles ipvsadm requests
func (h *Handler) Ipvsadm(w http.ResponseWriter, r *http.Request) {
	var req models.IpvsadmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.Ipvsadm(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== Utility ==========

// Socat handles socat requests
func (h *Handler) Socat(w http.ResponseWriter, r *http.Request) {
	var req models.SocatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Address1 == "" || req.Address2 == "" {
		writeError(w, http.StatusBadRequest, "Both addresses are required")
		return
	}

	resp, err := h.executor.Socat(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// File handles file type detection requests
func (h *Handler) File(w http.ResponseWriter, r *http.Request) {
	var req models.FileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Path == "" {
		writeError(w, http.StatusBadRequest, "Path is required")
		return
	}

	resp, err := h.executor.File(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Jq handles jq requests
func (h *Handler) Jq(w http.ResponseWriter, r *http.Request) {
	var req models.JqRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Filter == "" {
		writeError(w, http.StatusBadRequest, "Filter is required")
		return
	}

	resp, err := h.executor.Jq(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Whois handles whois requests
func (h *Handler) Whois(w http.ResponseWriter, r *http.Request) {
	var req models.WhoisRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Domain == "" {
		writeError(w, http.StatusBadRequest, "Domain is required")
		return
	}

	resp, err := h.executor.Whois(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// IPInfo handles IP info requests
func (h *Handler) IPInfo(w http.ResponseWriter, r *http.Request) {
	resp, err := h.executor.IPInfo(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== Routing Protocols ==========

// Bird handles BIRD routing requests
func (h *Handler) Bird(w http.ResponseWriter, r *http.Request) {
	var req models.BirdRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	resp, err := h.executor.Bird(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== SSH ==========

// SSHKeyscan handles ssh-keyscan requests
func (h *Handler) SSHKeyscan(w http.ResponseWriter, r *http.Request) {
	var req models.SSHKeyscanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "Host is required")
		return
	}

	resp, err := h.executor.SSHKeyscan(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ========== Generic Command ==========

// Exec handles generic command execution
func (h *Handler) Exec(w http.ResponseWriter, r *http.Request) {
	var req models.GenericRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Command == "" {
		writeError(w, http.StatusBadRequest, "Command is required")
		return
	}

	resp, err := h.executor.Generic(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
