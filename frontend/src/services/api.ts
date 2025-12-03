import { ToolResponse, ToolInfo, HealthResponse } from '../types';

const API_BASE_URL = process.env.EXPO_PUBLIC_API_URL || '';

class ApiService {
  private baseUrl: string;

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl;
  }

  setBaseUrl(url: string) {
    this.baseUrl = url;
  }

  getBaseUrl(): string {
    return this.baseUrl;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Request failed' }));
      throw new Error(error.error || 'Request failed');
    }

    return response.json();
  }

  // Health & Info
  async getHealth(): Promise<HealthResponse> {
    return this.request<HealthResponse>('/api/health');
  }

  async getTools(): Promise<ToolInfo[]> {
    return this.request<ToolInfo[]>('/api/tools');
  }

  // Network Diagnostics
  async ping(host: string, count?: number): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/ping', {
      method: 'POST',
      body: JSON.stringify({ host, count }),
    });
  }

  async fping(hosts: string[], count?: number): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/fping', {
      method: 'POST',
      body: JSON.stringify({ hosts, count }),
    });
  }

  async mtr(host: string, reportMode?: boolean, count?: number): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/mtr', {
      method: 'POST',
      body: JSON.stringify({ host, report_mode: reportMode, count }),
    });
  }

  async traceroute(host: string, maxHops?: number): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/traceroute', {
      method: 'POST',
      body: JSON.stringify({ host, max_hops: maxHops }),
    });
  }

  async tcpTraceroute(host: string, port?: number): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/tcptraceroute', {
      method: 'POST',
      body: JSON.stringify({ host, port }),
    });
  }

  async trippy(host: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/trippy', {
      method: 'POST',
      body: JSON.stringify({ host }),
    });
  }

  // DNS Tools
  async dns(host: string, type?: string, server?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/dns', {
      method: 'POST',
      body: JSON.stringify({ host, type, server }),
    });
  }

  async dig(host: string, type?: string, server?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/dig', {
      method: 'POST',
      body: JSON.stringify({ host, type, server }),
    });
  }

  async nslookup(host: string, server?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/nslookup', {
      method: 'POST',
      body: JSON.stringify({ host, server }),
    });
  }

  async host(host: string, server?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/host', {
      method: 'POST',
      body: JSON.stringify({ host, server }),
    });
  }

  // Port Scanning
  async nmap(host: string, ports?: string, scanType?: string, fastScan?: boolean): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/nmap', {
      method: 'POST',
      body: JSON.stringify({ host, ports, scan_type: scanType, fast_scan: fastScan }),
    });
  }

  async nping(host: string, port?: number, protocol?: string, count?: number): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/nping', {
      method: 'POST',
      body: JSON.stringify({ host, port, protocol, count }),
    });
  }

  async netcat(host: string, port: number, options?: { udp?: boolean; verbose?: boolean; zero?: boolean }): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/netcat', {
      method: 'POST',
      body: JSON.stringify({ host, port, ...options }),
    });
  }

  // HTTP/Web Tools
  async curl(url: string, options?: { method?: string; headers?: Record<string, string>; body?: string; followRedirect?: boolean; insecure?: boolean; verbose?: boolean }): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/curl', {
      method: 'POST',
      body: JSON.stringify({
        url,
        method: options?.method,
        headers: options?.headers,
        body: options?.body,
        follow_redirect: options?.followRedirect,
        insecure: options?.insecure,
        verbose: options?.verbose,
      }),
    });
  }

  async httpie(url: string, method?: string, headers?: Record<string, string>, data?: Record<string, string>): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/httpie', {
      method: 'POST',
      body: JSON.stringify({ url, method, headers, data }),
    });
  }

  async ab(url: string, requests?: number, concurrency?: number): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/ab', {
      method: 'POST',
      body: JSON.stringify({ url, requests, concurrency }),
    });
  }

  async fortio(url: string, connections?: number, duration?: string, qps?: number): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/fortio', {
      method: 'POST',
      body: JSON.stringify({ url, connections, duration, qps }),
    });
  }

  async websocat(url: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/websocat', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  }

  async grpcurl(server: string, service?: string, method?: string, plaintext?: boolean): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/grpcurl', {
      method: 'POST',
      body: JSON.stringify({ server, service, method, plaintext }),
    });
  }

  // Packet Capture
  async tcpdump(options?: { interface?: string; filter?: string; count?: number; verbose?: boolean }): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/tcpdump', {
      method: 'POST',
      body: JSON.stringify(options || {}),
    });
  }

  async tshark(options?: { interface?: string; filter?: string; count?: number; fields?: string }): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/tshark', {
      method: 'POST',
      body: JSON.stringify(options || {}),
    });
  }

  async ngrep(options?: { interface?: string; pattern?: string; filter?: string }): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/ngrep', {
      method: 'POST',
      body: JSON.stringify(options || {}),
    });
  }

  // Performance Testing
  async iperf(server: string, port?: number, duration?: number, reverse?: boolean, udp?: boolean): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/iperf', {
      method: 'POST',
      body: JSON.stringify({ server, port, duration, reverse, udp }),
    });
  }

  async iperf3(server: string, port?: number, duration?: number, reverse?: boolean, udp?: boolean, json?: boolean): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/iperf3', {
      method: 'POST',
      body: JSON.stringify({ server, port, duration, reverse, udp, json }),
    });
  }

  async speedtest(serverId?: number, simple?: boolean): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/speedtest', {
      method: 'POST',
      body: JSON.stringify({ server_id: serverId, simple }),
    });
  }

  // Network Configuration
  async ipRoute(action?: string, target?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/ip/route', {
      method: 'POST',
      body: JSON.stringify({ action, target }),
    });
  }

  async ipAddr(iface?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/ip/addr', {
      method: 'POST',
      body: JSON.stringify({ interface: iface }),
    });
  }

  async ipLink(iface?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/ip/link', {
      method: 'POST',
      body: JSON.stringify({ interface: iface }),
    });
  }

  async ipNeigh(iface?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/ip/neigh', {
      method: 'POST',
      body: JSON.stringify({ interface: iface }),
    });
  }

  async netstat(options?: { listening?: boolean; tcp?: boolean; udp?: boolean; numeric?: boolean; programs?: boolean }): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/netstat', {
      method: 'POST',
      body: JSON.stringify(options || {}),
    });
  }

  async ss(options?: { listening?: boolean; tcp?: boolean; udp?: boolean; processes?: boolean; state?: string }): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/ss', {
      method: 'POST',
      body: JSON.stringify(options || {}),
    });
  }

  async ethtool(iface: string, stats?: boolean): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/ethtool', {
      method: 'POST',
      body: JSON.stringify({ interface: iface, stats }),
    });
  }

  async bridge(command?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/bridge', {
      method: 'POST',
      body: JSON.stringify({ command }),
    });
  }

  // Firewall
  async iptables(options?: { table?: string; list?: boolean; numeric?: boolean; verbose?: boolean }): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/iptables', {
      method: 'POST',
      body: JSON.stringify(options || {}),
    });
  }

  async nftables(command?: string, table?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/nftables', {
      method: 'POST',
      body: JSON.stringify({ command, table }),
    });
  }

  async ipset(command?: string, setName?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/ipset', {
      method: 'POST',
      body: JSON.stringify({ command, set_name: setName }),
    });
  }

  async conntrack(options?: { list?: boolean; protocol?: string; source?: string }): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/conntrack', {
      method: 'POST',
      body: JSON.stringify(options || {}),
    });
  }

  // SSL/TLS
  async openssl(command: string, host?: string, port?: number): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/openssl', {
      method: 'POST',
      body: JSON.stringify({ command, host, port }),
    });
  }

  // SNMP
  async snmpGet(host: string, community?: string, oid?: string, version?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/snmpget', {
      method: 'POST',
      body: JSON.stringify({ host, community, oid, version }),
    });
  }

  async snmpWalk(host: string, community?: string, oid?: string, version?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/snmpwalk', {
      method: 'POST',
      body: JSON.stringify({ host, community, oid, version }),
    });
  }

  // DHCP
  async dhcping(server?: string, iface?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/dhcping', {
      method: 'POST',
      body: JSON.stringify({ server, interface: iface }),
    });
  }

  // SMTP
  async swaks(server: string, port?: number, from?: string, to?: string, tls?: boolean): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/swaks', {
      method: 'POST',
      body: JSON.stringify({ server, port, from, to, tls }),
    });
  }

  // Container Tools
  async calicoctl(command: string, resource?: string, name?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/calicoctl', {
      method: 'POST',
      body: JSON.stringify({ command, resource, name }),
    });
  }

  // Traffic Monitoring
  async iftop(iface?: string, duration?: number): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/iftop', {
      method: 'POST',
      body: JSON.stringify({ interface: iface, duration }),
    });
  }

  // Load Balancing
  async ipvsadm(list?: boolean, numeric?: boolean): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/ipvsadm', {
      method: 'POST',
      body: JSON.stringify({ list, numeric }),
    });
  }

  // Utility
  async socat(address1: string, address2: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/socat', {
      method: 'POST',
      body: JSON.stringify({ address1, address2 }),
    });
  }

  async file(path: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/file', {
      method: 'POST',
      body: JSON.stringify({ path }),
    });
  }

  async jq(filter: string, input: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/jq', {
      method: 'POST',
      body: JSON.stringify({ filter, input }),
    });
  }

  async whois(domain: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/whois', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    });
  }

  async ipInfo(): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/ipinfo');
  }

  // Routing
  async bird(command?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/bird', {
      method: 'POST',
      body: JSON.stringify({ command }),
    });
  }

  // SSH
  async sshKeyscan(host: string, port?: number, type?: string): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/ssh-keyscan', {
      method: 'POST',
      body: JSON.stringify({ host, port, type }),
    });
  }

  // Generic Command
  async exec(command: string, args?: string[], timeout?: number): Promise<ToolResponse> {
    return this.request<ToolResponse>('/api/exec', {
      method: 'POST',
      body: JSON.stringify({ command, args, timeout }),
    });
  }
}

export const apiService = new ApiService();
export default apiService;
