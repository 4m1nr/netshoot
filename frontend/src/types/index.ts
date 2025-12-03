// Tool response from the API
export interface ToolResponse {
  tool: string;
  success: boolean;
  output: string;
  error?: string;
  exit_code: number;
}

// Tool information
export interface ToolInfo {
  name: string;
  description: string;
  usage: string;
  examples: string[];
  category: string;
}

// Health response
export interface HealthResponse {
  status: string;
  version: string;
  tools: string[];
}

// Network Diagnostics
export interface PingRequest {
  host: string;
  count?: number;
}

export interface FpingRequest {
  hosts: string[];
  count?: number;
}

export interface MTRRequest {
  host: string;
  report_mode?: boolean;
  count?: number;
}

export interface TracerouteRequest {
  host: string;
  max_hops?: number;
}

export interface TCPTracerouteRequest {
  host: string;
  port?: number;
}

export interface TrippyRequest {
  host: string;
}

// DNS Tools
export interface DNSRequest {
  host: string;
  type?: string;
  server?: string;
}

export interface DigRequest {
  host: string;
  type?: string;
  server?: string;
}

export interface NslookupRequest {
  host: string;
  server?: string;
}

export interface HostRequest {
  host: string;
  server?: string;
}

// Port Scanning
export interface NmapRequest {
  host: string;
  ports?: string;
  scan_type?: string;
  scripts?: string;
  verbose?: boolean;
  fast_scan?: boolean;
}

export interface NpingRequest {
  host: string;
  port?: number;
  protocol?: string;
  count?: number;
}

export interface NetcatRequest {
  host: string;
  port: number;
  udp?: boolean;
  verbose?: boolean;
  zero?: boolean;
}

// HTTP/Web Tools
export interface CurlRequest {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  follow_redirect?: boolean;
  insecure?: boolean;
  verbose?: boolean;
}

export interface HTTPieRequest {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  data?: Record<string, string>;
  json?: boolean;
}

export interface AbRequest {
  url: string;
  requests?: number;
  concurrency?: number;
}

export interface FortioRequest {
  url: string;
  connections?: number;
  duration?: string;
  qps?: number;
}

export interface WebsocatRequest {
  url: string;
}

export interface GrpcurlRequest {
  server: string;
  service?: string;
  method?: string;
  plaintext?: boolean;
  data?: string;
}

// Packet Capture
export interface TcpdumpRequest {
  interface?: string;
  filter?: string;
  count?: number;
  verbose?: boolean;
}

export interface TsharkRequest {
  interface?: string;
  filter?: string;
  count?: number;
  fields?: string;
}

export interface NgrepRequest {
  interface?: string;
  pattern?: string;
  filter?: string;
}

// Performance Testing
export interface IPerfRequest {
  server: string;
  port?: number;
  duration?: number;
  reverse?: boolean;
  udp?: boolean;
}

export interface IPerf3Request {
  server: string;
  port?: number;
  duration?: number;
  reverse?: boolean;
  udp?: boolean;
  json?: boolean;
}

export interface SpeedTestRequest {
  server_id?: number;
  simple?: boolean;
}

// Network Configuration
export interface IPRouteRequest {
  action?: string;
  target?: string;
}

export interface IPAddrRequest {
  interface?: string;
}

export interface IPLinkRequest {
  interface?: string;
}

export interface IPNeighRequest {
  interface?: string;
}

export interface NetstatRequest {
  listening?: boolean;
  tcp?: boolean;
  udp?: boolean;
  numeric?: boolean;
  programs?: boolean;
}

export interface SSRequest {
  listening?: boolean;
  tcp?: boolean;
  udp?: boolean;
  processes?: boolean;
  state?: string;
}

export interface EthtoolRequest {
  interface: string;
  stats?: boolean;
}

export interface BridgeRequest {
  command?: string;
}

// Firewall
export interface IptablesRequest {
  table?: string;
  list?: boolean;
  numeric?: boolean;
  verbose?: boolean;
}

export interface NftablesRequest {
  command?: string;
  table?: string;
}

export interface IpsetRequest {
  command?: string;
  set_name?: string;
}

export interface ConntrackRequest {
  list?: boolean;
  protocol?: string;
  source?: string;
}

// SSL/TLS
export interface OpenSSLRequest {
  command: string;
  host?: string;
  port?: number;
}

// SNMP
export interface SNMPRequest {
  host: string;
  community?: string;
  oid?: string;
  version?: string;
}

// DHCP
export interface DHCPingRequest {
  server?: string;
  interface?: string;
}

// SMTP
export interface SwaksRequest {
  server: string;
  port?: number;
  from?: string;
  to?: string;
  tls?: boolean;
}

// Container Tools
export interface CalicoctlRequest {
  command: string;
  resource?: string;
  name?: string;
}

// Traffic Monitoring
export interface IftopRequest {
  interface?: string;
  duration?: number;
}

// Load Balancing
export interface IpvsadmRequest {
  list?: boolean;
  numeric?: boolean;
}

// Utility
export interface SocatRequest {
  address1: string;
  address2: string;
}

export interface FileRequest {
  path: string;
}

export interface JqRequest {
  filter: string;
  input: string;
}

export interface WhoisRequest {
  domain: string;
}

// Routing
export interface BirdRequest {
  command?: string;
}

// SSH
export interface SSHKeyscanRequest {
  host: string;
  port?: number;
  type?: string;
}

// Generic Command
export interface GenericRequest {
  command: string;
  args?: string[];
  timeout?: number;
}

// Tool categories
export type ToolCategory = 
  | 'diagnostics'
  | 'dns'
  | 'scanning'
  | 'http'
  | 'capture'
  | 'performance'
  | 'config'
  | 'firewall'
  | 'ssl'
  | 'snmp'
  | 'dhcp'
  | 'email'
  | 'container'
  | 'monitoring'
  | 'loadbalancing'
  | 'utility'
  | 'routing'
  | 'ssh';

export const TOOL_CATEGORIES: Record<ToolCategory, { label: string; icon: string; color: string }> = {
  diagnostics: { label: 'Diagnostics', icon: '🔍', color: '#3B82F6' },
  dns: { label: 'DNS', icon: '🌐', color: '#10B981' },
  scanning: { label: 'Scanning', icon: '📡', color: '#F59E0B' },
  http: { label: 'HTTP/Web', icon: '🌍', color: '#8B5CF6' },
  capture: { label: 'Packet Capture', icon: '📦', color: '#EF4444' },
  performance: { label: 'Performance', icon: '⚡', color: '#EC4899' },
  config: { label: 'Configuration', icon: '⚙️', color: '#6366F1' },
  firewall: { label: 'Firewall', icon: '🔥', color: '#F97316' },
  ssl: { label: 'SSL/TLS', icon: '🔒', color: '#14B8A6' },
  snmp: { label: 'SNMP', icon: '📊', color: '#84CC16' },
  dhcp: { label: 'DHCP', icon: '📋', color: '#06B6D4' },
  email: { label: 'Email', icon: '📧', color: '#A855F7' },
  container: { label: 'Container', icon: '🐳', color: '#0EA5E9' },
  monitoring: { label: 'Monitoring', icon: '📈', color: '#22C55E' },
  loadbalancing: { label: 'Load Balancing', icon: '⚖️', color: '#D946EF' },
  utility: { label: 'Utility', icon: '🔧', color: '#64748B' },
  routing: { label: 'Routing', icon: '🛤️', color: '#F43F5E' },
  ssh: { label: 'SSH', icon: '🔑', color: '#0D9488' },
};
