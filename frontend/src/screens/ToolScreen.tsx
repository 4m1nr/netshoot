import React from 'react';
import { RouteProp, useRoute } from '@react-navigation/native';
import { ToolForm } from '../components/ToolForm';
import { ToolInfo, ToolResponse } from '../types';
import apiService from '../services/api';

type RootStackParamList = {
  Tool: { tool: ToolInfo };
};

type ToolScreenRouteProp = RouteProp<RootStackParamList, 'Tool'>;

// Define fields for each tool
const getToolFields = (toolName: string) => {
  switch (toolName) {
    // Network Diagnostics
    case 'ping':
      return [
        { name: 'host', label: 'Host', placeholder: 'e.g., google.com', required: true },
        { name: 'count', label: 'Count', placeholder: 'Number of pings (default: 4)', type: 'number' as const },
      ];
    case 'fping':
      return [
        { name: 'hosts', label: 'Hosts (comma-separated)', placeholder: 'e.g., host1.com,host2.com', required: true },
        { name: 'count', label: 'Count', placeholder: 'Number of pings (default: 3)', type: 'number' as const },
      ];
    case 'mtr':
      return [
        { name: 'host', label: 'Host', placeholder: 'e.g., google.com', required: true },
        { name: 'count', label: 'Count', placeholder: 'Number of probes (default: 10)', type: 'number' as const },
        { name: 'report_mode', label: 'Report Mode', type: 'boolean' as const, defaultValue: true },
      ];
    case 'traceroute':
      return [
        { name: 'host', label: 'Host', placeholder: 'e.g., google.com', required: true },
        { name: 'max_hops', label: 'Max Hops', placeholder: 'Maximum hops (default: 30)', type: 'number' as const },
      ];
    case 'tcptraceroute':
      return [
        { name: 'host', label: 'Host', placeholder: 'e.g., google.com', required: true },
        { name: 'port', label: 'Port', placeholder: 'Port number (default: 80)', type: 'number' as const },
      ];
    case 'trippy':
      return [
        { name: 'host', label: 'Host', placeholder: 'e.g., google.com', required: true },
      ];

    // DNS Tools
    case 'drill':
    case 'dns':
      return [
        { name: 'host', label: 'Host', placeholder: 'e.g., google.com', required: true },
        { name: 'type', label: 'Record Type', placeholder: 'e.g., A, AAAA, MX, NS' },
        { name: 'server', label: 'DNS Server', placeholder: 'e.g., 8.8.8.8' },
      ];
    case 'dig':
      return [
        { name: 'host', label: 'Host', placeholder: 'e.g., google.com', required: true },
        { name: 'type', label: 'Record Type', placeholder: 'e.g., A, AAAA, MX, NS' },
        { name: 'server', label: 'DNS Server', placeholder: 'e.g., 8.8.8.8' },
      ];
    case 'nslookup':
      return [
        { name: 'host', label: 'Host', placeholder: 'e.g., google.com', required: true },
        { name: 'server', label: 'DNS Server', placeholder: 'e.g., 8.8.8.8' },
      ];
    case 'host':
      return [
        { name: 'host', label: 'Host', placeholder: 'e.g., google.com', required: true },
        { name: 'server', label: 'DNS Server', placeholder: 'e.g., 8.8.8.8' },
      ];

    // Port Scanning
    case 'nmap':
      return [
        { name: 'host', label: 'Host', placeholder: 'e.g., scanme.nmap.org', required: true },
        { name: 'ports', label: 'Ports', placeholder: 'e.g., 80,443 or 1-1000' },
        { name: 'fast_scan', label: 'Fast Scan (-F)', type: 'boolean' as const },
        { name: 'verbose', label: 'Verbose (-v)', type: 'boolean' as const },
      ];
    case 'nping':
      return [
        { name: 'host', label: 'Host', placeholder: 'e.g., google.com', required: true },
        { name: 'port', label: 'Port', placeholder: 'Port number', type: 'number' as const },
        { name: 'protocol', label: 'Protocol', placeholder: 'tcp, udp, or icmp' },
        { name: 'count', label: 'Count', placeholder: 'Number of probes', type: 'number' as const },
      ];
    case 'netcat':
    case 'nc':
      return [
        { name: 'host', label: 'Host', placeholder: 'e.g., google.com', required: true },
        { name: 'port', label: 'Port', placeholder: 'Port number', required: true, type: 'number' as const },
        { name: 'udp', label: 'UDP Mode', type: 'boolean' as const },
        { name: 'verbose', label: 'Verbose', type: 'boolean' as const },
        { name: 'zero', label: 'Zero I/O (Scan Mode)', type: 'boolean' as const, defaultValue: true },
      ];

    // HTTP/Web Tools
    case 'curl':
      return [
        { name: 'url', label: 'URL', placeholder: 'https://example.com', required: true },
        { name: 'method', label: 'Method', placeholder: 'GET, POST, PUT, DELETE' },
        { name: 'follow_redirect', label: 'Follow Redirects', type: 'boolean' as const },
        { name: 'insecure', label: 'Ignore SSL Errors (-k)', type: 'boolean' as const },
        { name: 'verbose', label: 'Verbose (-v)', type: 'boolean' as const },
      ];
    case 'httpie':
    case 'http':
      return [
        { name: 'url', label: 'URL', placeholder: 'https://example.com', required: true },
        { name: 'method', label: 'Method', placeholder: 'GET, POST, PUT, DELETE' },
      ];
    case 'ab':
      return [
        { name: 'url', label: 'URL', placeholder: 'http://example.com/', required: true },
        { name: 'requests', label: 'Total Requests', placeholder: 'Number of requests (default: 100)', type: 'number' as const },
        { name: 'concurrency', label: 'Concurrency', placeholder: 'Concurrent requests (default: 10)', type: 'number' as const },
      ];
    case 'fortio':
      return [
        { name: 'url', label: 'URL', placeholder: 'http://example.com/', required: true },
        { name: 'connections', label: 'Connections', placeholder: 'Number of connections', type: 'number' as const },
        { name: 'duration', label: 'Duration', placeholder: 'e.g., 5s, 1m' },
        { name: 'qps', label: 'QPS', placeholder: 'Queries per second', type: 'number' as const },
      ];
    case 'websocat':
      return [
        { name: 'url', label: 'WebSocket URL', placeholder: 'ws://example.com/socket', required: true },
      ];
    case 'grpcurl':
      return [
        { name: 'server', label: 'Server', placeholder: 'localhost:50051', required: true },
        { name: 'service', label: 'Service', placeholder: 'package.Service' },
        { name: 'method', label: 'Method', placeholder: 'MethodName' },
        { name: 'plaintext', label: 'Plaintext (no TLS)', type: 'boolean' as const },
      ];

    // Packet Capture
    case 'tcpdump':
      return [
        { name: 'interface', label: 'Interface', placeholder: 'e.g., eth0' },
        { name: 'filter', label: 'Filter', placeholder: 'e.g., port 80' },
        { name: 'count', label: 'Packet Count', placeholder: 'Number of packets', type: 'number' as const },
        { name: 'verbose', label: 'Verbose', type: 'boolean' as const },
      ];
    case 'tshark':
      return [
        { name: 'interface', label: 'Interface', placeholder: 'e.g., eth0' },
        { name: 'filter', label: 'Capture Filter', placeholder: 'e.g., port 80' },
        { name: 'count', label: 'Packet Count', placeholder: 'Number of packets', type: 'number' as const },
        { name: 'fields', label: 'Display Fields', placeholder: 'e.g., ip.src,ip.dst' },
      ];
    case 'ngrep':
      return [
        { name: 'interface', label: 'Interface', placeholder: 'e.g., eth0' },
        { name: 'pattern', label: 'Pattern', placeholder: 'e.g., HTTP' },
        { name: 'filter', label: 'BPF Filter', placeholder: 'e.g., port 80' },
      ];

    // Performance Testing
    case 'iperf':
      return [
        { name: 'server', label: 'Server', placeholder: 'iperf server address', required: true },
        { name: 'port', label: 'Port', placeholder: 'Port number', type: 'number' as const },
        { name: 'duration', label: 'Duration (sec)', placeholder: 'Test duration', type: 'number' as const },
        { name: 'reverse', label: 'Reverse Mode', type: 'boolean' as const },
        { name: 'udp', label: 'UDP Mode', type: 'boolean' as const },
      ];
    case 'iperf3':
      return [
        { name: 'server', label: 'Server', placeholder: 'iperf3 server address', required: true },
        { name: 'port', label: 'Port', placeholder: 'Port number', type: 'number' as const },
        { name: 'duration', label: 'Duration (sec)', placeholder: 'Test duration', type: 'number' as const },
        { name: 'reverse', label: 'Reverse Mode', type: 'boolean' as const },
        { name: 'udp', label: 'UDP Mode', type: 'boolean' as const },
        { name: 'json', label: 'JSON Output', type: 'boolean' as const },
      ];
    case 'speedtest':
      return [
        { name: 'server_id', label: 'Server ID', placeholder: 'Specific server ID', type: 'number' as const },
        { name: 'simple', label: 'Simple Output', type: 'boolean' as const, defaultValue: true },
      ];

    // Network Configuration
    case 'ip-route':
      return [
        { name: 'action', label: 'Action', placeholder: 'show or get' },
        { name: 'target', label: 'Target IP', placeholder: 'IP for route lookup' },
      ];
    case 'ip-addr':
      return [
        { name: 'interface', label: 'Interface', placeholder: 'e.g., eth0 (optional)' },
      ];
    case 'ip-link':
      return [
        { name: 'interface', label: 'Interface', placeholder: 'e.g., eth0 (optional)' },
      ];
    case 'ip-neigh':
      return [
        { name: 'interface', label: 'Interface', placeholder: 'e.g., eth0 (optional)' },
      ];
    case 'netstat':
      return [
        { name: 'listening', label: 'Listening Only (-l)', type: 'boolean' as const },
        { name: 'tcp', label: 'TCP (-t)', type: 'boolean' as const, defaultValue: true },
        { name: 'udp', label: 'UDP (-u)', type: 'boolean' as const, defaultValue: true },
        { name: 'numeric', label: 'Numeric (-n)', type: 'boolean' as const, defaultValue: true },
        { name: 'programs', label: 'Programs (-p)', type: 'boolean' as const, defaultValue: true },
      ];
    case 'ss':
      return [
        { name: 'listening', label: 'Listening Only (-l)', type: 'boolean' as const },
        { name: 'tcp', label: 'TCP (-t)', type: 'boolean' as const, defaultValue: true },
        { name: 'udp', label: 'UDP (-u)', type: 'boolean' as const, defaultValue: true },
        { name: 'processes', label: 'Show Processes (-p)', type: 'boolean' as const },
        { name: 'state', label: 'State Filter', placeholder: 'e.g., established' },
      ];
    case 'ethtool':
      return [
        { name: 'interface', label: 'Interface', placeholder: 'e.g., eth0', required: true },
        { name: 'stats', label: 'Show Statistics (-S)', type: 'boolean' as const },
      ];
    case 'bridge':
      return [
        { name: 'command', label: 'Command', placeholder: 'link, fdb, mdb, or vlan' },
      ];

    // Firewall
    case 'iptables':
      return [
        { name: 'table', label: 'Table', placeholder: 'filter, nat, mangle, raw' },
        { name: 'list', label: 'List Rules (-L)', type: 'boolean' as const, defaultValue: true },
        { name: 'numeric', label: 'Numeric (-n)', type: 'boolean' as const, defaultValue: true },
        { name: 'verbose', label: 'Verbose (-v)', type: 'boolean' as const },
      ];
    case 'nftables':
    case 'nft':
      return [
        { name: 'command', label: 'Command', placeholder: 'list (default)' },
        { name: 'table', label: 'Table', placeholder: 'Table name' },
      ];
    case 'ipset':
      return [
        { name: 'command', label: 'Command', placeholder: 'list (default)' },
        { name: 'set_name', label: 'Set Name', placeholder: 'IP set name' },
      ];
    case 'conntrack':
      return [
        { name: 'protocol', label: 'Protocol', placeholder: 'tcp, udp, icmp' },
        { name: 'source', label: 'Source IP', placeholder: 'Filter by source' },
      ];

    // SSL/TLS
    case 'openssl':
      return [
        { name: 'command', label: 'Command', placeholder: 's_client', required: true },
        { name: 'host', label: 'Host', placeholder: 'e.g., google.com' },
        { name: 'port', label: 'Port', placeholder: '443', type: 'number' as const },
      ];

    // SNMP
    case 'snmpget':
    case 'snmpwalk':
      return [
        { name: 'host', label: 'Host', placeholder: 'SNMP agent address', required: true },
        { name: 'community', label: 'Community', placeholder: 'public (default)' },
        { name: 'oid', label: 'OID', placeholder: 'e.g., system' },
        { name: 'version', label: 'Version', placeholder: '1, 2c, or 3' },
      ];

    // DHCP
    case 'dhcping':
      return [
        { name: 'server', label: 'Server', placeholder: 'DHCP server address' },
        { name: 'interface', label: 'Interface', placeholder: 'e.g., eth0' },
      ];

    // Email
    case 'swaks':
      return [
        { name: 'server', label: 'SMTP Server', placeholder: 'mail.example.com', required: true },
        { name: 'port', label: 'Port', placeholder: '25 or 587', type: 'number' as const },
        { name: 'from', label: 'From Address', placeholder: 'sender@example.com' },
        { name: 'to', label: 'To Address', placeholder: 'recipient@example.com' },
        { name: 'tls', label: 'Use TLS', type: 'boolean' as const },
      ];

    // Container Tools
    case 'calicoctl':
      return [
        { name: 'command', label: 'Command', placeholder: 'get, describe, etc.', required: true },
        { name: 'resource', label: 'Resource', placeholder: 'nodes, pods, etc.' },
        { name: 'name', label: 'Name', placeholder: 'Resource name' },
      ];

    // Traffic Monitoring
    case 'iftop':
      return [
        { name: 'interface', label: 'Interface', placeholder: 'e.g., eth0' },
        { name: 'duration', label: 'Duration (sec)', placeholder: 'Monitoring duration', type: 'number' as const },
      ];

    // Load Balancing
    case 'ipvsadm':
      return [
        { name: 'list', label: 'List (-L)', type: 'boolean' as const, defaultValue: true },
        { name: 'numeric', label: 'Numeric (-n)', type: 'boolean' as const, defaultValue: true },
      ];

    // Utility
    case 'socat':
      return [
        { name: 'address1', label: 'Address 1', placeholder: 'e.g., TCP:localhost:80', required: true },
        { name: 'address2', label: 'Address 2', placeholder: 'e.g., -', required: true },
      ];
    case 'file':
      return [
        { name: 'path', label: 'File Path', placeholder: '/path/to/file', required: true },
      ];
    case 'jq':
      return [
        { name: 'filter', label: 'JQ Filter', placeholder: 'e.g., .key or .[0]', required: true },
        { name: 'input', label: 'JSON Input', placeholder: '{"key": "value"}', required: true },
      ];
    case 'whois':
      return [
        { name: 'domain', label: 'Domain', placeholder: 'e.g., google.com', required: true },
      ];
    case 'ipinfo':
      return [];

    // Routing
    case 'bird':
    case 'birdc':
      return [
        { name: 'command', label: 'Command', placeholder: 'show status, show route, etc.' },
      ];

    // SSH
    case 'ssh-keyscan':
      return [
        { name: 'host', label: 'Host', placeholder: 'e.g., github.com', required: true },
        { name: 'port', label: 'Port', placeholder: '22', type: 'number' as const },
        { name: 'type', label: 'Key Type', placeholder: 'rsa, ecdsa, ed25519' },
      ];

    // Generic
    case 'generic':
      return [
        { name: 'command', label: 'Command', placeholder: 'e.g., ping', required: true },
        { name: 'args', label: 'Arguments (comma-separated)', placeholder: '-c,4,google.com' },
        { name: 'timeout', label: 'Timeout (sec)', placeholder: '60', type: 'number' as const },
      ];

    default:
      return [
        { name: 'args', label: 'Arguments', placeholder: 'Command arguments' },
      ];
  }
};

// Map tool name to API call
const executeToolRequest = async (toolName: string, values: Record<string, any>): Promise<ToolResponse> => {
  switch (toolName) {
    case 'ping':
      return apiService.ping(values.host, values.count);
    case 'fping':
      const hosts = values.hosts?.split(',').map((h: string) => h.trim()) || [];
      return apiService.fping(hosts, values.count);
    case 'mtr':
      return apiService.mtr(values.host, values.report_mode, values.count);
    case 'traceroute':
      return apiService.traceroute(values.host, values.max_hops);
    case 'tcptraceroute':
      return apiService.tcpTraceroute(values.host, values.port);
    case 'trippy':
      return apiService.trippy(values.host);
    case 'drill':
    case 'dns':
      return apiService.dns(values.host, values.type, values.server);
    case 'dig':
      return apiService.dig(values.host, values.type, values.server);
    case 'nslookup':
      return apiService.nslookup(values.host, values.server);
    case 'host':
      return apiService.host(values.host, values.server);
    case 'nmap':
      return apiService.nmap(values.host, values.ports, values.scan_type, values.fast_scan);
    case 'nping':
      return apiService.nping(values.host, values.port, values.protocol, values.count);
    case 'netcat':
    case 'nc':
      return apiService.netcat(values.host, values.port, {
        udp: values.udp,
        verbose: values.verbose,
        zero: values.zero,
      });
    case 'curl':
      return apiService.curl(values.url, {
        method: values.method,
        followRedirect: values.follow_redirect,
        insecure: values.insecure,
        verbose: values.verbose,
      });
    case 'httpie':
    case 'http':
      return apiService.httpie(values.url, values.method);
    case 'ab':
      return apiService.ab(values.url, values.requests, values.concurrency);
    case 'fortio':
      return apiService.fortio(values.url, values.connections, values.duration, values.qps);
    case 'websocat':
      return apiService.websocat(values.url);
    case 'grpcurl':
      return apiService.grpcurl(values.server, values.service, values.method, values.plaintext);
    case 'tcpdump':
      return apiService.tcpdump({
        interface: values.interface,
        filter: values.filter,
        count: values.count,
        verbose: values.verbose,
      });
    case 'tshark':
      return apiService.tshark({
        interface: values.interface,
        filter: values.filter,
        count: values.count,
        fields: values.fields,
      });
    case 'ngrep':
      return apiService.ngrep({
        interface: values.interface,
        pattern: values.pattern,
        filter: values.filter,
      });
    case 'iperf':
      return apiService.iperf(values.server, values.port, values.duration, values.reverse, values.udp);
    case 'iperf3':
      return apiService.iperf3(values.server, values.port, values.duration, values.reverse, values.udp, values.json);
    case 'speedtest':
      return apiService.speedtest(values.server_id, values.simple);
    case 'ip-route':
      return apiService.ipRoute(values.action, values.target);
    case 'ip-addr':
      return apiService.ipAddr(values.interface);
    case 'ip-link':
      return apiService.ipLink(values.interface);
    case 'ip-neigh':
      return apiService.ipNeigh(values.interface);
    case 'netstat':
      return apiService.netstat({
        listening: values.listening,
        tcp: values.tcp,
        udp: values.udp,
        numeric: values.numeric,
        programs: values.programs,
      });
    case 'ss':
      return apiService.ss({
        listening: values.listening,
        tcp: values.tcp,
        udp: values.udp,
        processes: values.processes,
        state: values.state,
      });
    case 'ethtool':
      return apiService.ethtool(values.interface, values.stats);
    case 'bridge':
      return apiService.bridge(values.command);
    case 'iptables':
      return apiService.iptables({
        table: values.table,
        list: values.list,
        numeric: values.numeric,
        verbose: values.verbose,
      });
    case 'nftables':
    case 'nft':
      return apiService.nftables(values.command, values.table);
    case 'ipset':
      return apiService.ipset(values.command, values.set_name);
    case 'conntrack':
      return apiService.conntrack({
        list: true,
        protocol: values.protocol,
        source: values.source,
      });
    case 'openssl':
      return apiService.openssl(values.command, values.host, values.port);
    case 'snmpget':
      return apiService.snmpGet(values.host, values.community, values.oid, values.version);
    case 'snmpwalk':
      return apiService.snmpWalk(values.host, values.community, values.oid, values.version);
    case 'dhcping':
      return apiService.dhcping(values.server, values.interface);
    case 'swaks':
      return apiService.swaks(values.server, values.port, values.from, values.to, values.tls);
    case 'calicoctl':
      return apiService.calicoctl(values.command, values.resource, values.name);
    case 'iftop':
      return apiService.iftop(values.interface, values.duration);
    case 'ipvsadm':
      return apiService.ipvsadm(values.list, values.numeric);
    case 'socat':
      return apiService.socat(values.address1, values.address2);
    case 'file':
      return apiService.file(values.path);
    case 'jq':
      return apiService.jq(values.filter, values.input);
    case 'whois':
      return apiService.whois(values.domain);
    case 'ipinfo':
      return apiService.ipInfo();
    case 'bird':
    case 'birdc':
      return apiService.bird(values.command);
    case 'ssh-keyscan':
      return apiService.sshKeyscan(values.host, values.port, values.type);
    case 'generic':
      const args = values.args?.split(',').map((a: string) => a.trim()) || [];
      return apiService.exec(values.command, args, values.timeout);
    default:
      throw new Error(`Unknown tool: ${toolName}`);
  }
};

export const ToolScreen: React.FC = () => {
  const route = useRoute<ToolScreenRouteProp>();
  const { tool } = route.params;

  const fields = getToolFields(tool.name);

  return (
    <ToolForm
      title={tool.name}
      description={tool.description}
      fields={fields}
      onSubmit={(values) => executeToolRequest(tool.name, values)}
    />
  );
};

export default ToolScreen;
