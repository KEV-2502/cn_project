import {
  HealthStatus,
  PcapRecord,
  PcapReanalyzeResult,
  NetworkFlowItem,
  ThreatAlertItem,
  OverviewStats,
  AnalyticsSummary,
  PaginatedResponse,
  TopologyResponse,
} from '../types';

const API_BASE = '/api';

export async function fetchHealth(): Promise<HealthStatus> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
  return res.json();
}

export async function fetchPcaps(): Promise<PcapRecord[]> {
  const res = await fetch(`${API_BASE}/pcaps`);
  if (!res.ok) throw new Error(`Failed to load PCAP captures: ${res.statusText}`);
  return res.json();
}

export async function uploadPcap(file: File): Promise<PcapRecord> {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/pcaps/upload`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errorData.detail || 'Upload failed');
  }
  return res.json();
}

export async function reanalyzePcap(pcapId: number): Promise<PcapReanalyzeResult> {
  const res = await fetch(`${API_BASE}/pcaps/${pcapId}/reanalyze`, {
    method: 'POST',
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(errorData.detail || 'Re-analysis failed');
  }
  return res.json();
}

export async function deletePcap(pcapId: number): Promise<void> {
  const res = await fetch(`${API_BASE}/pcaps/${pcapId}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error('Failed to delete capture');
}

export async function fetchOverviewStats(pcapId?: number): Promise<OverviewStats> {
  const url = pcapId !== undefined ? `${API_BASE}/stats/overview?pcap_id=${pcapId}` : `${API_BASE}/stats/overview`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch overview metrics');
  return res.json();
}

export async function fetchAnalytics(pcapId?: number): Promise<AnalyticsSummary> {
  const url = pcapId !== undefined ? `${API_BASE}/stats/analytics?pcap_id=${pcapId}` : `${API_BASE}/stats/analytics`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch traffic analytics');
  return res.json();
}

export async function fetchFlows(params: {
  pcap_id?: number;
  protocol?: string;
  src_ip?: string;
  dst_ip?: string;
  port?: number;
  only_anomalies?: boolean;
  page?: number;
  page_size?: number;
}): Promise<PaginatedResponse<NetworkFlowItem>> {
  const query = new URLSearchParams();
  if (params.pcap_id !== undefined) query.set('pcap_id', params.pcap_id.toString());
  if (params.protocol) query.set('protocol', params.protocol);
  if (params.src_ip) query.set('src_ip', params.src_ip);
  if (params.dst_ip) query.set('dst_ip', params.dst_ip);
  if (params.port !== undefined) query.set('port', params.port.toString());
  if (params.only_anomalies) query.set('only_anomalies', 'true');
  if (params.page !== undefined) query.set('page', params.page.toString());
  if (params.page_size !== undefined) query.set('page_size', params.page_size.toString());

  const res = await fetch(`${API_BASE}/flows?${query.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch network flows');
  return res.json();
}

export async function fetchAlerts(params: {
  pcap_id?: number;
  severity?: string;
  status?: string;
  rule_id?: string;
  page?: number;
  page_size?: number;
}): Promise<PaginatedResponse<ThreatAlertItem>> {
  const query = new URLSearchParams();
  if (params.pcap_id !== undefined) query.set('pcap_id', params.pcap_id.toString());
  if (params.severity) query.set('severity', params.severity);
  if (params.status) query.set('status', params.status);
  if (params.rule_id) query.set('rule_id', params.rule_id);
  if (params.page !== undefined) query.set('page', params.page.toString());
  if (params.page_size !== undefined) query.set('page_size', params.page_size.toString());

  const res = await fetch(`${API_BASE}/alerts?${query.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch threat alerts');
  return res.json();
}

export async function updateAlertStatus(
  alertId: number,
  status: string,
  resolutionNotes?: string
): Promise<ThreatAlertItem> {
  const res = await fetch(`${API_BASE}/alerts/${alertId}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, resolution_notes: resolutionNotes }),
  });
  if (!res.ok) throw new Error('Failed to update alert status');
  return res.json();
}

export async function fetchTopology(params: {
  pcap_id?: number;
  protocol?: string;
  min_flows?: number;
  only_alerts?: boolean;
  limit_nodes?: number;
}): Promise<TopologyResponse> {
  const query = new URLSearchParams();
  if (params.pcap_id !== undefined) query.set('pcap_id', params.pcap_id.toString());
  if (params.protocol) query.set('protocol', params.protocol);
  if (params.min_flows !== undefined) query.set('min_flows', params.min_flows.toString());
  if (params.only_alerts) query.set('only_alerts', 'true');
  if (params.limit_nodes !== undefined) query.set('limit_nodes', params.limit_nodes.toString());

  const res = await fetch(`${API_BASE}/topology?${query.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch network topology');
  return res.json();
}
