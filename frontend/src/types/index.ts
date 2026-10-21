export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type IncidentStatusType = 'OPEN' | 'INVESTIGATING' | 'RESOLVED';
export type PcapStatusType = 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED';

export interface HealthStatus {
  status: string;
  version: string;
  database: string;
  models_ready: boolean;
}

export interface PcapRecord {
  id: number;
  filename: string;
  file_path: string;
  file_size_bytes: number;
  sha256_hash: string;
  status: PcapStatusType;
  packet_count: number;
  flow_count: number;
  alert_count: number;
  duration_seconds: number;
  error_message?: string | null;
  created_at: string;
  processed_at?: string | null;
}

export interface NetworkFlowItem {
  id: number;
  pcap_id: number;
  flow_key: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  ip_version: number;
  start_time: number;
  end_time: number;
  duration: number;
  forward_packets: number;
  backward_packets: number;
  forward_bytes: number;
  backward_bytes: number;
  total_packets: number;
  total_bytes: number;
  tcp_flags_forward: string;
  tcp_flags_backward: string;
  tcp_state: string;
  anomaly_score: number;
  is_anomaly: number;
  anomaly_features_json: string;
  created_at: string;
}

export interface ThreatAlertItem {
  id: number;
  pcap_id: number;
  rule_id: string;
  rule_name: string;
  detection_type: string;
  severity: SeverityLevel;
  risk_score: number;
  src_ip?: string | null;
  dst_ip?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  protocol?: string | null;
  timestamp: number;
  description: string;
  explanation: string;
  evidence_json: string;
  flow_ids_json: string;
  status: IncidentStatusType;
  resolution_notes?: string | null;
  created_at: string;
}

export interface OverviewStats {
  total_pcaps: number;
  total_packets: number;
  total_flows: number;
  total_bytes: number;
  total_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  medium_alerts: number;
  low_alerts: number;
  active_incidents: number;
  avg_risk_score: number;
}

export interface ProtocolDistributionItem {
  protocol: string;
  flow_count: number;
  packet_count: number;
  byte_count: number;
  percentage: number;
}

export interface TopHostItem {
  ip: string;
  packets: number;
  bytes: number;
  flow_count: number;
}

export interface TimeSeriesPointItem {
  timestamp: number;
  formatted_time: string;
  packet_count: number;
  byte_count: number;
  alert_count: number;
}

export interface AnalyticsSummary {
  overview: OverviewStats;
  protocol_distribution: ProtocolDistributionItem[];
  top_sources: TopHostItem[];
  top_destinations: TopHostItem[];
  timeline: TimeSeriesPointItem[];
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}
