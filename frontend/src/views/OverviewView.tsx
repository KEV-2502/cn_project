import React from 'react';
import { ShieldCheck, AlertTriangle, Activity, Database, Flame } from 'lucide-react';
import { StatCard } from '../components/StatCard';
import { EmptyState } from '../components/EmptyState';
import { OverviewStats, PcapRecord } from '../types';

interface Props {
  stats: OverviewStats | null;
  loading: boolean;
  selectedPcap: PcapRecord | null;
  onNavigateUpload: () => void;
  onNavigateAlerts: () => void;
}

export const OverviewView: React.FC<Props> = ({
  stats,
  loading,
  selectedPcap,
  onNavigateUpload,
  onNavigateAlerts,
}) => {
  if (loading) {
    return (
      <div style={{ padding: '60px 0', textAlign: 'center', color: 'var(--text-muted)' }}>
        Loading platform security metrics...
      </div>
    );
  }

  if (!stats || stats.total_pcaps === 0) {
    return (
      <EmptyState
        title="No Packet Captures Analyzed"
        description="Upload a PCAP capture file to start network flow generation, rule-based threat evaluation, and machine-learning anomaly scoring."
        onAction={onNavigateUpload}
        actionText="Upload First PCAP"
      />
    );
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {selectedPcap && (
        <div
          style={{
            backgroundColor: 'rgba(56, 189, 248, 0.08)',
            border: '1px solid rgba(56, 189, 248, 0.25)',
            borderRadius: '8px',
            padding: '12px 16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Filtered Capture: </span>
            <strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)', marginLeft: '6px' }}>{selectedPcap.filename}</strong>
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            SHA256: <span style={{ fontFamily: 'var(--font-mono)' }}>{selectedPcap.sha256_hash.slice(0, 12)}...</span>
          </div>
        </div>
      )}

      {/* Metric Cards Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '16px',
        }}
      >
        <StatCard
          title="Packets Analyzed"
          value={stats.total_packets.toLocaleString()}
          sublabel="Decoded via Scapy"
          icon={<Activity size={18} />}
        />
        <StatCard
          title="Network Flows"
          value={stats.total_flows.toLocaleString()}
          sublabel="Bidirectional 5-tuple"
          icon={<Database size={18} />}
        />
        <StatCard
          title="Total Threats Detected"
          value={stats.total_alerts.toLocaleString()}
          sublabel={`${stats.critical_alerts} Critical, ${stats.high_alerts} High`}
          icon={<AlertTriangle size={18} />}
          variant={stats.critical_alerts > 0 ? 'danger' : stats.high_alerts > 0 ? 'warning' : 'default'}
        />
        <StatCard
          title="Active Incidents"
          value={stats.active_incidents}
          sublabel="Open or Under Investigation"
          icon={<Flame size={18} />}
          variant={stats.active_incidents > 0 ? 'warning' : 'success'}
        />
        <StatCard
          title="Traffic Volume"
          value={formatBytes(stats.total_bytes)}
          sublabel="Aggregated payload bytes"
          icon={<ShieldCheck size={18} />}
        />
        <StatCard
          title="Average Risk Score"
          value={`${stats.avg_risk_score} / 100`}
          sublabel="Threat exposure index"
          icon={<Flame size={18} />}
          variant={stats.avg_risk_score > 60 ? 'danger' : stats.avg_risk_score > 30 ? 'warning' : 'success'}
        />
      </div>

      {/* Quick Navigation Action Banner */}
      <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h4 style={{ fontWeight: 600, marginBottom: '4px' }}>Ready to investigate detections?</h4>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
            Examine the rule triggers, anomalous feature outliers, and update incident tracking statuses.
          </p>
        </div>
        <button className="btn btn-primary" onClick={onNavigateAlerts}>
          View Security Alerts ({stats.total_alerts})
        </button>
      </div>
    </div>
  );
};
