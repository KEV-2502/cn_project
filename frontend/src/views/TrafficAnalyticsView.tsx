import React, { useEffect, useState } from 'react';
import { fetchAnalytics } from '../services/api';
import { AnalyticsSummary, PcapRecord } from '../types';
import { EmptyState } from '../components/EmptyState';
import { BarChart3, PieChart, Network } from 'lucide-react';

interface Props {
  selectedPcap: PcapRecord | null;
  onNavigateUpload: () => void;
}

export const TrafficAnalyticsView: React.FC<Props> = ({ selectedPcap, onNavigateUpload }) => {
  const [data, setData] = useState<AnalyticsSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    fetchAnalytics(selectedPcap?.id)
      .then((res) => {
        setData(res);
        setError(null);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [selectedPcap]);

  if (loading) {
    return <div style={{ padding: '60px 0', textAlign: 'center', color: 'var(--text-muted)' }}>Calculating traffic distribution...</div>;
  }

  if (error || !data || data.overview.total_flows === 0) {
    return (
      <EmptyState
        title="No Traffic Analytics Available"
        description="Traffic analytics requires an active PCAP capture. Upload a PCAP file to visualize protocol breakdowns and top communicating hosts."
        onAction={onNavigateUpload}
        actionText="Upload Capture"
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
      {/* Top Grid: Protocol Distribution & Top Talkers */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '20px' }}>
        
        {/* Protocol Distribution */}
        <div className="card">
          <div className="card-title" style={{ marginBottom: '16px' }}>
            <PieChart size={16} /> Protocol Distribution
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {data.protocol_distribution.map((p) => (
              <div key={p.protocol} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem' }}>
                  <span style={{ fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{p.protocol}</span>
                  <span style={{ color: 'var(--text-muted)' }}>
                    {p.flow_count} flows ({p.percentage}%) • {formatBytes(p.byte_count)}
                  </span>
                </div>
                <div style={{ height: '8px', backgroundColor: 'var(--bg-primary)', borderRadius: '4px', overflow: 'hidden' }}>
                  <div
                    style={{
                      height: '100%',
                      width: `${p.percentage}%`,
                      backgroundColor:
                        p.protocol === 'TCP' ? 'var(--accent-blue)' :
                        p.protocol === 'UDP' ? 'var(--accent-purple)' :
                        p.protocol === 'DNS' ? 'var(--accent-emerald)' : 'var(--accent-amber)',
                      borderRadius: '4px',
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Communicating Sources */}
        <div className="card">
          <div className="card-title" style={{ marginBottom: '16px' }}>
            <Network size={16} /> Top Communicating Sources (By Volume)
          </div>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Packets</th>
                  <th>Bytes</th>
                  <th>Flows</th>
                </tr>
              </thead>
              <tbody>
                {data.top_sources.map((s) => (
                  <tr key={s.ip}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--accent-blue)' }}>{s.ip}</td>
                    <td>{s.packets.toLocaleString()}</td>
                    <td>{formatBytes(s.bytes)}</td>
                    <td>{s.flow_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </div>

      {/* Top Destinations */}
      <div className="card">
        <div className="card-title" style={{ marginBottom: '16px' }}>
          <BarChart3 size={16} /> Top Destination Targets
        </div>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Destination IP</th>
                <th>Packets</th>
                <th>Bytes</th>
                <th>Flows</th>
              </tr>
            </thead>
            <tbody>
              {data.top_destinations.map((d) => (
                <tr key={d.ip}>
                  <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--accent-emerald)' }}>{d.ip}</td>
                  <td>{d.packets.toLocaleString()}</td>
                  <td>{formatBytes(d.bytes)}</td>
                  <td>{d.flow_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
};
