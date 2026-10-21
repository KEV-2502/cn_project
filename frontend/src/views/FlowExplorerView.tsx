import React, { useEffect, useState } from 'react';
import { fetchFlows } from '../services/api';
import { NetworkFlowItem, PcapRecord, PaginatedResponse } from '../types';
import { EmptyState } from '../components/EmptyState';
import { Filter, Search, ChevronLeft, ChevronRight, ShieldAlert } from 'lucide-react';

interface Props {
  selectedPcap: PcapRecord | null;
  onNavigateUpload: () => void;
}

export const FlowExplorerView: React.FC<Props> = ({ selectedPcap, onNavigateUpload }) => {
  const [flows, setFlows] = useState<PaginatedResponse<NetworkFlowItem> | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchIp, setSearchIp] = useState<string>('');
  const [protocol, setProtocol] = useState<string>('');
  const [onlyAnomalies, setOnlyAnomalies] = useState<boolean>(false);
  const [page, setPage] = useState<number>(1);

  const loadFlows = () => {
    setLoading(true);
    fetchFlows({
      pcap_id: selectedPcap?.id,
      src_ip: searchIp || undefined,
      protocol: protocol || undefined,
      only_anomalies: onlyAnomalies,
      page,
      page_size: 15,
    })
      .then((res) => setFlows(res))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    setPage(1);
  }, [selectedPcap, protocol, onlyAnomalies]);

  useEffect(() => {
    loadFlows();
  }, [selectedPcap, protocol, onlyAnomalies, page]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    loadFlows();
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Controls & Filter Bar */}
      <div className="card" style={{ padding: '16px 20px' }}>
        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center' }}>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, minWidth: '220px', background: 'var(--bg-secondary)', padding: '6px 12px', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
            <Search size={16} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Search source or dest IP..."
              value={searchIp}
              onChange={(e) => setSearchIp(e.target.value)}
              style={{ background: 'transparent', border: 'none', color: 'var(--text-main)', outline: 'none', width: '100%', fontSize: '0.875rem' }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Filter size={16} color="var(--text-muted)" />
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', color: 'var(--text-main)', padding: '7px 12px', borderRadius: '6px', fontSize: '0.875rem' }}
            >
              <option value="">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
              <option value="DNS">DNS</option>
            </select>
          </div>

          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.875rem', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={onlyAnomalies}
              onChange={(e) => setOnlyAnomalies(e.target.checked)}
              style={{ cursor: 'pointer' }}
            />
            Show AI Anomalies Only
          </label>

          <button type="submit" className="btn btn-secondary">
            Apply Filters
          </button>
        </form>
      </div>

      {/* Flow Table */}
      {loading ? (
        <div style={{ padding: '60px 0', textAlign: 'center', color: 'var(--text-muted)' }}>Loading network flows...</div>
      ) : !flows || flows.total === 0 ? (
        <EmptyState
          title="No Network Flows Found"
          description={selectedPcap ? "No flows match the active filter criteria." : "Upload a PCAP capture to extract bidirectional flows."}
          onAction={onNavigateUpload}
          actionText="Upload PCAP"
        />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Duration</th>
                  <th>Packets (Fwd / Rev)</th>
                  <th>Bytes</th>
                  <th>TCP State</th>
                  <th>AI Anomaly</th>
                </tr>
              </thead>
              <tbody>
                {flows.items.map((flow) => (
                  <tr key={flow.id}>
                    <td>
                      <span className="badge" style={{ backgroundColor: 'var(--bg-primary)', border: '1px solid var(--border-color)' }}>
                        {flow.protocol}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>
                      <span style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>{flow.src_ip}</span>
                      <span style={{ color: 'var(--text-subtle)' }}>:{flow.src_port}</span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>
                      <span style={{ color: 'var(--accent-emerald)', fontWeight: 600 }}>{flow.dst_ip}</span>
                      <span style={{ color: 'var(--text-subtle)' }}>:{flow.dst_port}</span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>
                      {flow.duration.toFixed(2)}s
                    </td>
                    <td>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{flow.total_packets}</span>{' '}
                      <span style={{ color: 'var(--text-subtle)', fontSize: '0.75rem' }}>({flow.forward_packets} / {flow.backward_packets})</span>
                    </td>
                    <td>{formatBytes(flow.total_bytes)}</td>
                    <td>
                      <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                        {flow.tcp_state || 'N/A'}
                      </span>
                    </td>
                    <td>
                      {flow.is_anomaly === 1 ? (
                        <span className="badge badge-high" title={`Score: ${flow.anomaly_score.toFixed(3)}`}>
                          <ShieldAlert size={12} /> ANOMALOUS
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-subtle)', fontSize: '0.8rem' }}>Normal</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
              Showing {flows.items.length} of {flows.total} flows (Page {flows.page} of {flows.pages})
            </span>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                className="btn btn-secondary"
                disabled={flows.page <= 1}
                onClick={() => setPage(flows.page - 1)}
                style={{ padding: '6px 12px' }}
              >
                <ChevronLeft size={16} /> Previous
              </button>
              <button
                className="btn btn-secondary"
                disabled={flows.page >= flows.pages}
                onClick={() => setPage(flows.page + 1)}
                style={{ padding: '6px 12px' }}
              >
                Next <ChevronRight size={16} />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
