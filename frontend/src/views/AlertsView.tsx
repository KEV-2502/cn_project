import React, { useEffect, useState } from 'react';
import { fetchAlerts } from '../services/api';
import { ThreatAlertItem, PcapRecord, PaginatedResponse } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState } from '../components/EmptyState';
import { AlertInvestigationModal } from './AlertInvestigationModal';
import { Filter, Eye, ChevronLeft, ChevronRight } from 'lucide-react';

interface Props {
  selectedPcap: PcapRecord | null;
  onNavigateUpload: () => void;
}

export const AlertsView: React.FC<Props> = ({ selectedPcap, onNavigateUpload }) => {
  const [alerts, setAlerts] = useState<PaginatedResponse<ThreatAlertItem> | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [page, setPage] = useState<number>(1);
  const [activeAlert, setActiveAlert] = useState<ThreatAlertItem | null>(null);

  const loadAlerts = () => {
    setLoading(true);
    fetchAlerts({
      pcap_id: selectedPcap?.id,
      severity: severityFilter || undefined,
      status: statusFilter || undefined,
      page,
      page_size: 15,
    })
      .then((res) => setAlerts(res))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    setPage(1);
  }, [selectedPcap, severityFilter, statusFilter]);

  useEffect(() => {
    loadAlerts();
  }, [selectedPcap, severityFilter, statusFilter, page]);

  const handleAlertUpdated = (updated: ThreatAlertItem) => {
    setActiveAlert(updated);
    if (alerts) {
      setAlerts({
        ...alerts,
        items: alerts.items.map((a) => (a.id === updated.id ? updated : a)),
      });
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Filter Controls */}
      <div className="card" style={{ padding: '16px 20px', display: 'flex', flexWrap: 'wrap', gap: '16px', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Filter size={16} color="var(--text-muted)" />
          <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-muted)' }}>Filters:</span>
        </div>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', color: 'var(--text-main)', padding: '7px 12px', borderRadius: '6px', fontSize: '0.875rem' }}
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-color)', color: 'var(--text-main)', padding: '7px 12px', borderRadius: '6px', fontSize: '0.875rem' }}
        >
          <option value="">All Incident States</option>
          <option value="OPEN">Open</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="RESOLVED">Resolved</option>
        </select>
      </div>

      {/* Alerts Table */}
      {loading ? (
        <div style={{ padding: '60px 0', textAlign: 'center', color: 'var(--text-muted)' }}>Loading security alerts...</div>
      ) : !alerts || alerts.total === 0 ? (
        <EmptyState
          title="No Threat Detections"
          description={selectedPcap ? "No alerts match the active severity or status filters." : "Upload a PCAP capture to scan for suspicious activity."}
          onAction={onNavigateUpload}
          actionText="Upload PCAP"
          icon="shield"
        />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Risk Score</th>
                  <th>Detection Type</th>
                  <th>Threat Rule</th>
                  <th>Source</th>
                  <th>Target</th>
                  <th>Incident Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {alerts.items.map((alert) => (
                  <tr key={alert.id}>
                    <td>
                      <StatusBadge type="severity" value={alert.severity} />
                    </td>
                    <td>
                      <span
                        style={{
                          fontWeight: 700,
                          fontFamily: 'var(--font-mono)',
                          color: alert.risk_score > 60 ? 'var(--accent-rose)' : alert.risk_score > 30 ? 'var(--accent-amber)' : 'var(--accent-emerald)',
                        }}
                      >
                        {alert.risk_score}
                      </span>
                    </td>
                    <td>
                      <span className="badge" style={{ backgroundColor: 'var(--bg-primary)', border: '1px solid var(--border-color)' }}>
                        {alert.detection_type}
                      </span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{alert.rule_name}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {alert.description}
                      </div>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>
                      <span style={{ color: 'var(--accent-blue)' }}>{alert.src_ip || 'N/A'}</span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>
                      <span style={{ color: 'var(--accent-emerald)' }}>{alert.dst_ip || 'N/A'}</span>
                    </td>
                    <td>
                      <StatusBadge type="status" value={alert.status} />
                    </td>
                    <td>
                      <button
                        className="btn btn-secondary"
                        onClick={() => setActiveAlert(alert)}
                        style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                      >
                        <Eye size={14} /> Investigate
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
              Showing {alerts.items.length} of {alerts.total} alerts (Page {alerts.page} of {alerts.pages})
            </span>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                className="btn btn-secondary"
                disabled={alerts.page <= 1}
                onClick={() => setPage(alerts.page - 1)}
                style={{ padding: '6px 12px' }}
              >
                <ChevronLeft size={16} /> Previous
              </button>
              <button
                className="btn btn-secondary"
                disabled={alerts.page >= alerts.pages}
                onClick={() => setPage(alerts.page + 1)}
                style={{ padding: '6px 12px' }}
              >
                Next <ChevronRight size={16} />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Detail Investigation Modal */}
      {activeAlert && (
        <AlertInvestigationModal
          alert={activeAlert}
          onClose={() => setActiveAlert(null)}
          onAlertUpdated={handleAlertUpdated}
        />
      )}
    </div>
  );
};
