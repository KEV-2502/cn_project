import React, { useState } from 'react';
import { ThreatAlertItem, IncidentStatusType } from '../types';
import { updateAlertStatus } from '../services/api';
import { StatusBadge } from '../components/StatusBadge';
import { X, CheckCircle, Clock } from 'lucide-react';

interface Props {
  alert: ThreatAlertItem;
  onClose: () => void;
  onAlertUpdated: (updated: ThreatAlertItem) => void;
}

export const AlertInvestigationModal: React.FC<Props> = ({ alert, onClose, onAlertUpdated }) => {
  const [status, setStatus] = useState<IncidentStatusType>(alert.status);
  const [notes, setNotes] = useState<string>(alert.resolution_notes || '');
  const [saving, setSaving] = useState<boolean>(false);
  const [feedback, setFeedback] = useState<string | null>(null);

  let parsedEvidence: Record<string, any> = {};
  try {
    parsedEvidence = JSON.parse(alert.evidence_json);
  } catch {
    parsedEvidence = { raw: alert.evidence_json };
  }

  let flowIds: number[] = [];
  try {
    flowIds = JSON.parse(alert.flow_ids_json);
  } catch {
    flowIds = [];
  }

  const handleSave = async () => {
    setSaving(true);
    try {
      const updated = await updateAlertStatus(alert.id, status, notes);
      onAlertUpdated(updated);
      setFeedback('Incident status updated successfully');
      setTimeout(() => setFeedback(null), 3000);
    } catch (err: any) {
      setFeedback(`Error: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <StatusBadge type="severity" value={alert.severity} />
              <StatusBadge type="status" value={alert.status} />
              <span style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: 'var(--text-subtle)' }}>
                {alert.rule_id}
              </span>
            </div>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-main)' }}>
              {alert.rule_name}
            </h2>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Risk Score Index Banner */}
        <div
          style={{
            backgroundColor: 'rgba(20, 28, 46, 0.8)',
            border: '1px solid var(--border-color)',
            borderRadius: '8px',
            padding: '16px',
            marginBottom: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div>
            <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
              Explainable Risk Score
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: alert.risk_score > 60 ? 'var(--accent-rose)' : 'var(--accent-amber)' }}>
              {alert.risk_score} <span style={{ fontSize: '1rem', color: 'var(--text-subtle)' }}>/ 100</span>
            </div>
          </div>
          <div style={{ maxWidth: '60%', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
            <strong>Reasoning: </strong>{alert.explanation}
          </div>
        </div>

        {/* Endpoints & Context */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px' }}>
          <div className="card" style={{ padding: '12px 16px' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '4px' }}>Source Endpoint</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--accent-blue)' }}>
              {alert.src_ip || 'N/A'}{alert.src_port ? `:${alert.src_port}` : ''}
            </div>
          </div>
          <div className="card" style={{ padding: '12px 16px' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '4px' }}>Target Destination</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--accent-emerald)' }}>
              {alert.dst_ip || 'N/A'}{alert.dst_port ? `:${alert.dst_port}` : ''}
            </div>
          </div>
        </div>

        {/* Triggering Evidence */}
        <div style={{ marginBottom: '20px' }}>
          <h4 style={{ fontSize: '0.875rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '8px' }}>
            Triggering Evidence & Measurements
          </h4>
          <pre
            style={{
              backgroundColor: 'var(--bg-primary)',
              border: '1px solid var(--border-color)',
              borderRadius: '8px',
              padding: '12px',
              fontSize: '0.8rem',
              color: '#38bdf8',
              overflowX: 'auto',
            }}
          >
            {JSON.stringify(parsedEvidence, null, 2)}
          </pre>
        </div>

        {/* Associated Flows */}
        {flowIds.length > 0 && (
          <div style={{ marginBottom: '20px' }}>
            <h4 style={{ fontSize: '0.875rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '8px' }}>
              Associated Flow Identifiers
            </h4>
            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
              {flowIds.map((fid) => (
                <span key={fid} className="badge" style={{ backgroundColor: 'var(--bg-primary)', border: '1px solid var(--border-color)' }}>
                  Flow #{fid}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Incident Management Section */}
        <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '20px' }}>
          <h4 style={{ fontSize: '0.875rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '12px' }}>
            SOC Incident Management
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'flex', gap: '12px' }}>
              {(['OPEN', 'INVESTIGATING', 'RESOLVED'] as IncidentStatusType[]).map((st) => (
                <button
                  key={st}
                  type="button"
                  onClick={() => setStatus(st)}
                  className={`btn ${status === st ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ flex: 1, justifyContent: 'center' }}
                >
                  {st === 'RESOLVED' ? <CheckCircle size={14} /> : <Clock size={14} />}
                  {st}
                </button>
              ))}
            </div>

            <textarea
              placeholder="Add investigator triage notes..."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={3}
              style={{
                width: '100%',
                backgroundColor: 'var(--bg-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '8px',
                padding: '10px',
                color: 'var(--text-main)',
                fontSize: '0.875rem',
                fontFamily: 'var(--font-sans)',
                outline: 'none',
              }}
            />

            {feedback && (
              <div style={{ fontSize: '0.85rem', color: feedback.startsWith('Error') ? 'var(--accent-rose)' : 'var(--accent-emerald)' }}>
                {feedback}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button className="btn btn-secondary" onClick={onClose}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                {saving ? 'Updating...' : 'Save Incident State'}
              </button>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};
