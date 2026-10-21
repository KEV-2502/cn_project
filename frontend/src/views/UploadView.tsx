import React, { useState } from 'react';
import { UploadCloud, FileText, CheckCircle2, AlertCircle, Trash2 } from 'lucide-react';
import { PcapRecord } from '../types';
import { uploadPcap, deletePcap } from '../services/api';
import { StatusBadge } from '../components/StatusBadge';

interface Props {
  pcaps: PcapRecord[];
  selectedPcap: PcapRecord | null;
  onSelectPcap: (pcap: PcapRecord | null) => void;
  onRefreshPcaps: () => void;
}

export const UploadView: React.FC<Props> = ({
  pcaps,
  selectedPcap,
  onSelectPcap,
  onRefreshPcaps,
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selected = e.target.files[0];
      const ext = selected.name.toLowerCase();
      if (!ext.endsWith('.pcap') && !ext.endsWith('.pcapng') && !ext.endsWith('.cap')) {
        setUploadError('Invalid file format. Please upload a .pcap, .pcapng, or .cap file.');
        setFile(null);
        return;
      }
      setUploadError(null);
      setFile(selected);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setUploadError(null);
    setUploadSuccess(null);

    try {
      const record = await uploadPcap(file);
      setUploadSuccess(`Uploaded "${record.filename}" successfully. Flow analysis initiated.`);
      setFile(null);
      onRefreshPcaps();
      onSelectPcap(record);
    } catch (err: any) {
      setUploadError(err.message || 'Failed to upload PCAP file.');
    } finally {
      setUploading(false);
    }
  };

  const handleDelete = async (id: number) => {
    if (!window.confirm('Delete this capture and its associated flows and alerts?')) return;
    try {
      await deletePcap(id);
      if (selectedPcap?.id === id) {
        onSelectPcap(null);
      }
      onRefreshPcaps();
    } catch (err: any) {
      alert(`Delete failed: ${err.message}`);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Upload Drop Zone Card */}
      <div className="card">
        <h3 style={{ fontSize: '1.125rem', fontWeight: 600, marginBottom: '8px' }}>
          Upload Network Packet Capture
        </h3>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '20px' }}>
          Select a libpcap/tcpdump capture file (.pcap, .pcapng, .cap). The ingestion engine will validate file integrity, compute a SHA256 checksum, aggregate bidirectional flows, and run detection rules.
        </p>

        <div
          style={{
            border: '2px dashed var(--border-color)',
            borderRadius: '10px',
            padding: '36px 20px',
            textAlign: 'center',
            backgroundColor: 'rgba(15, 21, 35, 0.4)',
            cursor: 'pointer',
          }}
          onClick={() => document.getElementById('pcap-file-input')?.click()}
        >
          <UploadCloud size={40} color="var(--accent-blue)" style={{ margin: '0 auto 12px auto' }} />
          <div style={{ fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px' }}>
            {file ? file.name : 'Click to browse or drop PCAP file here'}
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            {file ? `${formatBytes(file.size)}` : 'Supports standard PCAP / PCAPNG up to 100 MB'}
          </div>
          <input
            id="pcap-file-input"
            type="file"
            accept=".pcap,.pcapng,.cap"
            style={{ display: 'none' }}
            onChange={handleFileChange}
          />
        </div>

        {uploadError && (
          <div style={{ marginTop: '14px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--accent-rose)', fontSize: '0.875rem' }}>
            <AlertCircle size={16} /> {uploadError}
          </div>
        )}

        {uploadSuccess && (
          <div style={{ marginTop: '14px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--accent-emerald)', fontSize: '0.875rem' }}>
            <CheckCircle2 size={16} /> {uploadSuccess}
          </div>
        )}

        <div style={{ marginTop: '18px', display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
          {file && (
            <button className="btn btn-secondary" onClick={() => setFile(null)} disabled={uploading}>
              Clear
            </button>
          )}
          <button className="btn btn-primary" onClick={handleUpload} disabled={!file || uploading}>
            {uploading ? 'Processing Capture...' : 'Analyze PCAP'}
          </button>
        </div>
      </div>

      {/* Captured PCAP Catalog */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>
            Indexed PCAP Repositories ({pcaps.length})
          </h3>
          <button className="btn btn-secondary" onClick={onRefreshPcaps} style={{ fontSize: '0.8rem', padding: '4px 10px' }}>
            Refresh List
          </button>
        </div>

        {pcaps.length === 0 ? (
          <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            No PCAP files have been uploaded yet. Upload one above to begin.
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Capture Filename</th>
                  <th>Status</th>
                  <th>Packets</th>
                  <th>Flows</th>
                  <th>Alerts</th>
                  <th>Size</th>
                  <th>SHA256 Hash</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {pcaps.map((p) => {
                  const isSelected = selectedPcap?.id === p.id;
                  return (
                    <tr
                      key={p.id}
                      style={{
                        backgroundColor: isSelected ? 'rgba(56, 189, 248, 0.08)' : undefined,
                      }}
                    >
                      <td style={{ fontWeight: 600 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <FileText size={16} color="var(--accent-blue)" />
                          <span style={{ fontFamily: 'var(--font-mono)' }}>{p.filename}</span>
                          {isSelected && (
                            <span className="badge badge-medium" style={{ fontSize: '0.65rem' }}>ACTIVE</span>
                          )}
                        </div>
                      </td>
                      <td>
                        <StatusBadge type="pcap" value={p.status} />
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{p.packet_count.toLocaleString()}</td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{p.flow_count.toLocaleString()}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', color: p.alert_count > 0 ? 'var(--accent-rose)' : 'inherit', fontWeight: p.alert_count > 0 ? 700 : 400 }}>
                        {p.alert_count}
                      </td>
                      <td>{formatBytes(p.file_size_bytes)}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-subtle)' }} title={p.sha256_hash}>
                        {p.sha256_hash.slice(0, 10)}...
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '6px' }}>
                          <button
                            className="btn btn-secondary"
                            onClick={() => onSelectPcap(isSelected ? null : p)}
                            style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                          >
                            {isSelected ? 'Clear Filter' : 'Select'}
                          </button>
                          <button
                            className="btn btn-danger"
                            onClick={() => handleDelete(p.id)}
                            style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                            title="Delete capture"
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
};
