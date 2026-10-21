import React from 'react';
import { UploadCloud, ShieldAlert, ArrowRight } from 'lucide-react';

interface Props {
  title: string;
  description: string;
  actionText?: string;
  onAction?: () => void;
  icon?: 'upload' | 'shield';
}

export const EmptyState: React.FC<Props> = ({
  title,
  description,
  actionText = 'Upload PCAP Capture',
  onAction,
  icon = 'upload',
}) => {
  return (
    <div
      className="card"
      style={{
        padding: '60px 24px',
        textAlign: 'center',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '16px',
        borderStyle: 'dashed',
        backgroundColor: 'rgba(20, 28, 46, 0.4)',
      }}
    >
      <div
        style={{
          width: '56px',
          height: '56px',
          borderRadius: '50%',
          backgroundColor: 'rgba(56, 189, 248, 0.1)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--accent-blue)',
        }}
      >
        {icon === 'upload' ? <UploadCloud size={28} /> : <ShieldAlert size={28} />}
      </div>
      <div>
        <h3 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '4px' }}>
          {title}
        </h3>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', maxWidth: '420px', margin: '0 auto' }}>
          {description}
        </p>
      </div>
      {onAction && (
        <button className="btn btn-primary" onClick={onAction} style={{ marginTop: '8px' }}>
          {actionText}
          <ArrowRight size={16} />
        </button>
      )}
    </div>
  );
};
