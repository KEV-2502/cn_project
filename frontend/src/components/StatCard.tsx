import React from 'react';

interface Props {
  title: string;
  value: string | number;
  sublabel?: string;
  icon?: React.ReactNode;
  variant?: 'default' | 'danger' | 'warning' | 'success';
}

export const StatCard: React.FC<Props> = ({
  title,
  value,
  sublabel,
  icon,
  variant = 'default',
}) => {
  let valColor = 'var(--text-main)';
  if (variant === 'danger') valColor = 'var(--accent-rose)';
  if (variant === 'warning') valColor = 'var(--accent-amber)';
  if (variant === 'success') valColor = 'var(--accent-emerald)';

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span className="card-title">{title}</span>
        {icon && <span style={{ color: 'var(--text-subtle)' }}>{icon}</span>}
      </div>
      <div style={{ fontSize: '1.875rem', fontWeight: 700, color: valColor, letterSpacing: '-0.025em' }}>
        {value}
      </div>
      {sublabel && (
        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          {sublabel}
        </div>
      )}
    </div>
  );
};
