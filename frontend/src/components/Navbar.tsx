import React from 'react';
import { ShieldAlert, BarChart3, Network, UploadCloud, LayoutDashboard, Share2 } from 'lucide-react';
import { HealthStatus, PcapRecord } from '../types';

export type TabType = 'overview' | 'analytics' | 'topology' | 'flows' | 'alerts' | 'upload';

interface Props {
  activeTab: TabType;
  onTabChange: (tab: TabType) => void;
  health: HealthStatus | null;
  selectedPcap: PcapRecord | null;
  pcaps: PcapRecord[];
  onSelectPcap: (pcap: PcapRecord | null) => void;
  alertCount: number;
}

export const Navbar: React.FC<Props> = ({
  activeTab,
  onTabChange,
  health,
  selectedPcap,
  pcaps,
  onSelectPcap,
  alertCount,
}) => {
  const navItems = [
    { id: 'overview' as TabType, label: 'Overview', icon: <LayoutDashboard size={18} /> },
    { id: 'analytics' as TabType, label: 'Traffic Analytics', icon: <BarChart3 size={18} /> },
    { id: 'topology' as TabType, label: 'Network Topology', icon: <Share2 size={18} /> },
    { id: 'flows' as TabType, label: 'Flow Explorer', icon: <Network size={18} /> },
    {
      id: 'alerts' as TabType,
      label: 'Threat Alerts',
      icon: <ShieldAlert size={18} />,
      badge: alertCount > 0 ? alertCount : undefined,
    },
    { id: 'upload' as TabType, label: 'PCAP Ingestion', icon: <UploadCloud size={18} /> },
  ];

  return (
    <aside className="sidebar">
      {/* Brand Header */}
      <div style={{ padding: '24px 20px', borderBottom: '1px solid var(--border-color)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div
            style={{
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              backgroundColor: 'rgba(56, 189, 248, 0.15)',
              border: '1px solid rgba(56, 189, 248, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-blue)',
            }}
          >
            🛡️
          </div>
          <div>
            <h1 style={{ fontSize: '1rem', fontWeight: 800, color: 'var(--text-main)', letterSpacing: '-0.025em' }}>
              NetShield
            </h1>
            <div style={{ fontSize: '0.7rem', color: 'var(--accent-blue)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Threat Analytics SOC
            </div>
          </div>
        </div>
      </div>

      {/* Capture Selector */}
      <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-color)' }}>
        <label style={{ fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-subtle)', marginBottom: '6px', display: 'block' }}>
          Active Capture Filter
        </label>
        <select
          value={selectedPcap ? selectedPcap.id : ''}
          onChange={(e) => {
            const val = e.target.value;
            if (!val) onSelectPcap(null);
            else {
              const found = pcaps.find((p) => p.id === Number(val));
              onSelectPcap(found || null);
            }
          }}
          style={{
            width: '100%',
            backgroundColor: 'var(--bg-primary)',
            border: '1px solid var(--border-color)',
            borderRadius: '6px',
            color: 'var(--text-main)',
            padding: '6px 10px',
            fontSize: '0.8rem',
            fontFamily: 'var(--font-sans)',
            outline: 'none',
          }}
        >
          <option value="">All Captures (Aggregated)</option>
          {pcaps.map((p) => (
            <option key={p.id} value={p.id}>
              {p.filename} ({p.packet_count} pkts)
            </option>
          ))}
        </select>
      </div>

      {/* Navigation Links */}
      <nav style={{ padding: '16px 12px', display: 'flex', flexDirection: 'column', gap: '4px', flex: 1 }}>
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '10px 14px',
                borderRadius: '8px',
                border: 'none',
                backgroundColor: isActive ? 'rgba(56, 189, 248, 0.12)' : 'transparent',
                color: isActive ? 'var(--accent-blue)' : 'var(--text-muted)',
                fontWeight: isActive ? 600 : 500,
                fontSize: '0.875rem',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                textAlign: 'left',
                width: '100%',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ color: isActive ? 'var(--accent-blue)' : 'var(--text-subtle)' }}>
                  {item.icon}
                </span>
                <span>{item.label}</span>
              </div>
              {item.badge !== undefined && (
                <span
                  style={{
                    backgroundColor: 'var(--accent-rose)',
                    color: '#fff',
                    borderRadius: '9999px',
                    fontSize: '0.7rem',
                    padding: '2px 7px',
                    fontWeight: 700,
                  }}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Health Check & Version Status Footer */}
      <div style={{ padding: '16px 20px', borderTop: '1px solid var(--border-color)', backgroundColor: 'var(--bg-primary)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
          <div
            style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: health?.status === 'healthy' ? 'var(--accent-emerald)' : 'var(--accent-rose)',
            }}
          />
          <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)' }}>
            Core Backend: {health?.status || 'Connecting...'}
          </span>
        </div>
        <div style={{ fontSize: '0.7rem', color: 'var(--text-subtle)', display: 'flex', justifyContent: 'space-between' }}>
          <span>DB: {health?.database || 'sqlite'}</span>
          <span>v{health?.version || '0.1.0'}</span>
        </div>
      </div>
    </aside>
  );
};
