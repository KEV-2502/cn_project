import React, { useEffect, useState, useCallback } from 'react';
import { Navbar, TabType } from './components/Navbar';
import { OverviewView } from './views/OverviewView';
import { TrafficAnalyticsView } from './views/TrafficAnalyticsView';
import { TopologyView } from './views/TopologyView';
import { FlowExplorerView } from './views/FlowExplorerView';
import { AlertsView } from './views/AlertsView';
import { UploadView } from './views/UploadView';
import { fetchHealth, fetchPcaps, fetchOverviewStats } from './services/api';
import { HealthStatus, PcapRecord, OverviewStats } from './types';
import { RefreshCw } from 'lucide-react';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [pcaps, setPcaps] = useState<PcapRecord[]>([]);
  const [selectedPcap, setSelectedPcap] = useState<PcapRecord | null>(null);
  const [overviewStats, setOverviewStats] = useState<OverviewStats | null>(null);
  const [loadingStats, setLoadingStats] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);

  const loadData = useCallback(async () => {
    try {
      const [hRes, pRes] = await Promise.all([
        fetchHealth().catch(() => null),
        fetchPcaps().catch(() => []),
      ]);
      if (hRes) setHealth(hRes);
      setPcaps(pRes);

      const statsRes = await fetchOverviewStats(selectedPcap?.id).catch(() => null);
      setOverviewStats(statsRes);
    } catch (e) {
      console.error('Data refresh error:', e);
    } finally {
      setLoadingStats(false);
      setRefreshing(false);
    }
  }, [selectedPcap]);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, [loadData]);

  const handleManualRefresh = () => {
    setRefreshing(true);
    loadData();
  };

  const getPageTitle = () => {
    switch (activeTab) {
      case 'overview':
        return 'Executive Threat Intelligence & Operations Overview';
      case 'analytics':
        return 'Network Traffic Analytics & Protocol Telemetry';
      case 'topology':
        return 'Interactive Network Topology & Communication Map';
      case 'flows':
        return 'Bidirectional Flow Explorer & Anomaly Inspection';
      case 'alerts':
        return 'Security Alerts & Incident Response Triage';
      case 'upload':
        return 'PCAP Ingestion & Packet Parsing Engine';
      default:
        return 'Security Operations Console';
    }
  };

  return (
    <div className="app-container">
      {/* Navigation Sidebar */}
      <Navbar
        activeTab={activeTab}
        onTabChange={(tab) => setActiveTab(tab)}
        health={health}
        selectedPcap={selectedPcap}
        pcaps={pcaps}
        onSelectPcap={(pcap) => setSelectedPcap(pcap)}
        alertCount={overviewStats?.total_alerts || 0}
      />

      {/* Main Workspace */}
      <main className="main-content">
        {/* Sticky Topbar */}
        <header className="topbar">
          <div>
            <h2 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-main)' }}>
              {getPageTitle()}
            </h2>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {selectedPcap && (
              <span className="badge badge-medium" style={{ fontSize: '0.75rem' }}>
                Filtered: {selectedPcap.filename}
              </span>
            )}
            <button
              className="btn btn-secondary"
              onClick={handleManualRefresh}
              disabled={refreshing}
              style={{ fontSize: '0.8rem', padding: '6px 12px' }}
            >
              <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
              {refreshing ? 'Syncing...' : 'Sync'}
            </button>
          </div>
        </header>

        {/* View Router */}
        <div className="page-body">
          {activeTab === 'overview' && (
            <OverviewView
              stats={overviewStats}
              loading={loadingStats}
              selectedPcap={selectedPcap}
              onNavigateUpload={() => setActiveTab('upload')}
              onNavigateAlerts={() => setActiveTab('alerts')}
            />
          )}

          {activeTab === 'analytics' && (
            <TrafficAnalyticsView
              selectedPcap={selectedPcap}
              onNavigateUpload={() => setActiveTab('upload')}
            />
          )}

          {activeTab === 'topology' && (
            <TopologyView
              selectedPcap={selectedPcap}
              onNavigateUpload={() => setActiveTab('upload')}
              onNavigateFlows={() => setActiveTab('flows')}
              onNavigateAlerts={() => setActiveTab('alerts')}
            />
          )}

          {activeTab === 'flows' && (
            <FlowExplorerView
              selectedPcap={selectedPcap}
              onNavigateUpload={() => setActiveTab('upload')}
            />
          )}

          {activeTab === 'alerts' && (
            <AlertsView
              selectedPcap={selectedPcap}
              onNavigateUpload={() => setActiveTab('upload')}
            />
          )}

          {activeTab === 'upload' && (
            <UploadView
              pcaps={pcaps}
              selectedPcap={selectedPcap}
              onSelectPcap={(pcap) => setSelectedPcap(pcap)}
              onRefreshPcaps={loadData}
            />
          )}
        </div>
      </main>
    </div>
  );
};
