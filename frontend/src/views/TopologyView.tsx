import React, { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import {
  Share2,
  Filter,
  Search,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  ShieldAlert,
  ArrowRight,
  ExternalLink,
  X,
  Info,
  Maximize2,
} from 'lucide-react';
import { fetchTopology } from '../services/api';
import {
  TopologyResponse,
  TopologyNode,
  TopologyEdge,
  PcapRecord,
} from '../types';
import { EmptyState } from '../components/EmptyState';

interface Props {
  selectedPcap: PcapRecord | null;
  onNavigateUpload: () => void;
  onNavigateFlows?: (ip?: string) => void;
  onNavigateAlerts?: (ip?: string) => void;
}

interface NodePosition {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

export const TopologyView: React.FC<Props> = ({
  selectedPcap,
  onNavigateUpload,
  onNavigateFlows,
  onNavigateAlerts,
}) => {
  // Data state
  const [data, setData] = useState<TopologyResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [protocol, setProtocol] = useState<string>('');
  const [onlyAlerts, setOnlyAlerts] = useState<boolean>(false);
  const [minFlows, setMinFlows] = useState<number>(1);
  const [limitNodes, setLimitNodes] = useState<number>(50);
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Selection
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);

  // Canvas pan & zoom
  const [zoom, setZoom] = useState<number>(1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState<boolean>(false);
  const [panStart, setPanStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  // Node positions in canvas coordinates
  const [positions, setPositions] = useState<Record<string, NodePosition>>({});
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const [dragOffset, setDragOffset] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  // Hover Tooltip
  const [hoveredNode, setHoveredNode] = useState<{ node: TopologyNode; x: number; y: number } | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<{ edge: TopologyEdge; x: number; y: number } | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  // Load topology data from server
  const loadData = useCallback(() => {
    setLoading(true);
    fetchTopology({
      pcap_id: selectedPcap?.id,
      protocol: protocol || undefined,
      only_alerts: onlyAlerts,
      min_flows: minFlows,
      limit_nodes: limitNodes,
    })
      .then((res) => {
        setData(res);
        setError(null);
        setSelectedNodeId(null);
        setSelectedEdgeId(null);
      })
      .catch((err) => {
        console.error('Topology load error:', err);
        setError(err.message || 'Failed to load topology');
      })
      .finally(() => setLoading(false));
  }, [selectedPcap, protocol, onlyAlerts, minFlows, limitNodes]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Compute Layout Simulation when data changes
  useEffect(() => {
    if (!data || data.nodes.length === 0) {
      setPositions({});
      return;
    }

    const width = 1000;
    const height = 650;
    const cx = width / 2;
    const cy = height / 2;
    const count = data.nodes.length;

    // Initial arrangement: circular layout around center
    const newPos: Record<string, NodePosition> = {};
    const radius = Math.min(width, height) * 0.35;

    data.nodes.forEach((node, idx) => {
      const angle = (2 * Math.PI * idx) / count;
      newPos[node.id] = {
        x: cx + radius * Math.cos(angle) + (Math.random() - 0.5) * 20,
        y: cy + radius * Math.sin(angle) + (Math.random() - 0.5) * 20,
        vx: 0,
        vy: 0,
      };
    });

    // Run force-directed relaxation
    const nodeIds = data.nodes.map((n) => n.id);
    const edgeList = data.edges;
    const iterations = Math.min(150, 60 + count * 3);
    const kRepel = 12000;
    const restLength = Math.max(120, Math.min(220, 800 / Math.sqrt(count + 1)));
    const kSpring = 0.04;
    const kCenter = 0.015;

    for (let iter = 0; iter < iterations; iter++) {
      const alpha = 1.0 - iter / iterations; // cooling temperature

      // 1. Repulsion between all node pairs
      for (let i = 0; i < count; i++) {
        const idA = nodeIds[i];
        const pA = newPos[idA];
        for (let j = i + 1; j < count; j++) {
          const idB = nodeIds[j];
          const pB = newPos[idB];
          const dx = pA.x - pB.x;
          const dy = pA.y - pB.y;
          const distSq = dx * dx + dy * dy + 10;
          const dist = Math.sqrt(distSq);
          const force = (kRepel / distSq) * alpha;
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;

          pA.vx += fx;
          pA.vy += fy;
          pB.vx -= fx;
          pB.vy -= fy;
        }
      }

      // 2. Spring attraction along edges
      for (const edge of edgeList) {
        const pSrc = newPos[edge.source];
        const pTgt = newPos[edge.target];
        if (!pSrc || !pTgt) continue;

        const dx = pTgt.x - pSrc.x;
        const dy = pTgt.y - pSrc.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const displacement = dist - restLength;
        const force = displacement * kSpring * alpha;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;

        pSrc.vx += fx;
        pSrc.vy += fy;
        pTgt.vx -= fx;
        pTgt.vy -= fy;
      }

      // 3. Center gravity and update positions
      for (let i = 0; i < count; i++) {
        const id = nodeIds[i];
        const p = newPos[id];
        const cdx = cx - p.x;
        const cdy = cy - p.y;
        p.vx += cdx * kCenter * alpha;
        p.vy += cdy * kCenter * alpha;

        // Apply velocity with damping
        p.x += p.vx * 0.7;
        p.y += p.vy * 0.7;
        p.vx *= 0.4;
        p.vy *= 0.4;

        // Keep inside bounds
        p.x = Math.max(60, Math.min(width - 60, p.x));
        p.y = Math.max(60, Math.min(height - 60, p.y));
      }
    }

    setPositions(newPos);
  }, [data]);

  // Node radius scaling based on traffic volume
  const getNodeRadius = useCallback(
    (totalBytes: number) => {
      if (!data || data.nodes.length === 0) return 24;
      const maxBytes = Math.max(...data.nodes.map((n) => n.total_bytes), 1);
      const ratio = Math.log1p(totalBytes) / Math.log1p(maxBytes);
      return Math.round(20 + ratio * 16); // 20px to 36px
    },
    [data]
  );

  // Edge stroke width scaling based on flow count
  const getEdgeWidth = useCallback(
    (flowCount: number) => {
      if (!data || data.edges.length === 0) return 1.5;
      const maxFlows = Math.max(...data.edges.map((e) => e.flow_count), 1);
      const ratio = flowCount / maxFlows;
      return Math.max(1.5, Math.min(6, 1.5 + ratio * 4.5));
    },
    [data]
  );

  // Determine node color theme based on threat level
  const getNodeColor = useCallback((node: TopologyNode) => {
    if (node.max_severity === 'CRITICAL' || node.max_severity === 'HIGH') {
      return {
        fill: '#1e1018',
        stroke: '#f43f5e',
        glow: 'rgba(244, 63, 94, 0.4)',
        badgeClass: 'badge-critical',
      };
    }
    if (node.max_severity === 'MEDIUM') {
      return {
        fill: '#1c150c',
        stroke: '#f59e0b',
        glow: 'rgba(245, 158, 11, 0.35)',
        badgeClass: 'badge-high',
      };
    }
    if (node.max_severity === 'LOW') {
      return {
        fill: '#0d181e',
        stroke: '#38bdf8',
        glow: 'rgba(56, 189, 248, 0.3)',
        badgeClass: 'badge-medium',
      };
    }
    return {
      fill: '#0f172a',
      stroke: '#0ea5e9',
      glow: 'rgba(14, 165, 233, 0.25)',
      badgeClass: 'badge-low',
    };
  }, []);

  // Set of neighboring node IDs for active selection
  const neighborNodeIds = useMemo(() => {
    if (!selectedNodeId || !data) return new Set<string>();
    const neighbors = new Set<string>();
    neighbors.add(selectedNodeId);
    data.edges.forEach((e) => {
      if (e.source === selectedNodeId) neighbors.add(e.target);
      if (e.target === selectedNodeId) neighbors.add(e.source);
    });
    return neighbors;
  }, [selectedNodeId, data]);

  // Selected node object
  const selectedNode = useMemo(() => {
    if (!selectedNodeId || !data) return null;
    return data.nodes.find((n) => n.id === selectedNodeId) || null;
  }, [selectedNodeId, data]);

  // Selected edge object
  const selectedEdge = useMemo(() => {
    if (!selectedEdgeId || !data) return null;
    return data.edges.find((e) => e.id === selectedEdgeId) || null;
  }, [selectedEdgeId, data]);

  // Zoom handlers
  const handleZoomIn = () => setZoom((z) => Math.min(2.5, z + 0.2));
  const handleZoomOut = () => setZoom((z) => Math.max(0.4, z - 0.2));
  const handleResetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    setSelectedNodeId(null);
    setSelectedEdgeId(null);
  };

  // Canvas Pan Handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    // Only pan if clicking canvas background (not node)
    if (e.target === svgRef.current || (e.target as HTMLElement).tagName === 'rect') {
      setIsPanning(true);
      setPanStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isPanning) {
      setPan({ x: e.clientX - panStart.x, y: e.clientY - panStart.y });
    } else if (draggingNodeId) {
      const svg = svgRef.current;
      if (!svg) return;
      const rect = svg.getBoundingClientRect();
      const currentX = (e.clientX - rect.left - pan.x) / zoom;
      const currentY = (e.clientY - rect.top - pan.y) / zoom;

      setPositions((prev) => ({
        ...prev,
        [draggingNodeId]: {
          ...prev[draggingNodeId],
          x: currentX - dragOffset.x,
          y: currentY - dragOffset.y,
        },
      }));
    }
  };

  const handleMouseUp = () => {
    setIsPanning(false);
    setDraggingNodeId(null);
  };

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -0.1 : 0.1;
    setZoom((z) => Math.min(2.5, Math.max(0.4, z + delta)));
  };

  // Node Drag Start
  const handleNodeDragStart = (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    const pos = positions[id];
    if (!pos || !svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const mouseX = (e.clientX - rect.left - pan.x) / zoom;
    const mouseY = (e.clientY - rect.top - pan.y) / zoom;

    setDraggingNodeId(id);
    setDragOffset({ x: mouseX - pos.x, y: mouseY - pos.y });
    setSelectedNodeId(id);
    setSelectedEdgeId(null);
  };

  // Format bytes helper
  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };

  if (loading && !data) {
    return (
      <div style={{ padding: '80px 0', textAlign: 'center', color: 'var(--text-muted)' }}>
        <Share2 size={32} className="animate-spin" style={{ margin: '0 auto 16px', color: 'var(--accent-blue)' }} />
        <div style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-main)' }}>
          Aggregating Network Topology Graph...
        </div>
        <div style={{ fontSize: '0.8rem', color: 'var(--text-subtle)', marginTop: '4px' }}>
          Mapping observed hosts, communications, and threat correlations from flow database.
        </div>
      </div>
    );
  }

  if (error || !data || data.nodes.length === 0) {
    return (
      <EmptyState
        title="No Network Topology Available"
        description={
          error ||
          (selectedPcap
            ? `Capture '${selectedPcap.filename}' contains no flows matching the current filter criteria.`
            : 'No flow data currently exists in the platform. Upload a PCAP capture to explore host topology and attack paths.')
        }
        onAction={onNavigateUpload}
        actionText="Upload PCAP Capture"
      />
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', height: 'calc(100vh - 110px)' }}>
      {/* 1. Header Filter & Control Toolbar */}
      <div
        className="card"
        style={{
          padding: '12px 18px',
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '12px',
        }}
      >
        {/* Left: Filters */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Filter size={15} style={{ color: 'var(--accent-blue)' }} />
            <span style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-subtle)' }}>
              Filters:
            </span>
          </div>

          {/* Protocol Selector */}
          <select
            value={protocol}
            onChange={(e) => setProtocol(e.target.value)}
            style={{
              backgroundColor: 'var(--bg-primary)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              color: 'var(--text-main)',
              padding: '5px 10px',
              fontSize: '0.8rem',
            }}
          >
            <option value="">All Protocols</option>
            <option value="TCP">TCP Only</option>
            <option value="UDP">UDP Only</option>
            <option value="DNS">DNS Only</option>
            <option value="ICMP">ICMP Only</option>
          </select>

          {/* Min Flows Threshold */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Min Flows:</label>
            <select
              value={minFlows}
              onChange={(e) => setMinFlows(Number(e.target.value))}
              style={{
                backgroundColor: 'var(--bg-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                color: 'var(--text-main)',
                padding: '5px 10px',
                fontSize: '0.8rem',
              }}
            >
              <option value="1">≥ 1 flow</option>
              <option value="2">≥ 2 flows</option>
              <option value="5">≥ 5 flows</option>
              <option value="10">≥ 10 flows</option>
            </select>
          </div>

          {/* Alerted Hosts Toggle */}
          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.8rem',
              color: onlyAlerts ? 'var(--accent-rose)' : 'var(--text-muted)',
              cursor: 'pointer',
              userSelect: 'none',
              padding: '4px 8px',
              borderRadius: '6px',
              backgroundColor: onlyAlerts ? 'rgba(244, 63, 94, 0.15)' : 'transparent',
              border: onlyAlerts ? '1px solid rgba(244, 63, 94, 0.4)' : '1px solid transparent',
            }}
          >
            <input
              type="checkbox"
              checked={onlyAlerts}
              onChange={(e) => setOnlyAlerts(e.target.checked)}
              style={{ cursor: 'pointer' }}
            />
            <ShieldAlert size={14} />
            Alerted Hosts Only
          </label>

          {/* Limit Nodes */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Max Nodes:</label>
            <select
              value={limitNodes}
              onChange={(e) => setLimitNodes(Number(e.target.value))}
              style={{
                backgroundColor: 'var(--bg-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                color: 'var(--text-main)',
                padding: '5px 10px',
                fontSize: '0.8rem',
              }}
            >
              <option value="25">25 Hosts</option>
              <option value="50">50 Hosts</option>
              <option value="100">100 Hosts</option>
              <option value="200">200 Hosts</option>
            </select>
          </div>
        </div>

        {/* Right: Search & Reset */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: '10px', top: '9px', color: 'var(--text-subtle)' }} />
            <input
              type="text"
              placeholder="Search Host IP..."
              value={searchQuery}
              onChange={(e) => {
                const val = e.target.value.trim();
                setSearchQuery(val);
                if (val && data) {
                  const match = data.nodes.find((n) => n.ip.includes(val));
                  if (match) {
                    setSelectedNodeId(match.id);
                    setSelectedEdgeId(null);
                  }
                }
              }}
              style={{
                paddingLeft: '30px',
                paddingRight: '12px',
                paddingTop: '6px',
                paddingBottom: '6px',
                fontSize: '0.8rem',
                backgroundColor: 'var(--bg-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                color: 'var(--text-main)',
                width: '180px',
              }}
            />
          </div>

          {(selectedNodeId || selectedEdgeId) && (
            <button
              className="btn btn-secondary"
              onClick={() => {
                setSelectedNodeId(null);
                setSelectedEdgeId(null);
              }}
              style={{ fontSize: '0.75rem', padding: '6px 10px' }}
            >
              <X size={14} /> Clear Focus
            </button>
          )}

          <button
            className="btn btn-secondary"
            onClick={handleResetView}
            title="Reset Pan & Zoom"
            style={{ fontSize: '0.75rem', padding: '6px 10px' }}
          >
            <RotateCcw size={14} /> Reset View
          </button>
        </div>
      </div>

      {/* 2. Main Graph Workspace */}
      <div
        ref={containerRef}
        style={{
          flex: 1,
          position: 'relative',
          backgroundColor: 'var(--bg-primary)',
          border: '1px solid var(--border-color)',
          borderRadius: '12px',
          overflow: 'hidden',
          cursor: isPanning ? 'grabbing' : 'default',
        }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onWheel={handleWheel}
      >
        {/* Floating Zoom Controls */}
        <div
          style={{
            position: 'absolute',
            bottom: '20px',
            right: '20px',
            display: 'flex',
            flexDirection: 'column',
            gap: '6px',
            zIndex: 10,
          }}
        >
          <button
            className="btn btn-secondary"
            onClick={handleZoomIn}
            title="Zoom In"
            style={{ width: '36px', height: '36px', padding: 0, justifyContent: 'center' }}
          >
            <ZoomIn size={16} />
          </button>
          <button
            className="btn btn-secondary"
            onClick={handleZoomOut}
            title="Zoom Out"
            style={{ width: '36px', height: '36px', padding: 0, justifyContent: 'center' }}
          >
            <ZoomOut size={16} />
          </button>
          <button
            className="btn btn-secondary"
            onClick={handleResetView}
            title="Fit to Screen"
            style={{ width: '36px', height: '36px', padding: 0, justifyContent: 'center' }}
          >
            <Maximize2 size={16} />
          </button>
        </div>

        {/* Truncation Warning Notice */}
        {data.summary.is_truncated && (
          <div
            style={{
              position: 'absolute',
              top: '16px',
              left: '16px',
              zIndex: 10,
              backgroundColor: 'rgba(245, 158, 11, 0.15)',
              border: '1px solid rgba(245, 158, 11, 0.4)',
              borderRadius: '8px',
              padding: '6px 12px',
              fontSize: '0.75rem',
              color: '#fcd34d',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <Info size={14} />
            Showing top {data.nodes.length} of {data.summary.total_unfiltered_nodes} hosts (ranked by threat & volume)
          </div>
        )}

        {/* Interactive SVG Canvas */}
        <svg
          ref={svgRef}
          width="100%"
          height="100%"
          style={{ display: 'block', width: '100%', height: '100%' }}
        >
          <defs>
            {/* Arrow Markers for Directional Edges */}
            <marker
              id="arrow-normal"
              viewBox="0 0 10 10"
              refX="18"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(148, 163, 184, 0.5)" />
            </marker>
            <marker
              id="arrow-alert"
              viewBox="0 0 10 10"
              refX="18"
              refY="5"
              markerWidth="7"
              markerHeight="7"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#f43f5e" />
            </marker>
            <marker
              id="arrow-highlight"
              viewBox="0 0 10 10"
              refX="18"
              refY="5"
              markerWidth="7"
              markerHeight="7"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#38bdf8" />
            </marker>
          </defs>

          {/* Transform group for Pan & Zoom */}
          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* 1. EDGES */}
            {data.edges.map((edge) => {
              const srcPos = positions[edge.source];
              const tgtPos = positions[edge.target];
              if (!srcPos || !tgtPos) return null;

              const isEdgeSelected = selectedEdgeId === edge.id;
              const isConnectedToSelectedNode =
                selectedNodeId === edge.source || selectedNodeId === edge.target;
              const isDimmed =
                (selectedNodeId && !isConnectedToSelectedNode) ||
                (selectedEdgeId && !isEdgeSelected);

              const strokeWidth = getEdgeWidth(edge.flow_count);

              let strokeColor = 'rgba(148, 163, 184, 0.35)';
              let markerId = 'url(#arrow-normal)';

              if (edge.has_alerts) {
                strokeColor = isDimmed ? 'rgba(244, 63, 94, 0.3)' : '#f43f5e';
                markerId = 'url(#arrow-alert)';
              }

              if (isEdgeSelected || isConnectedToSelectedNode) {
                strokeColor = edge.has_alerts ? '#f43f5e' : '#38bdf8';
                markerId = edge.has_alerts ? 'url(#arrow-alert)' : 'url(#arrow-highlight)';
              }

              return (
                <g key={edge.id}>
                  {/* Invisible thicker stroke for easier hover/click */}
                  <line
                    x1={srcPos.x}
                    y1={srcPos.y}
                    x2={tgtPos.x}
                    y2={tgtPos.y}
                    stroke="transparent"
                    strokeWidth={Math.max(12, strokeWidth * 2.5)}
                    style={{ cursor: 'pointer' }}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedEdgeId(edge.id);
                      setSelectedNodeId(null);
                    }}
                    onMouseEnter={(e) => {
                      setHoveredEdge({ edge, x: e.clientX, y: e.clientY });
                    }}
                    onMouseLeave={() => setHoveredEdge(null)}
                  />

                  {/* Visible Edge */}
                  <line
                    x1={srcPos.x}
                    y1={srcPos.y}
                    x2={tgtPos.x}
                    y2={tgtPos.y}
                    stroke={strokeColor}
                    strokeWidth={strokeWidth}
                    strokeOpacity={isDimmed ? 0.2 : 0.85}
                    markerEnd={markerId}
                    style={{
                      transition: 'stroke 0.2s, stroke-width 0.2s, opacity 0.2s',
                    }}
                  />
                </g>
              );
            })}

            {/* 2. NODES */}
            {data.nodes.map((node) => {
              const pos = positions[node.id];
              if (!pos) return null;

              const isNodeSelected = selectedNodeId === node.id;
              const isNeighbor = neighborNodeIds.has(node.id);
              const isEdgeEndpoint =
                selectedEdge && (selectedEdge.source === node.id || selectedEdge.target === node.id);

              const isDimmed =
                (selectedNodeId && !isNeighbor) ||
                (selectedEdgeId && !isEdgeEndpoint);

              const r = getNodeRadius(node.total_bytes);
              const theme = getNodeColor(node);

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  style={{
                    cursor: 'grab',
                    opacity: isDimmed ? 0.25 : 1.0,
                    transition: 'opacity 0.2s',
                  }}
                  onMouseDown={(e) => handleNodeDragStart(e, node.id)}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedNodeId(node.id);
                    setSelectedEdgeId(null);
                  }}
                  onMouseEnter={(e) => {
                    setHoveredNode({ node, x: e.clientX, y: e.clientY });
                  }}
                  onMouseLeave={() => setHoveredNode(null)}
                >
                  {/* Pulsing ring for critical/high threats */}
                  {node.alert_count > 0 && !isDimmed && (
                    <circle
                      r={r + 8}
                      fill="none"
                      stroke={theme.stroke}
                      strokeWidth="2"
                      strokeDasharray="4 4"
                      opacity="0.6"
                      className="animate-spin"
                    />
                  )}

                  {/* Selection Glow */}
                  {(isNodeSelected || isEdgeEndpoint) && (
                    <circle
                      r={r + 6}
                      fill="none"
                      stroke={theme.stroke}
                      strokeWidth="3"
                      opacity="0.9"
                    />
                  )}

                  {/* Main Node Body */}
                  <circle
                    r={r}
                    fill={theme.fill}
                    stroke={theme.stroke}
                    strokeWidth={isNodeSelected ? '3' : '2'}
                    style={{
                      filter: `drop-shadow(0 0 8px ${theme.glow})`,
                      transition: 'r 0.2s, stroke 0.2s',
                    }}
                  />

                  {/* Center Node Icon */}
                  <text
                    textAnchor="middle"
                    dominantBaseline="central"
                    fill={theme.stroke}
                    fontSize={r >= 28 ? '14' : '11'}
                    fontWeight="700"
                    style={{ pointerEvents: 'none', userSelect: 'none' }}
                  >
                    {node.role === 'server' ? 'S' : node.role === 'client' ? 'C' : 'M'}
                  </text>

                  {/* Node IP Label */}
                  <text
                    y={r + 14}
                    textAnchor="middle"
                    fill={isNodeSelected ? '#ffffff' : 'var(--text-main)'}
                    fontSize="11"
                    fontFamily="var(--font-mono)"
                    fontWeight={isNodeSelected ? '700' : '500'}
                    style={{
                      pointerEvents: 'none',
                      userSelect: 'none',
                      textShadow: '0 1px 3px rgba(0,0,0,0.8)',
                    }}
                  >
                    {node.ip}
                  </text>

                  {/* Threat Count Pill if Alerted */}
                  {node.alert_count > 0 && (
                    <g transform={`translate(${r - 6}, ${-r + 4})`}>
                      <circle r="8" fill="#f43f5e" />
                      <text
                        textAnchor="middle"
                        dominantBaseline="central"
                        fill="#ffffff"
                        fontSize="9"
                        fontWeight="800"
                        style={{ pointerEvents: 'none', userSelect: 'none' }}
                      >
                        {node.alert_count}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}
          </g>
        </svg>

        {/* 3. Floating Details Side Panel (Host or Connection) */}
        {selectedNode && (
          <div
            className="card"
            style={{
              position: 'absolute',
              top: '16px',
              right: '16px',
              width: '340px',
              maxHeight: 'calc(100% - 32px)',
              overflowY: 'auto',
              backgroundColor: 'rgba(15, 23, 42, 0.95)',
              backdropFilter: 'blur(16px)',
              border: '1px solid var(--border-color)',
              borderRadius: '12px',
              boxShadow: '0 12px 32px rgba(0,0,0,0.7)',
              zIndex: 30,
              display: 'flex',
              flexDirection: 'column',
              gap: '14px',
            }}
          >
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px' }}>
              <div>
                <div style={{ fontSize: '0.7rem', textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
                  Host Details
                </div>
                <div style={{ fontSize: '1rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-main)' }}>
                  {selectedNode.ip}
                </div>
              </div>
              <button
                onClick={() => setSelectedNodeId(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Badges */}
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <span className={`badge ${selectedNode.alert_count > 0 ? 'badge-critical' : 'badge-low'}`}>
                {selectedNode.alert_count > 0 ? `${selectedNode.alert_count} Active Alerts` : 'Clean Host'}
              </span>
              <span className="badge badge-medium">
                {selectedNode.role.toUpperCase()} HOST
              </span>
              {selectedNode.max_severity && (
                <span className={`badge badge-${selectedNode.max_severity.toLowerCase()}`}>
                  {selectedNode.max_severity} SEVERITY
                </span>
              )}
            </div>

            {/* Quick Metrics Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              <div style={{ padding: '8px 10px', backgroundColor: 'var(--bg-primary)', borderRadius: '6px' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-subtle)' }}>Total Flows</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-main)' }}>
                  {selectedNode.total_flows}
                </div>
              </div>
              <div style={{ padding: '8px 10px', backgroundColor: 'var(--bg-primary)', borderRadius: '6px' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-subtle)' }}>Total Traffic</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--accent-blue)' }}>
                  {formatBytes(selectedNode.total_bytes)}
                </div>
              </div>
              <div style={{ padding: '8px 10px', backgroundColor: 'var(--bg-primary)', borderRadius: '6px' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-subtle)' }}>Total Packets</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-main)' }}>
                  {selectedNode.total_packets}
                </div>
              </div>
              <div style={{ padding: '8px 10px', backgroundColor: 'var(--bg-primary)', borderRadius: '6px' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-subtle)' }}>Peers</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-main)' }}>
                  {selectedNode.peer_count}
                </div>
              </div>
            </div>

            {/* Directional Traffic Bar */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', marginBottom: '4px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Sent: {formatBytes(selectedNode.sent_bytes)}</span>
                <span style={{ color: 'var(--text-muted)' }}>Recv: {formatBytes(selectedNode.received_bytes)}</span>
              </div>
              <div style={{ height: '6px', borderRadius: '3px', backgroundColor: 'var(--bg-primary)', display: 'flex', overflow: 'hidden' }}>
                <div
                  style={{
                    width: `${Math.round((selectedNode.sent_bytes / Math.max(1, selectedNode.total_bytes)) * 100)}%`,
                    backgroundColor: 'var(--accent-blue)',
                  }}
                />
                <div
                  style={{
                    width: `${Math.round((selectedNode.received_bytes / Math.max(1, selectedNode.total_bytes)) * 100)}%`,
                    backgroundColor: 'var(--accent-purple)',
                  }}
                />
              </div>
            </div>

            {/* Protocols */}
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-subtle)', marginBottom: '6px' }}>
                Protocols Observed
              </div>
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                {selectedNode.protocols.map((p) => (
                  <span key={p} className="badge badge-medium" style={{ fontSize: '0.7rem' }}>
                    {p}
                  </span>
                ))}
              </div>
            </div>

            {/* Connected Peers List */}
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-subtle)', marginBottom: '6px' }}>
                Communicating Peers ({selectedNode.peers.length})
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', maxHeight: '110px', overflowY: 'auto' }}>
                {selectedNode.peers.map((peerIp) => (
                  <div
                    key={peerIp}
                    onClick={() => {
                      setSelectedNodeId(peerIp);
                      setSelectedEdgeId(null);
                    }}
                    style={{
                      padding: '5px 8px',
                      backgroundColor: 'var(--bg-primary)',
                      borderRadius: '6px',
                      fontSize: '0.75rem',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--accent-cyan)',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                    }}
                  >
                    <span>{peerIp}</span>
                    <ArrowRight size={12} style={{ color: 'var(--text-subtle)' }} />
                  </div>
                ))}
              </div>
            </div>

            {/* Associated Threat Alerts */}
            {selectedNode.alert_count > 0 && (
              <div>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--accent-rose)', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <ShieldAlert size={14} /> Threat Alerts ({selectedNode.alerts.length})
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '140px', overflowY: 'auto' }}>
                  {selectedNode.alerts.map((al) => (
                    <div
                      key={al.id}
                      style={{
                        padding: '6px 8px',
                        backgroundColor: 'rgba(244, 63, 94, 0.1)',
                        border: '1px solid rgba(244, 63, 94, 0.3)',
                        borderRadius: '6px',
                        fontSize: '0.75rem',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontWeight: 700, color: '#fda4af' }}>{al.rule_name}</span>
                        <span className={`badge badge-${al.severity.toLowerCase()}`} style={{ fontSize: '0.65rem' }}>
                          {al.severity}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                        {al.description}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Actions */}
            <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
              {onNavigateFlows && (
                <button
                  className="btn btn-secondary"
                  onClick={() => onNavigateFlows(selectedNode.ip)}
                  style={{ flex: 1, fontSize: '0.75rem', padding: '6px 10px', justifyContent: 'center' }}
                >
                  <ExternalLink size={12} /> Explore Flows
                </button>
              )}
              {onNavigateAlerts && selectedNode.alert_count > 0 && (
                <button
                  className="btn btn-secondary"
                  onClick={() => onNavigateAlerts(selectedNode.ip)}
                  style={{ flex: 1, fontSize: '0.75rem', padding: '6px 10px', justifyContent: 'center', color: '#fda4af' }}
                >
                  <ShieldAlert size={12} /> View Alerts
                </button>
              )}
            </div>
          </div>
        )}

        {/* Selected Edge Details Panel */}
        {selectedEdge && (
          <div
            className="card"
            style={{
              position: 'absolute',
              top: '16px',
              right: '16px',
              width: '340px',
              maxHeight: 'calc(100% - 32px)',
              overflowY: 'auto',
              backgroundColor: 'rgba(15, 23, 42, 0.95)',
              backdropFilter: 'blur(16px)',
              border: '1px solid var(--border-color)',
              borderRadius: '12px',
              boxShadow: '0 12px 32px rgba(0,0,0,0.7)',
              zIndex: 30,
              display: 'flex',
              flexDirection: 'column',
              gap: '14px',
            }}
          >
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px' }}>
              <div>
                <div style={{ fontSize: '0.7rem', textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 700 }}>
                  Connection Details
                </div>
                <div style={{ fontSize: '0.85rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span>{selectedEdge.source}</span>
                  <ArrowRight size={14} style={{ color: 'var(--accent-blue)' }} />
                  <span>{selectedEdge.target}</span>
                </div>
              </div>
              <button
                onClick={() => setSelectedEdgeId(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Badges */}
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <span className={`badge ${selectedEdge.has_alerts ? 'badge-critical' : 'badge-low'}`}>
                {selectedEdge.has_alerts ? `${selectedEdge.alert_count} Alerts on Link` : 'Clean Traffic'}
              </span>
              {selectedEdge.max_severity && (
                <span className={`badge badge-${selectedEdge.max_severity.toLowerCase()}`}>
                  {selectedEdge.max_severity}
                </span>
              )}
            </div>

            {/* Quick Metrics Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              <div style={{ padding: '8px 10px', backgroundColor: 'var(--bg-primary)', borderRadius: '6px' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-subtle)' }}>Flow Count</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-main)' }}>
                  {selectedEdge.flow_count}
                </div>
              </div>
              <div style={{ padding: '8px 10px', backgroundColor: 'var(--bg-primary)', borderRadius: '6px' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-subtle)' }}>Total Bytes</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--accent-blue)' }}>
                  {formatBytes(selectedEdge.total_bytes)}
                </div>
              </div>
              <div style={{ padding: '8px 10px', backgroundColor: 'var(--bg-primary)', borderRadius: '6px' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-subtle)' }}>Forward Packets</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-main)' }}>
                  {selectedEdge.forward_packets}
                </div>
              </div>
              <div style={{ padding: '8px 10px', backgroundColor: 'var(--bg-primary)', borderRadius: '6px' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-subtle)' }}>Backward Packets</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-main)' }}>
                  {selectedEdge.backward_packets}
                </div>
              </div>
            </div>

            {/* Protocols and Observed Ports */}
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-subtle)', marginBottom: '4px' }}>
                Protocols
              </div>
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '10px' }}>
                {selectedEdge.protocols.map((p) => (
                  <span key={p} className="badge badge-medium" style={{ fontSize: '0.7rem' }}>
                    {p}
                  </span>
                ))}
              </div>

              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-subtle)', marginBottom: '4px' }}>
                Target Ports Observed ({selectedEdge.ports.length})
              </div>
              <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', maxHeight: '60px', overflowY: 'auto' }}>
                {selectedEdge.ports.map((port) => (
                  <span
                    key={port}
                    style={{
                      padding: '2px 6px',
                      backgroundColor: 'var(--bg-primary)',
                      borderRadius: '4px',
                      fontSize: '0.75rem',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--text-main)',
                      border: '1px solid var(--border-color)',
                    }}
                  >
                    {port}
                  </span>
                ))}
              </div>
            </div>

            {/* TCP States */}
            {selectedEdge.tcp_states.length > 0 && (
              <div>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-subtle)', marginBottom: '4px' }}>
                  Observed TCP States
                </div>
                <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                  {selectedEdge.tcp_states.map((st) => (
                    <span key={st} className="badge badge-low" style={{ fontSize: '0.7rem' }}>
                      {st}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Alerts on Link */}
            {selectedEdge.has_alerts && (
              <div>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--accent-rose)', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <ShieldAlert size={14} /> Correlated Alerts ({selectedEdge.alerts.length})
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '120px', overflowY: 'auto' }}>
                  {selectedEdge.alerts.map((al) => (
                    <div
                      key={al.id}
                      style={{
                        padding: '6px 8px',
                        backgroundColor: 'rgba(244, 63, 94, 0.1)',
                        border: '1px solid rgba(244, 63, 94, 0.3)',
                        borderRadius: '6px',
                        fontSize: '0.75rem',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontWeight: 700, color: '#fda4af' }}>{al.rule_name}</span>
                        <span className={`badge badge-${al.severity.toLowerCase()}`} style={{ fontSize: '0.65rem' }}>
                          {al.severity}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                        {al.description}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Action Buttons to Inspect Endpoints */}
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                className="btn btn-secondary"
                onClick={() => {
                  setSelectedNodeId(selectedEdge.source);
                  setSelectedEdgeId(null);
                }}
                style={{ flex: 1, fontSize: '0.75rem', padding: '6px 8px', justifyContent: 'center' }}
              >
                Inspect Source
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => {
                  setSelectedNodeId(selectedEdge.target);
                  setSelectedEdgeId(null);
                }}
                style={{ flex: 1, fontSize: '0.75rem', padding: '6px 8px', justifyContent: 'center' }}
              >
                Inspect Target
              </button>
            </div>
          </div>
        )}

        {/* Hover Tooltip (Node) */}
        {hoveredNode && !selectedNode && (
          <div
            style={{
              position: 'fixed',
              left: `${hoveredNode.x + 15}px`,
              top: `${hoveredNode.y - 15}px`,
              pointerEvents: 'none',
              zIndex: 40,
              backgroundColor: 'rgba(15, 23, 42, 0.95)',
              border: '1px solid var(--border-color)',
              borderRadius: '8px',
              padding: '10px 14px',
              boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
              fontSize: '0.75rem',
              color: 'var(--text-main)',
              minWidth: '180px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{hoveredNode.node.ip}</span>
              <span className={`badge ${hoveredNode.node.alert_count > 0 ? 'badge-critical' : 'badge-low'}`} style={{ fontSize: '0.65rem' }}>
                {hoveredNode.node.role.toUpperCase()}
              </span>
            </div>
            <div style={{ color: 'var(--text-muted)' }}>Flows: <strong style={{ color: 'var(--text-main)' }}>{hoveredNode.node.total_flows}</strong></div>
            <div style={{ color: 'var(--text-muted)' }}>Traffic: <strong style={{ color: 'var(--accent-blue)' }}>{formatBytes(hoveredNode.node.total_bytes)}</strong></div>
            <div style={{ color: 'var(--text-muted)' }}>Peers: <strong style={{ color: 'var(--text-main)' }}>{hoveredNode.node.peer_count}</strong></div>
            {hoveredNode.node.alert_count > 0 && (
              <div style={{ color: '#fda4af', marginTop: '4px', fontWeight: 600 }}>
                ⚠️ {hoveredNode.node.alert_count} Threat Alert(s)
              </div>
            )}
          </div>
        )}

        {/* Hover Tooltip (Edge) */}
        {hoveredEdge && !selectedEdge && (
          <div
            style={{
              position: 'fixed',
              left: `${hoveredEdge.x + 15}px`,
              top: `${hoveredEdge.y - 15}px`,
              pointerEvents: 'none',
              zIndex: 40,
              backgroundColor: 'rgba(15, 23, 42, 0.95)',
              border: '1px solid var(--border-color)',
              borderRadius: '8px',
              padding: '10px 14px',
              boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
              fontSize: '0.75rem',
              color: 'var(--text-main)',
              minWidth: '200px',
            }}
          >
            <div style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', marginBottom: '4px' }}>
              {hoveredEdge.edge.source} → {hoveredEdge.edge.target}
            </div>
            <div style={{ color: 'var(--text-muted)' }}>Flows: <strong style={{ color: 'var(--text-main)' }}>{hoveredEdge.edge.flow_count}</strong></div>
            <div style={{ color: 'var(--text-muted)' }}>Bytes: <strong style={{ color: 'var(--accent-blue)' }}>{formatBytes(hoveredEdge.edge.total_bytes)}</strong></div>
            <div style={{ color: 'var(--text-muted)' }}>Protos: <strong style={{ color: 'var(--text-main)' }}>{hoveredEdge.edge.protocols.join(', ')}</strong></div>
            {hoveredEdge.edge.has_alerts && (
              <div style={{ color: '#fda4af', marginTop: '4px', fontWeight: 600 }}>
                ⚠️ {hoveredEdge.edge.alert_count} Alert(s) on Connection
              </div>
            )}
          </div>
        )}
      </div>

      {/* 4. Bottom Legend & Summary Bar */}
      <div
        className="card"
        style={{
          padding: '10px 18px',
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '12px',
          fontSize: '0.75rem',
        }}
      >
        {/* Color / Visual Legend */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <span style={{ fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-subtle)' }}>
            Map Legend:
          </span>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '12px', height: '12px', borderRadius: '50%', backgroundColor: '#0ea5e9', display: 'inline-block' }} />
            <span style={{ color: 'var(--text-muted)' }}>Clean Host</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '12px', height: '12px', borderRadius: '50%', backgroundColor: '#f59e0b', display: 'inline-block' }} />
            <span style={{ color: 'var(--text-muted)' }}>Medium Threat</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '12px', height: '12px', borderRadius: '50%', backgroundColor: '#f43f5e', display: 'inline-block' }} />
            <span style={{ color: 'var(--text-muted)' }}>High / Critical Alert</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '20px', height: '2px', backgroundColor: 'rgba(148, 163, 184, 0.7)', display: 'inline-block' }} />
            <span style={{ color: 'var(--text-muted)' }}>Edge = Communication (Arrow = Direction)</span>
          </div>
        </div>

        {/* Global Statistics Counter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ color: 'var(--text-muted)' }}>
            Hosts: <strong style={{ color: 'var(--text-main)' }}>{data.summary.total_nodes}</strong>
          </span>
          <span style={{ color: 'var(--text-muted)' }}>
            Links: <strong style={{ color: 'var(--text-main)' }}>{data.summary.total_edges}</strong>
          </span>
          <span style={{ color: 'var(--text-muted)' }}>
            Total Flows: <strong style={{ color: 'var(--text-main)' }}>{data.summary.total_flows}</strong>
          </span>
          <span style={{ color: 'var(--text-muted)' }}>
            Threat Hosts:{' '}
            <strong style={{ color: data.summary.alerted_nodes_count > 0 ? '#fda4af' : 'var(--text-main)' }}>
              {data.summary.alerted_nodes_count}
            </strong>
          </span>
        </div>
      </div>
    </div>
  );
};
