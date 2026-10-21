import React from 'react';
import { SeverityLevel, IncidentStatusType, PcapStatusType } from '../types';

interface Props {
  type: 'severity' | 'status' | 'pcap';
  value: SeverityLevel | IncidentStatusType | PcapStatusType | string;
}

export const StatusBadge: React.FC<Props> = ({ type, value }) => {
  const val = String(value).toUpperCase();

  if (type === 'severity') {
    let cls = 'badge-low';
    if (val === 'CRITICAL') cls = 'badge-critical';
    else if (val === 'HIGH') cls = 'badge-high';
    else if (val === 'MEDIUM') cls = 'badge-medium';
    return <span className={`badge ${cls}`}>{val}</span>;
  }

  if (type === 'status') {
    let cls = 'badge-open';
    if (val === 'INVESTIGATING') cls = 'badge-investigating';
    else if (val === 'RESOLVED') cls = 'badge-resolved';
    return <span className={`badge ${cls}`}>{val}</span>;
  }

  // PCAP status
  let pcapCls = 'badge-medium';
  if (val === 'COMPLETED') pcapCls = 'badge-resolved';
  else if (val === 'FAILED') pcapCls = 'badge-critical';
  else if (val === 'PROCESSING') pcapCls = 'badge-investigating';
  return <span className={`badge ${pcapCls}`}>{val}</span>;
};
