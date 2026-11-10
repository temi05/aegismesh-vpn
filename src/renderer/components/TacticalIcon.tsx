// Автономные векторные SVG-иконки Stitch Tactical Telemetry (работают 100% оффлайн без Google Fonts CDN)
import React from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowLeftRight,
  CheckCircle2,
  ClipboardCheck,
  FileText,
  Gauge,
  GitBranch,
  Hourglass,
  KeyRound,
  Layers,
  Network,
  Power,
  QrCode,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Smartphone,
  Terminal,
  Unlink,
  UploadCloud,
  Zap,
} from 'lucide-react';

interface TacticalIconProps {
  name: string;
  size?: number;
  className?: string;
}

export const TacticalIcon: React.FC<TacticalIconProps> = ({
  name,
  size = 18,
  className = '',
}) => {
  switch (name) {
    case 'security':
    case 'shield':
      return <Shield size={size} className={className} />;
    case 'shield_with_heart':
      return <ShieldCheck size={size} className={className} />;
    case 'gpp_bad':
    case 'emergency_home':
      return <ShieldAlert size={size} className={className} />;
    case 'power_settings_new':
      return <Power size={size} className={className} />;
    case 'hub':
      return <Network size={size} className={className} />;
    case 'monitoring':
    case 'analytics':
      return <Activity size={size} className={className} />;
    case 'terminal':
      return <Terminal size={size} className={className} />;
    case 'alt_route':
      return <GitBranch size={size} className={className} />;
    case 'tune':
      return <Sliders size={size} className={className} />;
    case 'qr_code_2':
      return <QrCode size={size} className={className} />;
    case 'description':
      return <FileText size={size} className={className} />;
    case 'reorder':
      return <Layers size={size} className={className} />;
    case 'speed':
      return <Gauge size={size} className={className} />;
    case 'cloud_upload':
      return <UploadCloud size={size} className={className} />;
    case 'sync':
      return <RefreshCw size={size} className={className} />;
    case 'warning':
      return <AlertTriangle size={size} className={className} />;
    case 'bolt':
      return <Zap size={size} className={className} />;
    case 'link_off':
      return <Unlink size={size} className={className} />;
    case 'hourglass_top':
      return <Hourglass size={size} className={className} />;
    case 'swap_horiz':
      return <ArrowLeftRight size={size} className={className} />;
    case 'vpn_key':
      return <KeyRound size={size} className={className} />;
    case 'download_done':
      return <CheckCircle2 size={size} className={className} />;
    case 'fact_check':
      return <ClipboardCheck size={size} className={className} />;
    case 'devices':
      return <Smartphone size={size} className={className} />;
    default:
      return <Shield size={size} className={className} />;
  }
};
