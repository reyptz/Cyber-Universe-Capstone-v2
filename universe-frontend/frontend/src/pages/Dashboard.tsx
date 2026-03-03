import { useQuery } from '@tanstack/react-query';
import { 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  TrendingUp,
  Target,
  Database,
  Shield,
  Clock,
  Zap,
  ShieldCheck,
  Globe
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { api } from '../lib/api';
import { CyberMap } from '../components/cyber/CyberMap';
import { OffensivePanel } from '../components/cyber/OffensivePanel';
import { SecurityTimeline } from '../components/cyber/SecurityTimeline';

interface Metrics {
  missions: {
    total: number;
    active: number;
    completed: number;
  };
  results: {
    total: number;
    to_validate: number;
  };
  workflow: {
    total_items: number;
    in_progress: number;
  };
  detection: {
    rules_count: number;
    enabled_rules: number;
  };
}

export function Dashboard() {
  const { data: metrics, isLoading } = useQuery<Metrics>({
    queryKey: ['metrics'],
    queryFn: api.getMetrics,
    refetchInterval: 5000, // Refresh every 5s
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full bg-slate-950">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-600"></div>
      </div>
    );
  }

  const stats = [
    {
      title: 'Active Missions',
      value: metrics?.missions.active || 0,
      total: metrics?.missions.total || 0,
      icon: Target,
      color: 'text-red-500',
      bgColor: 'bg-red-500/10 border-red-500/20',
    },
    {
      title: 'eBPF Nodes',
      value: 12,
      subtitle: `4 detected threats`,
      icon: ShieldCheck,
      color: 'text-cyan-500',
      bgColor: 'bg-cyan-500/10 border-cyan-500/20',
    },
    {
      title: 'Payload Engine',
      value: 'ACTIVE',
      subtitle: `Genjutsu v1.0`,
      icon: Zap,
      color: 'text-orange-500',
      bgColor: 'bg-orange-500/10 border-orange-500/20',
    },
    {
      title: 'Detection Rules',
      value: metrics?.detection.enabled_rules || 0,
      total: metrics?.detection.rules_count || 0,
      icon: Shield,
      color: 'text-purple-500',
      bgColor: 'bg-purple-500/10 border-purple-500/20',
    },
  ];

  return (
    <div className="space-y-6 bg-slate-950 p-6 min-h-screen text-slate-100">
      {/* Header HUD */}
      <div className="flex items-center justify-between border-b border-cyan-900/30 pb-4">
        <div>
          <h1 className="text-3xl font-bold font-mono tracking-tighter text-cyan-400">GHOST COMMAND CENTER</h1>
          <p className="text-xs font-mono text-cyan-700">VERSION 3.0.1 // UNIFIED INTERFACE</p>
        </div>
        <div className="flex items-center space-x-6 text-sm font-mono">
          <div className="flex flex-col items-end">
            <span className="text-[10px] text-cyan-900 uppercase">System Status</span>
            <span className="text-green-500 flex items-center gap-1">
              <div className="h-1.5 w-1.5 rounded-full bg-green-500 animate-pulse" />
              ONLINE
            </span>
          </div>
          <div className="flex flex-col items-end border-l border-cyan-900/30 pl-6">
            <span className="text-[10px] text-cyan-900 uppercase">Local Time</span>
            <span className="text-cyan-500">{new Date().toLocaleTimeString()}</span>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <Card key={stat.title} className="bg-slate-900/50 border-slate-800 hover:border-cyan-500/50 transition-colors group">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-1">
                      {stat.title}
                    </p>
                    <div className="flex items-baseline space-x-2">
                      <p className="text-2xl font-bold font-mono text-slate-100 group-hover:text-cyan-400 transition-colors">
                        {stat.value}
                      </p>
                      {stat.total !== undefined && (
                        <p className="text-xs text-slate-600 font-mono">/ {stat.total}</p>
                      )}
                    </div>
                    {stat.subtitle && (
                      <p className="text-[10px] text-slate-500 font-mono mt-1 italic">{stat.subtitle}</p>
                    )}
                  </div>
                  <div className={`p-3 rounded-lg border ${stat.bgColor}`}>
                    <Icon className={`h-5 w-5 ${stat.color}`} />
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Main Command Center Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Real-time Map & Controls */}
        <div className="xl:col-span-2 space-y-6">
          <CyberMap />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <OffensivePanel />
            <Card className="bg-slate-950 border-cyan-900/50">
              <CardHeader className="border-b border-cyan-900/30">
                <CardTitle className="text-cyan-400 flex items-center gap-2 font-mono text-lg">
                  <TrendingUp className="h-5 w-5" />
                  LATENCY & PERFORMANCE
                </CardTitle>
              </CardHeader>
              <CardContent className="p-6 space-y-4">
                <div className="space-y-4">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono text-slate-400 uppercase tracking-widest">eBPF Detection Latency</span>
                      <span className="text-sm font-bold text-cyan-400 font-mono">145 ms</span>
                    </div>
                    <div className="w-full bg-slate-900 rounded-full h-1.5 border border-cyan-900/20">
                      <div className="bg-cyan-500 h-1.5 rounded-full shadow-[0_0_8px_#06b6d4]" style={{ width: '72%' }}></div>
                    </div>
                  </div>
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono text-slate-400 uppercase tracking-widest">Payload Execution (C)</span>
                      <span className="text-sm font-bold text-red-500 font-mono">482 ms</span>
                    </div>
                    <div className="w-full bg-slate-900 rounded-full h-1.5 border border-red-900/20">
                      <div className="bg-red-500 h-1.5 rounded-full shadow-[0_0_8px_#ef4444]" style={{ width: '96%' }}></div>
                    </div>
                  </div>
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono text-slate-400 uppercase tracking-widest">C2 UI Sync</span>
                      <span className="text-sm font-bold text-green-500 font-mono">28 ms</span>
                    </div>
                    <div className="w-full bg-slate-900 rounded-full h-1.5 border border-green-900/20">
                      <div className="bg-green-500 h-1.5 rounded-full shadow-[0_0_8px_#22c55e]" style={{ width: '100%' }}></div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Incident Timeline */}
        <div className="xl:col-span-1">
          <SecurityTimeline />
        </div>
      </div>
    </div>
  );
}
