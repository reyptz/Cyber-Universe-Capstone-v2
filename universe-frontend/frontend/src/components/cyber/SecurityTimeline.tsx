import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Shield, Clock, AlertCircle, CheckCircle2, Info } from 'lucide-react';

interface SecurityEvent {
  id: string;
  timestamp: string;
  type: 'alert' | 'info' | 'success';
  module: 'eBPF' | 'RAG' | 'C2';
  message: string;
}

export const SecurityTimeline: React.FC = () => {
  const [events] = React.useState<SecurityEvent[]>([
    { id: '1', timestamp: '19:42:01', type: 'alert', module: 'eBPF', message: 'CRITICAL: NtUnmapViewOfSection detected on PID 4412 (Suspicious Hollowing)' },
    { id: '2', timestamp: '19:41:55', type: 'info', module: 'C2', message: 'New node registered: ghost-node-771' },
    { id: '3', timestamp: '19:41:30', type: 'success', module: 'RAG', message: 'Security scan complete: No PII leakage found in LLM response.' },
    { id: '4', timestamp: '19:40:12', type: 'alert', module: 'eBPF', message: 'WARNING: Unusual syscall pattern detected (ptrace) on process: chrome.exe' },
  ]);

  return (
    <Card className="bg-slate-950 border-cyan-900/50 shadow-[0_0_15px_rgba(0,255,255,0.1)]">
      <CardHeader className="border-b border-cyan-900/30">
        <CardTitle className="text-cyan-400 flex items-center gap-2 font-mono text-lg">
          <Shield className="h-5 w-5" />
          DEFENSIVE INCIDENT TIMELINE
        </CardTitle>
      </CardHeader>
      <CardContent className="p-4 space-y-4 max-h-[500px] overflow-y-auto custom-scrollbar">
        {events.map((event, i) => (
          <div key={event.id} className="relative pl-6 pb-6 border-l border-cyan-900/30 last:pb-0 group">
            {/* Timeline Dot */}
            <div className={`absolute -left-[6.5px] top-1 h-3 w-3 rounded-full border-2 border-slate-950 shadow-[0_0_5px_rgba(0,0,0,0.5)] ${
              event.type === 'alert' ? 'bg-red-500 shadow-[0_0_8px_#ef4444]' : 
              event.type === 'success' ? 'bg-green-500 shadow-[0_0_8px_#22c55e]' : 'bg-cyan-500 shadow-[0_0_8px_#06b6d4]'
            }`} />
            
            {/* Event Card */}
            <div className="bg-slate-900/50 border border-cyan-900/20 p-3 rounded-lg group-hover:border-cyan-500/30 transition-all hover:bg-slate-900/80">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono text-cyan-500/70 flex items-center gap-1 uppercase tracking-widest">
                  <Clock className="h-3 w-3" />
                  {event.timestamp}
                </span>
                <span className={`text-[10px] px-2 py-0.5 rounded border font-mono uppercase ${
                  event.module === 'eBPF' ? 'bg-purple-900/30 border-purple-500/50 text-purple-400' : 
                  event.module === 'RAG' ? 'bg-blue-900/30 border-blue-500/50 text-blue-400' : 
                  'bg-cyan-900/30 border-cyan-500/50 text-cyan-400'
                }`}>
                  {event.module}
                </span>
              </div>
              <p className={`text-xs font-mono leading-relaxed ${
                event.type === 'alert' ? 'text-red-100' : 'text-slate-200'
              }`}>
                {event.message}
              </p>
              
              {/* Context Info Overlay (Hover) */}
              <div className="mt-2 flex items-center gap-4 text-[10px] text-slate-500 font-mono">
                <div className="flex items-center gap-1">
                  <Info className="h-3 w-3" />
                  Severity: <span className={event.type === 'alert' ? 'text-red-500' : 'text-green-500'}>{event.type === 'alert' ? 'High' : 'Low'}</span>
                </div>
                <div>Action: Logged & Notified</div>
              </div>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
};
