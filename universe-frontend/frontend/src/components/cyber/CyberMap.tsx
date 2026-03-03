import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Globe, MapPin, ShieldAlert } from 'lucide-react';

interface ThreatPoint {
  id: string;
  lat: number;
  lng: number;
  type: 'attack' | 'defense';
  severity: 'low' | 'medium' | 'high' | 'critical';
  label: string;
}

export const CyberMap: React.FC = () => {
  // Simulation de points de menaces (eBPF events)
  const [threats] = React.useState<ThreatPoint[]>([
    { id: '1', lat: 48.8566, lng: 2.3522, type: 'attack', severity: 'critical', label: 'Process Hollowing (Paris)' },
    { id: '2', lat: 40.7128, lng: -74.0060, type: 'defense', severity: 'medium', label: 'eBPF Sensor Active (NY)' },
    { id: '3', lat: 35.6762, lng: 139.6503, type: 'attack', severity: 'high', label: 'Injection Detected (Tokyo)' },
  ]);

  return (
    <Card className="bg-slate-950 border-cyan-900/50 shadow-[0_0_15px_rgba(0,255,255,0.1)]">
      <CardHeader className="border-b border-cyan-900/30">
        <CardTitle className="text-cyan-400 flex items-center gap-2 font-mono text-lg">
          <Globe className="h-5 w-5 animate-pulse" />
          REAL-TIME THREAT GEOLOCATION
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0 relative min-h-[400px] bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')] bg-slate-900 overflow-hidden">
        {/* Grille Cyber */}
        <div className="absolute inset-0 opacity-20 pointer-events-none" 
             style={{ backgroundImage: 'radial-gradient(circle, #00ffff 1px, transparent 1px)', backgroundSize: '30px 30px' }} />
        
        {/* Points de Menaces Simulés */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="relative w-full h-full">
            {threats.map((threat) => (
              <div
                key={threat.id}
                className="absolute transform -translate-x-1/2 -translate-y-1/2 group"
                style={{ 
                  left: `${(threat.lng + 180) * (100 / 360)}%`, 
                  top: `${(90 - threat.lat) * (100 / 180)}%` 
                }}
              >
                {/* Animation de pulsation pour la menace */}
                <div className={`absolute -inset-4 rounded-full animate-ping opacity-75 ${
                  threat.type === 'attack' ? 'bg-red-500' : 'bg-cyan-500'
                }`} />
                <div className={`relative p-1 rounded-full ${
                  threat.type === 'attack' ? 'bg-red-600' : 'bg-cyan-600'
                } border-2 border-white/50 shadow-lg cursor-pointer`}>
                  <MapPin className="h-4 w-4 text-white" />
                </div>

                {/* Tooltip Cyber */}
                <div className="absolute left-full ml-2 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity bg-slate-900 border border-cyan-500/50 p-2 rounded text-xs whitespace-nowrap z-50">
                  <div className="font-bold text-cyan-400 font-mono uppercase">{threat.label}</div>
                  <div className="text-slate-400">Severity: <span className={
                    threat.severity === 'critical' ? 'text-red-500' : 
                    threat.severity === 'high' ? 'text-orange-500' : 'text-yellow-500'
                  }>{threat.severity.toUpperCase()}</span></div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* HUD Overlay */}
        <div className="absolute bottom-4 left-4 bg-slate-900/80 border border-cyan-900/50 p-3 rounded-lg backdrop-blur-sm">
          <div className="text-[10px] text-cyan-500/70 font-mono mb-2">SYSTEM STATUS: NOMINAL</div>
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2 text-xs">
              <div className="h-2 w-2 rounded-full bg-red-500 shadow-[0_0_5px_#ef4444]" />
              <span className="text-slate-300">Active Injections</span>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <div className="h-2 w-2 rounded-full bg-cyan-500 shadow-[0_0_5px_#06b6d4]" />
              <span className="text-slate-300">eBPF Nodes Active</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
