import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Terminal, Shield, Zap, Send, Settings, Target } from 'lucide-react';

export const OffensivePanel: React.FC = () => {
  const [target, setTarget] = React.useState('');
  const [obfuscation, setObfuscation] = React.useState('medium');
  const [injection, setInjection] = React.useState('reflective_dll_loading');
  const [logs, setLogs] = React.useState<string[]>([
    '[INIT] Offensive Operations Suite ready.',
    '[GHOST] Payload engine linked (C-core).',
    '[GENJUTSU] Obfuscator-LLVM version 16.0 detected.'
  ]);

  const addLog = (msg: string) => setLogs(prev => [`[${new Date().toLocaleTimeString()}] ${msg}`, ...prev].slice(0, 10));

  const runOperation = () => {
    addLog(`Deploying ${injection} on target: ${target || 'localhost'}...`);
    addLog(`Applying ${obfuscation} Genjutsu obfuscation...`);
    setTimeout(() => addLog('SUCCESS: Ghost injection successful. Process hollowing confirmed.'), 1500);
  };

  return (
    <Card className="bg-slate-950 border-red-900/50 shadow-[0_0_15px_rgba(255,0,0,0.1)]">
      <CardHeader className="border-b border-red-900/30">
        <CardTitle className="text-red-500 flex items-center gap-2 font-mono text-lg">
          <Target className="h-5 w-5" />
          OFFENSIVE CONTROL PANEL
        </CardTitle>
      </CardHeader>
      <CardContent className="p-6 space-y-6">
        {/* Input Control Section */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-mono text-slate-400 uppercase">Target Process / ID</label>
            <div className="relative">
              <input
                type="text"
                placeholder="ex: lsass.exe"
                className="w-full bg-slate-900 border border-red-900/30 rounded p-2 text-red-50 text-sm font-mono focus:outline-none focus:border-red-500/50 transition-colors"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
              <Terminal className="absolute right-2 top-2 h-4 w-4 text-red-900/50" />
            </div>
          </div>
          <div className="space-y-2">
            <label className="text-xs font-mono text-slate-400 uppercase">Injection Method</label>
            <select
              className="w-full bg-slate-900 border border-red-900/30 rounded p-2 text-red-50 text-sm font-mono focus:outline-none focus:border-red-500/50 transition-colors"
              value={injection}
              onChange={(e) => setInjection(e.target.value)}
            >
              <option value="reflective_dll_loading">Reflective DLL Loading</option>
              <option value="process_hollowing">Process Hollowing</option>
              <option value="dll_hijacking">DLL Hijacking</option>
            </select>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap gap-4 items-center">
          <div className="flex-1 space-y-2">
            <label className="text-xs font-mono text-slate-400 uppercase">Genjutsu Level</label>
            <div className="flex gap-2">
              {['light', 'medium', 'heavy', 'extreme'].map(lvl => (
                <button
                  key={lvl}
                  onClick={() => setObfuscation(lvl)}
                  className={`flex-1 py-1 text-[10px] font-mono rounded uppercase border ${
                    obfuscation === lvl 
                      ? 'bg-red-900/50 border-red-500 text-red-50' 
                      : 'bg-slate-900 border-red-900/30 text-slate-500 hover:border-red-700/50 transition-colors'
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>
          </div>
          <button
            onClick={runOperation}
            className="px-6 py-2 bg-red-600 hover:bg-red-500 text-white rounded font-mono font-bold flex items-center gap-2 transition-all active:scale-95 shadow-[0_0_10px_rgba(255,0,0,0.3)]"
          >
            <Zap className="h-4 w-4 fill-white" />
            DEPLOY GHOST
          </button>
        </div>

        {/* Real-time Console */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-xs font-mono text-slate-400 uppercase">Operation Output (STDOUT)</label>
            <span className="text-[10px] text-red-500 animate-pulse font-mono">LINK: ACTIVE</span>
          </div>
          <div className="bg-black border border-red-900/30 rounded p-3 h-32 overflow-y-auto font-mono text-[11px] space-y-1 custom-scrollbar">
            {logs.map((log, i) => (
              <div key={i} className={`${log.includes('SUCCESS') ? 'text-green-400' : 'text-red-400/80'}`}>
                <span className="opacity-50 mr-2">&gt;</span>
                {log}
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
