import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { 
  Shield, 
  Plus, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Eye,
  Play,
  Pause,
  Settings,
  Filter,
  Search
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { api } from '../lib/api';

interface DetectionRule {
  id: string;
  name: string;
  description: string;
  type: 'sigma' | 'yara' | 'ebpf' | 'ml';
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  created_at: string;
  last_triggered?: string;
  trigger_count: number;
}

interface Alert {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  message: string;
  timestamp: string;
  status: 'new' | 'investigating' | 'resolved' | 'false_positive';
  metadata: Record<string, any>;
}

const severityColors = {
  low: 'bg-gray-100 text-gray-800',
  medium: 'bg-blue-100 text-blue-800',
  high: 'bg-orange-100 text-orange-800',
  critical: 'bg-red-100 text-red-800',
};

const typeColors = {
  sigma: 'bg-purple-100 text-purple-800',
  yara: 'bg-green-100 text-green-800',
  ebpf: 'bg-blue-100 text-blue-800',
  ml: 'bg-pink-100 text-pink-800',
};

export function Detection() {
  const [activeTab, setActiveTab] = useState<'rules' | 'alerts'>('rules');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const queryClient = useQueryClient();

  const { data: rules, isLoading: rulesLoading } = useQuery<DetectionRule[]>({
    queryKey: ['detection-rules'],
    queryFn: api.getDetectionRules,
    refetchInterval: 10000,
  });

  const { data: alerts, isLoading: alertsLoading } = useQuery<Alert[]>({
    queryKey: ['alerts'],
    queryFn: api.getAlerts,
    refetchInterval: 5000,
  });

  const createRuleMutation = useMutation({
    mutationFn: api.createDetectionRule,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['detection-rules'] });
    },
  });

  const filteredRules = rules?.filter(rule => {
    const matchesSearch = rule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         rule.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = filterType === 'all' || rule.type === filterType;
    return matchesSearch && matchesType;
  });

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'new':
        return <AlertTriangle className="h-4 w-4 text-red-600" />;
      case 'investigating':
        return <Eye className="h-4 w-4 text-yellow-600" />;
      case 'resolved':
        return <CheckCircle className="h-4 w-4 text-green-600" />;
      case 'false_positive':
        return <Clock className="h-4 w-4 text-gray-600" />;
      default:
        return <AlertTriangle className="h-4 w-4 text-gray-600" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Détection</h1>
        <button className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700">
          <Plus className="h-4 w-4 mr-2" />
          Nouvelle règle
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {[
          { 
            label: 'Règles actives', 
            value: rules?.filter(r => r.enabled).length || 0, 
            total: rules?.length || 0,
            color: 'text-green-600' 
          },
          { 
            label: 'Alertes nouvelles', 
            value: alerts?.filter(a => a.status === 'new').length || 0, 
            color: 'text-red-600' 
          },
          { 
            label: 'En investigation', 
            value: alerts?.filter(a => a.status === 'investigating').length || 0, 
            color: 'text-yellow-600' 
          },
          { 
            label: 'Résolues (24h)', 
            value: alerts?.filter(a => a.status === 'resolved').length || 0, 
            color: 'text-blue-600' 
          },
        ].map((stat) => (
          <Card key={stat.label}>
            <CardContent className="pt-6">
              <div className="text-center">
                <p className="text-2xl font-bold text-gray-900">
                  {stat.value}
                  {stat.total && <span className="text-sm text-gray-500">/{stat.total}</span>}
                </p>
                <p className={`text-sm ${stat.color}`}>{stat.label}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'rules', name: 'Règles de détection', icon: Shield },
            { id: 'alerts', name: 'Alertes', icon: AlertTriangle },
          ].map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as 'rules' | 'alerts')}
                className={`flex items-center py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Icon className="h-4 w-4 mr-2" />
                {tab.name}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Search and Filters */}
      <div className="flex items-center space-x-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Rechercher..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500 w-full"
          />
        </div>
        {activeTab === 'rules' && (
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="border border-gray-300 rounded-md px-3 py-2 focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="all">Tous les types</option>
            <option value="sigma">Sigma</option>
            <option value="yara">YARA</option>
            <option value="ebpf">eBPF</option>
            <option value="ml">ML</option>
          </select>
        )}
      </div>

      {/* Content */}
      {activeTab === 'rules' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {rulesLoading ? (
            <div className="col-span-full flex items-center justify-center h-64">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
          ) : (
            filteredRules?.map((rule) => (
              <Card key={rule.id} className="hover:shadow-lg transition-shadow">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg">{rule.name}</CardTitle>
                    <div className="flex items-center space-x-2">
                      {rule.enabled ? (
                        <Play className="h-4 w-4 text-green-600" />
                      ) : (
                        <Pause className="h-4 w-4 text-gray-400" />
                      )}
                      <button className="text-gray-400 hover:text-gray-600">
                        <Settings className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <p className="text-sm text-gray-600 line-clamp-2">
                      {rule.description}
                    </p>

                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${typeColors[rule.type]}`}>
                        {rule.type.toUpperCase()}
                      </span>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${severityColors[rule.severity]}`}>
                        {rule.severity}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <p className="text-gray-600">Déclenchements</p>
                        <p className="font-medium">{rule.trigger_count}</p>
                      </div>
                      <div>
                        <p className="text-gray-600">Statut</p>
                        <p className={`font-medium ${rule.enabled ? 'text-green-600' : 'text-gray-400'}`}>
                          {rule.enabled ? 'Activée' : 'Désactivée'}
                        </p>
                      </div>
                    </div>

                    <div className="text-xs text-gray-500">
                      Créée le {new Date(rule.created_at).toLocaleDateString()}
                      {rule.last_triggered && (
                        <div>
                          Dernier déclenchement: {new Date(rule.last_triggered).toLocaleString()}
                        </div>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>
      )}

      {activeTab === 'alerts' && (
        <div className="space-y-4">
          {alertsLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
          ) : (
            alerts?.map((alert) => (
              <Card key={alert.id} className="hover:shadow-md transition-shadow">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        {getStatusIcon(alert.status)}
                        <h3 className="font-medium text-gray-900">{alert.rule_name}</h3>
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${severityColors[alert.severity as keyof typeof severityColors]}`}>
                          {alert.severity}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 mb-2">{alert.message}</p>
                      <div className="flex items-center space-x-4 text-xs text-gray-500">
                        <span>{new Date(alert.timestamp).toLocaleString()}</span>
                        <span>ID: {alert.id.slice(0, 8)}</span>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <button className="px-3 py-1 text-xs font-medium text-blue-600 bg-blue-100 rounded-md hover:bg-blue-200">
                        Investiguer
                      </button>
                      <button className="px-3 py-1 text-xs font-medium text-gray-600 bg-gray-100 rounded-md hover:bg-gray-200">
                        Résoudre
                      </button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>
      )}
    </div>
  );
}