import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { 
  Plus, 
  Target, 
  Play, 
  Pause, 
  Trash2, 
  Edit, 
  Calendar,
  Clock,
  CheckCircle,
  AlertCircle
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { api } from '../lib/api';

interface Mission {
  id: string;
  name: string;
  targets: string[];
  depth: number;
  frequency: string;
  status: 'active' | 'paused' | 'completed' | 'error';
  created_at: string;
  last_run?: string;
  findings_count: number;
}

export function Missions() {
  const [showCreateForm, setShowCreateForm] = useState(false);
  const queryClient = useQueryClient();

  const { data: missions, isLoading } = useQuery<Mission[]>({
    queryKey: ['missions'],
    queryFn: api.getMissions,
    refetchInterval: 10000,
  });

  const createMissionMutation = useMutation({
    mutationFn: api.createMission,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['missions'] });
      setShowCreateForm(false);
    },
  });

  const deleteMissionMutation = useMutation({
    mutationFn: api.deleteMission,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['missions'] });
    },
  });

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <Play className="h-4 w-4 text-green-600" />;
      case 'paused':
        return <Pause className="h-4 w-4 text-yellow-600" />;
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-blue-600" />;
      case 'error':
        return <AlertCircle className="h-4 w-4 text-red-600" />;
      default:
        return <Clock className="h-4 w-4 text-gray-600" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-green-100 text-green-800';
      case 'paused':
        return 'bg-yellow-100 text-yellow-800';
      case 'completed':
        return 'bg-blue-100 text-blue-800';
      case 'error':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Missions OSINT</h1>
        <button
          onClick={() => setShowCreateForm(true)}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
        >
          <Plus className="h-4 w-4 mr-2" />
          Nouvelle Mission
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {[
          { label: 'Total', value: missions?.length || 0, color: 'text-gray-600' },
          { label: 'Actives', value: missions?.filter(m => m.status === 'active').length || 0, color: 'text-green-600' },
          { label: 'En pause', value: missions?.filter(m => m.status === 'paused').length || 0, color: 'text-yellow-600' },
          { label: 'Terminées', value: missions?.filter(m => m.status === 'completed').length || 0, color: 'text-blue-600' },
        ].map((stat) => (
          <Card key={stat.label}>
            <CardContent className="pt-6">
              <div className="text-center">
                <p className="text-2xl font-bold text-gray-900">{stat.value}</p>
                <p className={`text-sm ${stat.color}`}>{stat.label}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Missions Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {missions?.map((mission) => (
          <Card key={mission.id} className="hover:shadow-lg transition-shadow">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-lg">{mission.name}</CardTitle>
                <div className="flex items-center space-x-2">
                  {getStatusIcon(mission.status)}
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${getStatusColor(mission.status)}`}>
                    {mission.status}
                  </span>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div>
                  <p className="text-sm font-medium text-gray-700">Cibles</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {mission.targets.slice(0, 3).map((target, idx) => (
                      <span key={idx} className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
                        {target}
                      </span>
                    ))}
                    {mission.targets.length > 3 && (
                      <span className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
                        +{mission.targets.length - 3}
                      </span>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-gray-600">Profondeur</p>
                    <p className="font-medium">{mission.depth}</p>
                  </div>
                  <div>
                    <p className="text-gray-600">Fréquence</p>
                    <p className="font-medium">{mission.frequency}</p>
                  </div>
                </div>

                <div className="flex items-center justify-between text-sm">
                  <div className="flex items-center space-x-1 text-gray-600">
                    <Target className="h-4 w-4" />
                    <span>{mission.findings_count} résultats</span>
                  </div>
                  <div className="flex items-center space-x-1 text-gray-600">
                    <Calendar className="h-4 w-4" />
                    <span>{new Date(mission.created_at).toLocaleDateString()}</span>
                  </div>
                </div>

                {mission.last_run && (
                  <div className="text-xs text-gray-500">
                    Dernière exécution: {new Date(mission.last_run).toLocaleString()}
                  </div>
                )}

                <div className="flex items-center justify-end space-x-2 pt-2 border-t">
                  <button className="p-2 text-gray-400 hover:text-blue-600">
                    <Edit className="h-4 w-4" />
                  </button>
                  <button 
                    onClick={() => deleteMissionMutation.mutate(mission.id)}
                    className="p-2 text-gray-400 hover:text-red-600"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Create Mission Modal */}
      {showCreateForm && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Nouvelle Mission OSINT</h3>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const formData = new FormData(e.currentTarget);
                const targets = (formData.get('targets') as string).split(',').map(t => t.trim());
                createMissionMutation.mutate({
                  name: formData.get('name'),
                  targets,
                  depth: parseInt(formData.get('depth') as string),
                  frequency: formData.get('frequency'),
                });
              }}
              className="space-y-4"
            >
              <div>
                <label className="block text-sm font-medium text-gray-700">Nom</label>
                <input
                  name="name"
                  type="text"
                  required
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">Cibles (séparées par des virgules)</label>
                <textarea
                  name="targets"
                  required
                  rows={3}
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
                  placeholder="example.com, target.org"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">Profondeur</label>
                <select
                  name="depth"
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
                >
                  <option value="1">1 - Surface</option>
                  <option value="2">2 - Modéré</option>
                  <option value="3">3 - Profond</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">Fréquence</label>
                <select
                  name="frequency"
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
                >
                  <option value="hourly">Toutes les heures</option>
                  <option value="daily">Quotidienne</option>
                  <option value="weekly">Hebdomadaire</option>
                </select>
              </div>
              <div className="flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setShowCreateForm(false)}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200"
                >
                  Annuler
                </button>
                <button
                  type="submit"
                  disabled={createMissionMutation.isPending}
                  className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50"
                >
                  {createMissionMutation.isPending ? 'Création...' : 'Créer'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}