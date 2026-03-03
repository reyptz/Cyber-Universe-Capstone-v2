import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { 
  Plus, 
  MoreHorizontal, 
  Calendar, 
  User, 
  Tag,
  Clock,
  CheckCircle,
  AlertCircle,
  ArrowRight
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { api } from '../lib/api';

interface WorkflowItem {
  id: string;
  title: string;
  description: string;
  status: 'todo' | 'in_progress' | 'review' | 'done';
  priority: 'low' | 'medium' | 'high' | 'critical';
  assignee: string;
  created_at: string;
  due_date?: string;
  tags: string[];
}

const statusColumns = [
  { id: 'todo', title: 'À faire', color: 'bg-gray-100' },
  { id: 'in_progress', title: 'En cours', color: 'bg-blue-100' },
  { id: 'review', title: 'Révision', color: 'bg-yellow-100' },
  { id: 'done', title: 'Terminé', color: 'bg-green-100' },
];

const priorityColors = {
  low: 'bg-gray-100 text-gray-800',
  medium: 'bg-blue-100 text-blue-800',
  high: 'bg-orange-100 text-orange-800',
  critical: 'bg-red-100 text-red-800',
};

export function Workflow() {
  const [draggedItem, setDraggedItem] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const { data: workflowItems, isLoading } = useQuery<WorkflowItem[]>({
    queryKey: ['workflow'],
    queryFn: api.getWorkflowItems,
    refetchInterval: 5000,
  });

  const updateItemMutation = useMutation({
    mutationFn: ({ id, item }: { id: string; item: Partial<WorkflowItem> }) =>
      api.updateWorkflowItem(id, item),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['workflow'] });
    },
  });

  const handleDragStart = (e: React.DragEvent, itemId: string) => {
    setDraggedItem(itemId);
    e.dataTransfer.effectAllowed = 'move';
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  };

  const handleDrop = (e: React.DragEvent, newStatus: string) => {
    e.preventDefault();
    if (draggedItem) {
      updateItemMutation.mutate({
        id: draggedItem,
        item: { status: newStatus as WorkflowItem['status'] },
      });
      setDraggedItem(null);
    }
  };

  const getItemsByStatus = (status: string) => {
    return workflowItems?.filter(item => item.status === status) || [];
  };

  const getPriorityIcon = (priority: string) => {
    switch (priority) {
      case 'critical':
        return <AlertCircle className="h-4 w-4 text-red-600" />;
      case 'high':
        return <ArrowRight className="h-4 w-4 text-orange-600" />;
      default:
        return null;
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
        <h1 className="text-3xl font-bold text-gray-900">Workflow</h1>
        <button className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700">
          <Plus className="h-4 w-4 mr-2" />
          Nouvelle tâche
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {statusColumns.map((column) => {
          const items = getItemsByStatus(column.id);
          return (
            <Card key={column.id}>
              <CardContent className="pt-6">
                <div className="text-center">
                  <p className="text-2xl font-bold text-gray-900">{items.length}</p>
                  <p className="text-sm text-gray-600">{column.title}</p>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Kanban Board */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statusColumns.map((column) => (
          <div
            key={column.id}
            className={`rounded-lg p-4 ${column.color} min-h-96`}
            onDragOver={handleDragOver}
            onDrop={(e) => handleDrop(e, column.id)}
          >
            <h3 className="font-semibold text-gray-900 mb-4 flex items-center justify-between">
              {column.title}
              <span className="text-sm font-normal text-gray-600">
                {getItemsByStatus(column.id).length}
              </span>
            </h3>

            <div className="space-y-3">
              {getItemsByStatus(column.id).map((item) => (
                <Card
                  key={item.id}
                  className="cursor-move hover:shadow-md transition-shadow bg-white"
                  draggable
                  onDragStart={(e) => handleDragStart(e, item.id)}
                >
                  <CardContent className="p-4">
                    <div className="space-y-3">
                      <div className="flex items-start justify-between">
                        <h4 className="font-medium text-gray-900 text-sm">
                          {item.title}
                        </h4>
                        <div className="flex items-center space-x-1">
                          {getPriorityIcon(item.priority)}
                          <button className="text-gray-400 hover:text-gray-600">
                            <MoreHorizontal className="h-4 w-4" />
                          </button>
                        </div>
                      </div>

                      <p className="text-xs text-gray-600 line-clamp-2">
                        {item.description}
                      </p>

                      <div className="flex items-center justify-between">
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${priorityColors[item.priority]}`}>
                          {item.priority}
                        </span>
                        <div className="flex items-center space-x-1 text-xs text-gray-500">
                          <User className="h-3 w-3" />
                          <span>{item.assignee}</span>
                        </div>
                      </div>

                      {item.tags.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {item.tags.slice(0, 2).map((tag, idx) => (
                            <span key={idx} className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
                              {tag}
                            </span>
                          ))}
                          {item.tags.length > 2 && (
                            <span className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
                              +{item.tags.length - 2}
                            </span>
                          )}
                        </div>
                      )}

                      <div className="flex items-center justify-between text-xs text-gray-500">
                        <div className="flex items-center space-x-1">
                          <Calendar className="h-3 w-3" />
                          <span>{new Date(item.created_at).toLocaleDateString()}</span>
                        </div>
                        {item.due_date && (
                          <div className="flex items-center space-x-1">
                            <Clock className="h-3 w-3" />
                            <span>{new Date(item.due_date).toLocaleDateString()}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}