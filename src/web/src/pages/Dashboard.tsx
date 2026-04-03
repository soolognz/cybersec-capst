import React, { useState, useEffect } from 'react'
import { Shield, AlertTriangle, Ban, Activity, TrendingUp, Eye } from 'lucide-react'
import { useWebSocket } from '../hooks/useWebSocket'

interface Stats {
  alert_stats: { total_alerts: number; critical: number; warning: number }
  prevention_stats: { active_bans: number; total_bans: number; watchlist_size: number }
  model_performance?: Record<string, { Accuracy: number; 'F1-Score': number; 'ROC-AUC': number }>
}

function StatCard({ icon, label, value, color }: {
  icon: React.ReactNode; label: string; value: string | number; color: string
}) {
  return (
    <div className={`bg-gray-900 border border-gray-800 rounded-xl p-6 hover:border-${color}-600/50 transition-colors`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-gray-500 text-sm">{label}</p>
          <p className="text-3xl font-bold mt-1">{value}</p>
        </div>
        <div className={`p-3 rounded-lg bg-${color}-600/20 text-${color}-400`}>
          {icon}
        </div>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(true)
  const { messages, isConnected } = useWebSocket(
    `ws://${window.location.hostname}:8000/api/ws/realtime`
  )

  useEffect(() => {
    fetch('/api/dashboard/stats')
      .then(r => r.json())
      .then(setStats)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  const recentAlerts = messages.filter(m => m.threat_level).slice(-5)

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-bold">Dashboard</h2>
          <p className="text-gray-500 mt-1">Real-time SSH brute-force monitoring</p>
        </div>
        <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm ${
          isConnected ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'
        }`}>
          <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
          {isConnected ? 'Live' : 'Disconnected'}
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6 mb-8">
        <StatCard
          icon={<AlertTriangle size={24} />}
          label="Critical Alerts"
          value={stats?.alert_stats?.critical ?? 0}
          color="red"
        />
        <StatCard
          icon={<Eye size={24} />}
          label="Early Warnings"
          value={stats?.alert_stats?.warning ?? 0}
          color="yellow"
        />
        <StatCard
          icon={<Ban size={24} />}
          label="IPs Banned"
          value={stats?.prevention_stats?.active_bans ?? 0}
          color="orange"
        />
        <StatCard
          icon={<Shield size={24} />}
          label="Watchlist"
          value={stats?.prevention_stats?.watchlist_size ?? 0}
          color="blue"
        />
      </div>

      {/* Model Performance Summary */}
      {stats?.model_performance && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-8">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <TrendingUp size={20} className="text-blue-400" />
            Model Performance Summary
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-500 border-b border-gray-800">
                  <th className="text-left py-3 px-4">Model</th>
                  <th className="text-right py-3 px-4">Accuracy</th>
                  <th className="text-right py-3 px-4">F1-Score</th>
                  <th className="text-right py-3 px-4">ROC-AUC</th>
                  <th className="text-right py-3 px-4">Status</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(stats.model_performance).map(([name, metrics]) => (
                  <tr key={name} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="py-3 px-4 font-medium">{name}</td>
                    <td className="text-right py-3 px-4">{(metrics.Accuracy * 100).toFixed(1)}%</td>
                    <td className="text-right py-3 px-4">{(metrics['F1-Score'] * 100).toFixed(1)}%</td>
                    <td className="text-right py-3 px-4">{(metrics['ROC-AUC'] * 100).toFixed(1)}%</td>
                    <td className="text-right py-3 px-4">
                      {name === 'Isolation Forest' ? (
                        <span className="px-2 py-1 bg-blue-600/20 text-blue-400 rounded text-xs">Main</span>
                      ) : (
                        <span className="px-2 py-1 bg-gray-700 text-gray-400 rounded text-xs">Benchmark</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Recent Alerts */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Activity size={20} className="text-green-400" />
          Recent Activity
        </h3>
        {recentAlerts.length > 0 ? (
          <div className="space-y-3">
            {recentAlerts.map((alert, i) => (
              <div key={i} className={`flex items-center gap-4 p-3 rounded-lg ${
                alert.threat_level === 'critical' ? 'bg-red-900/20 border border-red-800/30' :
                alert.threat_level === 'warning' ? 'bg-yellow-900/20 border border-yellow-800/30' :
                'bg-gray-800/50'
              }`}>
                <div className={`w-2 h-2 rounded-full ${
                  alert.threat_level === 'critical' ? 'bg-red-400' :
                  alert.threat_level === 'warning' ? 'bg-yellow-400' : 'bg-green-400'
                }`} />
                <div className="flex-1">
                  <span className="text-sm">{alert.message || `${alert.threat_level} from ${alert.source_ip}`}</span>
                </div>
                <span className="text-xs text-gray-500">{alert.timestamp}</span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-gray-500 text-center py-8">
            {isConnected ? 'No recent activity. System is monitoring...' : 'Connect to see real-time activity'}
          </p>
        )}
      </div>
    </div>
  )
}
