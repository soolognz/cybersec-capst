import React, { useState, useEffect } from 'react'
import { Bell, ChevronLeft, ChevronRight } from 'lucide-react'

interface Alert {
  id: string
  timestamp: string
  source_ip: string
  threat_level: string
  anomaly_score: number
  ewma_score: number
  message: string
  action_taken: string
}

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [filter, setFilter] = useState<string>('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    const params = new URLSearchParams({ page: String(page), page_size: '20' })
    if (filter) params.set('threat_level', filter)

    fetch(`/api/alerts?${params}`)
      .then(r => r.json())
      .then(data => {
        setAlerts(data.alerts || [])
        setTotalPages(data.total_pages || 1)
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [page, filter])

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-bold flex items-center gap-2">
            <Bell size={24} className="text-yellow-400" />
            Alert History
          </h2>
          <p className="text-gray-500 mt-1">All detected threats and early warnings</p>
        </div>

        <div className="flex gap-2">
          {['', 'critical', 'warning'].map(f => (
            <button
              key={f}
              onClick={() => { setFilter(f); setPage(1) }}
              className={`px-4 py-2 rounded-lg text-sm transition-colors ${
                filter === f
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {f || 'All'}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-800/50 text-gray-500">
              <th className="text-left py-3 px-4">ID</th>
              <th className="text-left py-3 px-4">Timestamp</th>
              <th className="text-left py-3 px-4">Source IP</th>
              <th className="text-left py-3 px-4">Level</th>
              <th className="text-right py-3 px-4">Score</th>
              <th className="text-right py-3 px-4">EWMA</th>
              <th className="text-left py-3 px-4">Action</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map(alert => (
              <tr key={alert.id} className="border-t border-gray-800/50 hover:bg-gray-800/30">
                <td className="py-3 px-4 font-mono text-xs">{alert.id}</td>
                <td className="py-3 px-4 text-gray-400">{new Date(alert.timestamp).toLocaleString()}</td>
                <td className="py-3 px-4 font-mono">{alert.source_ip}</td>
                <td className="py-3 px-4">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    alert.threat_level === 'critical'
                      ? 'bg-red-900/30 text-red-400'
                      : 'bg-yellow-900/30 text-yellow-400'
                  }`}>
                    {alert.threat_level.toUpperCase()}
                  </span>
                </td>
                <td className="text-right py-3 px-4 font-mono">{alert.anomaly_score.toFixed(4)}</td>
                <td className="text-right py-3 px-4 font-mono">{alert.ewma_score.toFixed(4)}</td>
                <td className="py-3 px-4 text-gray-400 text-xs">{alert.action_taken || '-'}</td>
              </tr>
            ))}
            {alerts.length === 0 && (
              <tr>
                <td colSpan={7} className="py-12 text-center text-gray-500">
                  {loading ? 'Loading...' : 'No alerts found'}
                </td>
              </tr>
            )}
          </tbody>
        </table>

        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-gray-800">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="flex items-center gap-1 px-3 py-1.5 rounded bg-gray-800 text-sm disabled:opacity-50"
            >
              <ChevronLeft size={16} /> Previous
            </button>
            <span className="text-sm text-gray-500">Page {page} of {totalPages}</span>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="flex items-center gap-1 px-3 py-1.5 rounded bg-gray-800 text-sm disabled:opacity-50"
            >
              Next <ChevronRight size={16} />
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
