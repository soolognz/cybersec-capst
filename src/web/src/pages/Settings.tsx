import React, { useState, useEffect } from 'react'
import { Settings as SettingsIcon, Save } from 'lucide-react'

export default function SettingsPage() {
  const [config, setConfig] = useState({
    alpha: 0.3,
    base_percentile: 95.0,
    sensitivity_factor: 1.5,
    lookback_window: 100,
  })

  useEffect(() => {
    fetch('/api/threshold/config')
      .then(r => r.json())
      .then(setConfig)
      .catch(console.error)
  }, [])

  const handleSave = () => {
    fetch('/api/threshold/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    }).then(() => alert('Configuration saved'))
      .catch(e => alert('Save failed: ' + e))
  }

  return (
    <div>
      <h2 className="text-2xl font-bold flex items-center gap-2 mb-8">
        <SettingsIcon size={24} className="text-gray-400" />
        System Settings
      </h2>

      <div className="max-w-2xl space-y-8">
        {/* Dynamic Threshold Config */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold mb-6">Dynamic Threshold Parameters</h3>

          <div className="space-y-6">
            <div>
              <label className="block text-sm text-gray-400 mb-2">
                EWMA Alpha (smoothing factor: 0-1)
              </label>
              <input
                type="number"
                step="0.05"
                min="0.05"
                max="0.95"
                value={config.alpha}
                onChange={e => setConfig({ ...config, alpha: +e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm focus:border-blue-500 focus:outline-none"
              />
              <p className="text-xs text-gray-600 mt-1">Higher = more responsive to score changes</p>
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-2">
                Base Percentile (alert threshold)
              </label>
              <input
                type="number"
                step="1"
                min="80"
                max="99"
                value={config.base_percentile}
                onChange={e => setConfig({ ...config, base_percentile: +e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm focus:border-blue-500 focus:outline-none"
              />
              <p className="text-xs text-gray-600 mt-1">95th percentile = only top 5% trigger alerts</p>
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-2">
                Sensitivity Factor (early warning)
              </label>
              <input
                type="number"
                step="0.1"
                min="1.1"
                max="3.0"
                value={config.sensitivity_factor}
                onChange={e => setConfig({ ...config, sensitivity_factor: +e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm focus:border-blue-500 focus:outline-none"
              />
              <p className="text-xs text-gray-600 mt-1">1.5 = early warning at 67% of alert threshold</p>
            </div>

            <div>
              <label className="block text-sm text-gray-400 mb-2">
                Lookback Window (number of recent scores)
              </label>
              <input
                type="number"
                step="10"
                min="20"
                max="500"
                value={config.lookback_window}
                onChange={e => setConfig({ ...config, lookback_window: +e.target.value })}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm focus:border-blue-500 focus:outline-none"
              />
            </div>
          </div>

          <button
            onClick={handleSave}
            className="mt-6 flex items-center gap-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm font-medium transition-colors"
          >
            <Save size={16} /> Save Configuration
          </button>
        </div>

        {/* System Info */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold mb-4">System Information</h3>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-500">Main Model</span>
              <span>Isolation Forest</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Benchmark Models</span>
              <span>LOF, One-Class SVM</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Features</span>
              <span>14 features (5-min window)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">ELK Stack</span>
              <span>Elasticsearch + Logstash + Kibana</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Prevention</span>
              <span>Fail2Ban Integration</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
