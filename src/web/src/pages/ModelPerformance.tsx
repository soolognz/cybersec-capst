import React, { useState, useEffect } from 'react'
import { BarChart3, Award, Clock, Cpu } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar } from 'recharts'

interface ModelMetrics {
  Accuracy: number
  Precision: number
  Recall: number
  'F1-Score': number
  'ROC-AUC': number
  'PR-AUC': number
  FPR: number
  'Training Time (s)': number
}

interface FeatureImportance {
  Feature: string
  Importance_Mean: number
  Importance_Std: number
}

export default function ModelPerformance() {
  const [comparison, setComparison] = useState<Record<string, ModelMetrics>>({})
  const [bestModel, setBestModel] = useState('')
  const [features, setFeatures] = useState<FeatureImportance[]>([])

  useEffect(() => {
    fetch('/api/dashboard/stats')
      .then(r => r.json())
      .then(data => {
        if (data.model_performance) setComparison(data.model_performance)
        if (data.feature_importance) setFeatures(data.feature_importance)
      })
      .catch(console.error)

    fetch('/api/dashboard/model-comparison')
      .then(r => r.json())
      .then(data => {
        if (data.best_model) setBestModel(data.best_model)
      })
      .catch(() => {})
  }, [])

  const chartData = Object.entries(comparison).map(([name, m]) => ({
    name: name.replace('Isolation Forest', 'IF').replace('One-Class SVM', 'OCSVM'),
    fullName: name,
    Accuracy: +(m.Accuracy * 100).toFixed(1),
    Precision: +(m.Precision * 100).toFixed(1),
    Recall: +(m.Recall * 100).toFixed(1),
    'F1-Score': +(m['F1-Score'] * 100).toFixed(1),
    'ROC-AUC': +(m['ROC-AUC'] * 100).toFixed(1),
  }))

  const radarData = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC'].map(metric => {
    const point: any = { metric }
    Object.entries(comparison).forEach(([name, m]) => {
      const key = name.replace('Isolation Forest', 'IF').replace('One-Class SVM', 'OCSVM')
      point[key] = +((m as any)[metric] * 100).toFixed(1)
    })
    return point
  })

  const importanceData = features
    .filter(f => f.Importance_Mean > 0)
    .slice(0, 10)
    .map(f => ({
      name: f.Feature.replace(/_/g, ' '),
      importance: +(f.Importance_Mean * 100).toFixed(2),
    }))

  return (
    <div>
      <div className="mb-8">
        <h2 className="text-2xl font-bold flex items-center gap-2">
          <BarChart3 size={24} className="text-purple-400" />
          Model Performance Comparison
        </h2>
        <p className="text-gray-500 mt-1">
          Isolation Forest (main) vs LOF & One-Class SVM (benchmarks)
        </p>
      </div>

      {/* Metrics Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-8">
        <h3 className="text-lg font-semibold mb-4">Performance Metrics</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 border-b border-gray-800">
                <th className="text-left py-3 px-4">Model</th>
                <th className="text-right py-3 px-4">Accuracy</th>
                <th className="text-right py-3 px-4">Precision</th>
                <th className="text-right py-3 px-4">Recall</th>
                <th className="text-right py-3 px-4">F1-Score</th>
                <th className="text-right py-3 px-4">ROC-AUC</th>
                <th className="text-right py-3 px-4">PR-AUC</th>
                <th className="text-right py-3 px-4">FPR</th>
                <th className="text-right py-3 px-4">Train Time</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(comparison).map(([name, m]) => (
                <tr key={name} className={`border-b border-gray-800/50 ${
                  name === 'Isolation Forest' ? 'bg-blue-900/10' : ''
                }`}>
                  <td className="py-3 px-4 font-medium flex items-center gap-2">
                    {name}
                    {name === 'Isolation Forest' && (
                      <Award size={14} className="text-blue-400" />
                    )}
                  </td>
                  <td className="text-right py-3 px-4">{(m.Accuracy * 100).toFixed(1)}%</td>
                  <td className="text-right py-3 px-4">{(m.Precision * 100).toFixed(1)}%</td>
                  <td className="text-right py-3 px-4">{(m.Recall * 100).toFixed(1)}%</td>
                  <td className="text-right py-3 px-4 font-semibold">{(m['F1-Score'] * 100).toFixed(1)}%</td>
                  <td className="text-right py-3 px-4">{(m['ROC-AUC'] * 100).toFixed(1)}%</td>
                  <td className="text-right py-3 px-4">{(m['PR-AUC'] * 100).toFixed(1)}%</td>
                  <td className="text-right py-3 px-4">{(m.FPR * 100).toFixed(1)}%</td>
                  <td className="text-right py-3 px-4 flex items-center justify-end gap-1">
                    <Clock size={12} className="text-gray-500" />
                    {m['Training Time (s)'].toFixed(3)}s
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        {/* Bar Chart */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold mb-4">Metrics Comparison</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="name" stroke="#9CA3AF" />
              <YAxis domain={[0, 100]} stroke="#9CA3AF" />
              <Tooltip contentStyle={{ background: '#1F2937', border: '1px solid #374151' }} />
              <Legend />
              <Bar dataKey="Accuracy" fill="#3B82F6" />
              <Bar dataKey="F1-Score" fill="#10B981" />
              <Bar dataKey="ROC-AUC" fill="#8B5CF6" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Radar Chart */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold mb-4">Model Radar</h3>
          <ResponsiveContainer width="100%" height={300}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#374151" />
              <PolarAngleAxis dataKey="metric" stroke="#9CA3AF" />
              <PolarRadiusAxis domain={[0, 100]} stroke="#4B5563" />
              <Radar name="IF" dataKey="IF" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.2} />
              <Radar name="LOF" dataKey="LOF" stroke="#10B981" fill="#10B981" fillOpacity={0.2} />
              <Radar name="OCSVM" dataKey="OCSVM" stroke="#F59E0B" fill="#F59E0B" fillOpacity={0.2} />
              <Legend />
              <Tooltip contentStyle={{ background: '#1F2937', border: '1px solid #374151' }} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Feature Importance */}
      {importanceData.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Cpu size={20} className="text-green-400" />
            Feature Importance (Isolation Forest)
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={importanceData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis type="number" stroke="#9CA3AF" />
              <YAxis dataKey="name" type="category" width={180} stroke="#9CA3AF" />
              <Tooltip contentStyle={{ background: '#1F2937', border: '1px solid #374151' }} />
              <Bar dataKey="importance" fill="#10B981" name="Importance (%)" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}
