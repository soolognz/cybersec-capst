import React from 'react'
import { Activity, ExternalLink } from 'lucide-react'

export default function KibanaEmbed() {
  const kibanaUrl = 'http://localhost:5601'

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-bold flex items-center gap-2">
            <Activity size={24} className="text-green-400" />
            Kibana Dashboard
          </h2>
          <p className="text-gray-500 mt-1">ELK Stack log visualization and analytics</p>
        </div>
        <a
          href={kibanaUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 px-4 py-2 bg-gray-800 rounded-lg text-sm hover:bg-gray-700 transition-colors"
        >
          Open in new tab <ExternalLink size={14} />
        </a>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden" style={{ height: 'calc(100vh - 200px)' }}>
        <iframe
          src={`${kibanaUrl}/app/dashboards`}
          className="w-full h-full border-0"
          title="Kibana Dashboard"
          sandbox="allow-same-origin allow-scripts allow-popups allow-forms"
        />
      </div>
    </div>
  )
}
