import React, { useState } from 'react'
import { Shield, BarChart3, Bell, Monitor, Settings, Activity } from 'lucide-react'
import Dashboard from './pages/Dashboard'
import Alerts from './pages/Alerts'
import ModelPerformance from './pages/ModelPerformance'
import KibanaEmbed from './pages/KibanaEmbed'
import SettingsPage from './pages/Settings'

type Page = 'dashboard' | 'alerts' | 'models' | 'kibana' | 'settings'

const navItems: { id: Page; label: string; icon: React.ReactNode }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: <Monitor size={20} /> },
  { id: 'alerts', label: 'Alerts', icon: <Bell size={20} /> },
  { id: 'models', label: 'Model Performance', icon: <BarChart3 size={20} /> },
  { id: 'kibana', label: 'Kibana', icon: <Activity size={20} /> },
  { id: 'settings', label: 'Settings', icon: <Settings size={20} /> },
]

export default function App() {
  const [currentPage, setCurrentPage] = useState<Page>('dashboard')

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard': return <Dashboard />
      case 'alerts': return <Alerts />
      case 'models': return <ModelPerformance />
      case 'kibana': return <KibanaEmbed />
      case 'settings': return <SettingsPage />
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex">
      {/* Sidebar */}
      <aside className="w-64 bg-gray-900 border-r border-gray-800 flex flex-col">
        <div className="p-6 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <Shield className="text-blue-500" size={28} />
            <div>
              <h1 className="font-bold text-lg">SSH Guard AI</h1>
              <p className="text-xs text-gray-500">Brute-Force Detection</p>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-1">
          {navItems.map(item => (
            <button
              key={item.id}
              onClick={() => setCurrentPage(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm transition-colors ${
                currentPage === item.id
                  ? 'bg-blue-600/20 text-blue-400 border border-blue-600/30'
                  : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
              }`}
            >
              {item.icon}
              {item.label}
            </button>
          ))}
        </nav>

        <div className="p-4 border-t border-gray-800">
          <div className="text-xs text-gray-600 text-center">
            AI-Powered Early Prediction
            <br />FPT University Capstone 2026
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <div className="p-8">
          {renderPage()}
        </div>
      </main>
    </div>
  )
}
