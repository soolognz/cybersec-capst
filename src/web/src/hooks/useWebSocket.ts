import { useState, useEffect, useRef, useCallback } from 'react'

interface WSMessage {
  type: string
  [key: string]: any
}

export function useWebSocket(url: string) {
  const [messages, setMessages] = useState<WSMessage[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectRef = useRef<NodeJS.Timeout>()

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(url)

      ws.onopen = () => {
        setIsConnected(true)
        console.log('WebSocket connected')
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          setMessages(prev => [...prev.slice(-99), data])
        } catch {
          console.warn('Invalid WS message:', event.data)
        }
      }

      ws.onclose = () => {
        setIsConnected(false)
        reconnectRef.current = setTimeout(connect, 3000)
      }

      ws.onerror = () => {
        ws.close()
      }

      wsRef.current = ws
    } catch {
      reconnectRef.current = setTimeout(connect, 3000)
    }
  }, [url])

  useEffect(() => {
    connect()
    return () => {
      clearTimeout(reconnectRef.current)
      wsRef.current?.close()
    }
  }, [connect])

  const sendMessage = useCallback((msg: string) => {
    wsRef.current?.send(msg)
  }, [])

  return { messages, isConnected, sendMessage }
}
