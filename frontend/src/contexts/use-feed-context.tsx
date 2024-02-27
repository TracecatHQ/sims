"use client"

import React, { useCallback, useState } from "react"
import { FeedItem, feedItemSchema } from "@/schemas/workbench/feed"
import useWebSocket from "react-use-websocket"

export const useFeedContext = () => React.useContext(FeedContext)

const FeedContext = React.createContext({
  feedItems: [] as FeedItem[],
  setFeedItems: (items: FeedItem[]) => {},
  resetFeedItems: () => {},
  isRunning: false,
  setIsRunning: (isLoading: boolean) => {},
  connect: (params: Record<string, any>) => {},
  disconnect: () => {},
})

const FeedProvider = (props: { children: React.ReactNode }) => {
  const [isRunning, setIsRunning] = useState(false)
  const [feedItems, setFeedItems] = useState<FeedItem[]>([])
  const { sendJsonMessage, lastJsonMessage, getWebSocket } = useWebSocket(
    `${process.env.NEXT_PUBLIC_API_URL?.replace("https", "wss")}/feed/logs/ws`,
    {
      onOpen: () => console.log("Connection opened"),
      onClose: () => console.log("Connection closed"),
      shouldReconnect: (_closeEvent) => false,
      onMessage: (event) => {
        if (!lastJsonMessage) return
        console.log("Last message", lastJsonMessage)
        const newFeedItem = feedItemSchema.parse(lastJsonMessage)
        setFeedItems((prevItems) => prevItems.concat(newFeedItem))
      },
    }
  )

  const connect = useCallback(
    (data: Record<string, any>) => {
      if (!isRunning) {
        setIsRunning(true) // Update connection status
        // Send initial data upon connection
        sendJsonMessage(data)
      }
    },
    [isRunning, sendJsonMessage]
  )

  const disconnect = useCallback(() => {
    const websocketInstance = getWebSocket()
    if (websocketInstance) {
      websocketInstance.close() // Close the connection
      setIsRunning(false) // Update connection status
      console.log("Disconnected")
    }
  }, [getWebSocket])

  return (
    <FeedContext.Provider
      value={{
        feedItems,
        setFeedItems,
        resetFeedItems: () => setFeedItems([]),
        isRunning,
        setIsRunning,
        connect,
        disconnect,
      }}
    >
      {props.children}
    </FeedContext.Provider>
  )
}
export default FeedProvider
