"use client"

import React from "react"
import FeedProvider from "@/contexts/use-feed-context"

import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable"
import { Separator } from "@/components/ui/separator"
import Canvas, { DnDFlowProvider } from "@/components/workbench//canvas/flow"
import Catalog from "@/components/workbench/library/catalog"
import LogsPanel from "@/components/workbench/logs/panel"

export default function WorkbenchPage() {
  return (
    <FeedProvider>
      <DnDFlowProvider>
        <div className="flex items-center px-4 py-2">
          <h1 className="text-lg font-bold">Workbench</h1>
        </div>
        <Separator />
        <ResizablePanelGroup direction="horizontal" className="h-full">
          <ResizablePanel defaultSize={15} minSize={15}>
            <Catalog />
          </ResizablePanel>
          <ResizableHandle />
          <ResizablePanel defaultSize={65} minSize={30}>
            <Canvas />
          </ResizablePanel>
          <ResizableHandle withHandle />
          <ResizablePanel defaultSize={20} minSize={20}>
            <LogsPanel />
          </ResizablePanel>
        </ResizablePanelGroup>
      </DnDFlowProvider>
    </FeedProvider>
  )
}
