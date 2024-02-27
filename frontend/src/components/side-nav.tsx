"use client"

import * as React from "react"
import { ChevronsLeft, ChevronsRight, Hammer } from "lucide-react"
import { ImperativePanelHandle } from "react-resizable-panels"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable"
import { TooltipProvider } from "@/components/ui/tooltip"
import {
  CollapsibleLogo,
  CollapsibleSidebar,
  NavLink,
} from "@/components/collapsible-sidebar"
import { ThemeToggle } from "@/components/theme/toggle"

const links: NavLink[] = [
  {
    title: "Workbench",
    icon: Hammer,
    href: "/workbench",
    variant: "ghost",
  },
]
interface SideNavProps {
  children: React.ReactNode
  defaultLayout: number[] | undefined
  defaultCollapsed?: boolean
  navCollapsedSize: number
}

const smoothTransitions = false

export function SideNav({
  children,
  defaultLayout = [1, 60, 20],
  defaultCollapsed = true,
  navCollapsedSize,
}: SideNavProps) {
  const sidePanelRef = React.useRef<ImperativePanelHandle>(null)
  const [isCollapsed, setIsCollapsed] = React.useState(defaultCollapsed)

  const toggleSidePanel = () => {
    const side = sidePanelRef.current
    if (!side) {
      return
    }
    if (side.isCollapsed()) {
      side.expand()
    } else {
      side.collapse()
    }
    setIsCollapsed(!isCollapsed)
    document.cookie = `react-resizable-panels:collapsed=${JSON.stringify(
      !isCollapsed
    )}`
  }

  return (
    <TooltipProvider delayDuration={0}>
      <ResizablePanelGroup
        direction="horizontal"
        onLayout={(sizes: number[]) => {
          document.cookie = `react-resizable-panels:layout=${JSON.stringify(
            sizes
          )}`
        }}
        className="h-full max-h-screen items-stretch"
      >
        <ResizablePanel
          ref={sidePanelRef}
          defaultSize={defaultLayout[0]}
          collapsedSize={navCollapsedSize}
          collapsible={true}
          minSize={8}
          maxSize={20}
          onCollapse={() => {
            setIsCollapsed(true)
            document.cookie = `react-resizable-panels:collapsed=${JSON.stringify(
              true
            )}`
          }}
          onExpand={() => {
            setIsCollapsed(false)
            document.cookie = `react-resizable-panels:collapsed=${JSON.stringify(
              false
            )}`
          }}
          className={cn(
            "flex min-w-[50px] flex-col",
            smoothTransitions && "transition-all duration-300 ease-in-out"
          )}
        >
          <CollapsibleLogo isCollapsed={isCollapsed} />
          <CollapsibleSidebar isCollapsed={isCollapsed} links={links} />
          <div className="flex h-full flex-col justify-end">
            <ThemeToggle className="justify-end hover:bg-transparent" />
            <PanelToggle
              className="justify-end"
              isCollapsed={isCollapsed}
              toggleSidePanel={toggleSidePanel}
            />
          </div>
        </ResizablePanel>
        <ResizableHandle />
        <ResizablePanel defaultSize={defaultLayout[1]} minSize={30}>
          {children}
        </ResizablePanel>
      </ResizablePanelGroup>
    </TooltipProvider>
  )
}
interface PanelToggleProps extends React.HTMLAttributes<HTMLDivElement> {
  isCollapsed: any
  toggleSidePanel: React.MouseEventHandler<HTMLButtonElement> | undefined
}
function PanelToggle({
  isCollapsed,
  toggleSidePanel,
  className,
}: PanelToggleProps) {
  return (
    <div
      data-collapsed={isCollapsed}
      className={cn(
        "group flex flex-col gap-4 py-2 data-[collapsed=true]:py-2",
        className
      )}
    >
      <nav className="grid gap-1 px-2 group-[[data-collapsed=true]]:justify-center group-[[data-collapsed=true]]:px-2">
        <Button
          variant="ghost"
          className={cn(
            "hover:bg-transparent",
            !isCollapsed && "justify-start"
          )}
          onClick={toggleSidePanel}
        >
          {isCollapsed ? (
            <ChevronsRight className="h-4 w-4" />
          ) : (
            <ChevronsLeft className="mr-2 h-4 w-4" />
          )}
        </Button>
      </nav>
    </div>
  )
}
