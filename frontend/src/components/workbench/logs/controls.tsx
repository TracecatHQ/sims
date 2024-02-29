"use client"

import { useCallback, useEffect, useState } from "react"
import { useFeedContext } from "@/contexts/use-feed-context"
import { Primitive } from "@/schemas/workbench/primitive"
import { Edge, Node } from "reactflow"
import { v4 as uuidv4 } from "uuid"

import { flattenMap } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { toast } from "@/components/ui/use-toast"
import { useDnDFlow } from "@/components/workbench/canvas/flow"

interface LogsControlsProps extends React.HTMLAttributes<HTMLDivElement> {
  scenario?: string
}

function LogsControls({ className, scenario }: LogsControlsProps) {
  const { getNodes, getEdges, setEdges } = useDnDFlow()
  const { feedItems, setFeedItems, isRunning, setIsRunning, connect } =
    useFeedContext()
  const [jobUuid, setJobUuid] = useState<string | null>(null)

  const toggleEdgeAnimation = useCallback(
    (animated: boolean) => {
      const edges = getEdges()
      setEdges(
        edges.map(
          (edge: Edge) =>
            ({
              ...edge,
              animated,
            } as Edge)
        )
      )
    },
    [setEdges, getEdges]
  )

  const handleRun = async () => {
    if (!scenario) {
      toast({
        title: "Invalid action",
        description: "Please select a scenario.",
      })
      return
    }
    const nodes = getNodes()
    const edges = getEdges()
    if (nodes.length === 0) {
      toast({
        title: "Invalid action",
        description: "Please add at least one node.",
      })
      return
    }

    // Count the number of nodes that don't have any incoming edges

    let startNodes = new Set<string>(
      nodes.map((node: Node<Primitive>) => node.id)
    )
    edges.forEach((edge: Edge) => {
      startNodes.delete(edge.target)
    })

    if (startNodes.size > 1) {
      toast({
        title: "Invalid action",
        description: "Only one start node supported.",
      })
      return
    }

    // Convert nodes into map
    const nodeMap = new Map<string, Primitive>(
      nodes.map((node: Node<Primitive>) => [node.id, node.data])
    )
    // Extract the list from the graph
    const adj = new Map<string, string>(
      edges.map((edge: Edge) => [edge.source, edge.target])
    )

    const techniqueIds = flattenMap(Array.from(startNodes)[0], adj).map(
      (id) => nodeMap.get(id)?.stratusId
    )
    // Generate a uuid
    const sessionUuid = uuidv4()
    localStorage.setItem("sessionUuid", sessionUuid)

    connect({
      uuid: sessionUuid,
      scenario_id: scenario,
      technique_ids: techniqueIds,
    })
    toast({
      title: "Started lab",
      description: sessionUuid,
    })
    setJobUuid(sessionUuid)
  }

  const handleStopRun = useCallback(async () => {
    console.log("Stopping run")

    toast({
      title: "Cancelling lab",
      description: jobUuid,
    })
    toggleEdgeAnimation(false)
    setIsRunning(false)
  }, [jobUuid, setIsRunning, toggleEdgeAnimation])

  useEffect(() => {
    if (isRunning) {
      console.log("Subscribing to feed")
      toggleEdgeAnimation(true)
    } else {
      fetch(`${process.env.NEXT_PUBLIC_API_URL}/labs/${jobUuid}`, {
        method: "DELETE",
      }).then((response) => {
        if (!response.ok) {
          toast({
            title: "Failed to cancel lab",
            description: jobUuid,
          })
        }
      })
      toggleEdgeAnimation(false)
      setJobUuid(null)
      return
    }
    // Cleanup
    return () => {
      toggleEdgeAnimation(false)
      setIsRunning(false)
    }
  }, [isRunning]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="flex w-full items-center justify-between space-x-2">
      <Button
        className="w-1/2"
        variant={isRunning ? "destructive" : "default"}
        onClick={!isRunning ? handleRun : handleStopRun}
      >
        {isRunning ? "Cancel" : "Run"}
      </Button>

      <Button
        className="w-1/2"
        variant="destructive"
        disabled={isRunning || feedItems.length === 0}
        onClick={() => setFeedItems([])}
      >
        Clear
      </Button>
    </div>
  )
}

export default LogsControls
