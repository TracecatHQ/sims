import React, { useCallback, useRef, useState } from "react"
import ReactFlow, {
  Background,
  Connection,
  Controls,
  Edge,
  MarkerType,
  Node,
  OnConnect,
  ReactFlowInstance,
  ReactFlowProvider,
  addEdge,
  useEdgesState,
  useNodesState,
  useReactFlow,
} from "reactflow"

import "reactflow/dist/style.css"
import { useToast } from "@/components/ui/use-toast"
import PrimitiveNode, {
  PrimitiveNodeData,
} from "@/components/workbench/canvas/primitive-node"

let id = 0
const getId = (): string => `dndnode_${id++}`

const nodeTypes = {
  primitive: PrimitiveNode,
}

const defaultEdgeOptions = {
  markerEnd: {
    type: MarkerType.ArrowClosed,
  },
  style: { strokeWidth: 3 },
}

const DnDFlow: React.FC = () => {
  const reactFlowWrapper = useRef<HTMLDivElement>(null)
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [reactFlowInstance, setReactFlowInstance] =
    useState<ReactFlowInstance | null>(null)
  const { toast } = useToast()

  const onConnect = useCallback(
    (params: Edge | Connection) => {
      if (
        edges.filter((e) => e.source === params.source).length > 0 ||
        edges.filter((e) => e.target === params.target).length > 0
      ) {
        toast({
          title: "Invalid action",
          description: "MUltiple incoming or outgoing edges not supported.",
        })
        return
      }

      setEdges((eds) => addEdge(params, eds))
    },
    [toast, edges, setEdges]
  )

  const onDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault()
    event.dataTransfer.dropEffect = "move"
  }, [])

  const onDrop = (event: React.DragEvent) => {
    event.preventDefault()

    // Limit toatal number of nodes
    if (nodes.length >= 10) {
      toast({
        title: "Invalid action",
        description: "Maximum 10 nodes allowed.",
      })
      return
    }

    const type = event.dataTransfer.getData("application/reactflow")
    const data = JSON.parse(
      event.dataTransfer.getData("application/json")
    ) as PrimitiveNodeData

    if (!data || !type || !reactFlowInstance) return

    const position = reactFlowInstance.screenToFlowPosition({
      x: event.clientX,
      y: event.clientY,
    })

    const newNode = {
      id: getId(),
      type,
      position,
      data,
    } as Node<PrimitiveNodeData>

    setNodes((nds) => nds.concat(newNode))
  }

  return (
    <div ref={reactFlowWrapper} style={{ height: "100%" }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        defaultEdgeOptions={defaultEdgeOptions}
        onConnect={onConnect as OnConnect}
        onInit={setReactFlowInstance}
        onDrop={onDrop}
        onDragOver={onDragOver}
        nodeTypes={nodeTypes}
        fitViewOptions={{ maxZoom: 1 }}
        proOptions={{ hideAttribution: true }}
      >
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  )
}

const DnDFlowProvider = ReactFlowProvider
const useDnDFlow = useReactFlow

export { DnDFlowProvider, useDnDFlow }
export default DnDFlow
