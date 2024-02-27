import React from "react"
import { Handle, NodeProps, Position } from "reactflow"

import { Card } from "@/components/ui/card"
import { iconMap } from "@/components/icons/aws"

export interface PrimitiveNodeData {
  platform: string
  tactic: string
  product: string
  displayName: string
  severity: string
}

const handleStyle = { width: 8, height: 8 }

export default React.memo(function PrimitiveNode({
  data: { platform, product, tactic, displayName },
}: NodeProps<PrimitiveNodeData>) {
  const Icon = iconMap[product]
  return (
    <Card className="border-2 bg-white px-4 py-2 dark:border-slate-800 dark:bg-gray-900">
      <div className="flex">
        <div className="flex h-12 w-12 items-center justify-center rounded-md bg-gray-100 dark:bg-gray-800">
          <Icon className="rounded-md" />
        </div>
        <div className="ml-2">
          <div className="text-lg font-bold">{displayName}</div>
          <div className="capitalize text-gray-400">{tactic}</div>
          <div className="uppercase text-gray-400">
            @{platform}-{product}
          </div>
        </div>
      </div>

      <Handle
        type="target"
        position={Position.Top}
        className="w-16 !bg-gray-500"
        style={handleStyle}
      />
      <Handle
        type="source"
        position={Position.Bottom}
        className="w-16 !bg-gray-500"
        style={handleStyle}
      />
    </Card>
  )
})
