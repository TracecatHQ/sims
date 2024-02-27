import { DragEvent } from "react"
import { usePrimitiveLibContext } from "@/contexts/use-primitives-context"
import { Primitive } from "@/schemas/workbench/primitive"
import { ScrollArea } from "@radix-ui/react-scroll-area"

import { groupBy } from "@/lib/utils"
import { Card } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import { CollapsibleSection } from "@/components/collapsible-section"
import { iconMap } from "@/components/icons/aws"

export default function Catalog() {
  const { primitives } = usePrimitiveLibContext()
  const onDragStart = (
    event: DragEvent<HTMLDivElement>,
    nodeType: string,
    data: string
  ) => {
    event.dataTransfer.setData("application/reactflow", nodeType)
    event.dataTransfer.setData("application/json", data)
    event.dataTransfer.effectAllowed = "move"
  }

  return (
    <div className="flex h-full select-none flex-col space-y-4 p-4 text-sm">
      <ScrollArea className="no-scrollbar h-full overflow-auto rounded-md">
        {Object.entries(groupBy(primitives, "tactic")).map(
          ([tactic, primitives], index) => {
            return (
              <div key={index} className="mt-2 items-center">
                <CollapsibleSection
                  title={tactic}
                  showToggleText={false}
                  className="text-md truncate text-start font-medium"
                  size="lg"
                  iconSize="md"
                  defaultIsOpen
                >
                  <CatalogSection
                    primitives={primitives}
                    dragHandler={onDragStart}
                  />
                </CollapsibleSection>
                <Separator className="mt-4" />
              </div>
            )
          }
        )}
      </ScrollArea>
    </div>
  )
}

interface CatalogSectionProps extends React.HTMLAttributes<HTMLDivElement> {
  primitives: Primitive[]
  dragHandler: (
    event: DragEvent<HTMLDivElement>,
    nodeType: string,
    data: string
  ) => void
}
function CatalogSection({ primitives, dragHandler }: CatalogSectionProps) {
  return (
    <div className="space-y-2">
      {primitives.map((primitive, index) => {
        const Icon = iconMap[primitive.product as string]
        return (
          <CatalogItem
            key={index}
            onDragStart={(event) =>
              dragHandler(event, "primitive", JSON.stringify(primitive))
            }
            draggable
            primitive={primitive}
            Icon={Icon}
          />
        )
      })}
    </div>
  )
}

export interface CatalogItemProps extends React.HTMLAttributes<HTMLDivElement> {
  primitive: Primitive
  Icon: React.FC<React.SVGProps<SVGSVGElement>>
}

export function CatalogItem({ primitive, Icon, ...props }: CatalogItemProps) {
  return (
    <Card
      className="flex items-center p-2 text-start transition-all hover:cursor-grab hover:bg-accent"
      {...props}
    >
      <Icon className="mr-2 shrink-0 rounded-lg" />
      <div className="flex flex-col">
        <span className="grow">{primitive.displayName}</span>
        <span className="uppercase text-gray-400">
          {primitive.platform}-{primitive.product}
        </span>
      </div>
    </Card>
  )
}
