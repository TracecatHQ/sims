import React from "react"
import { useFeedContext } from "@/contexts/use-feed-context"
import { FeedItem } from "@/schemas/workbench/feed"
import { ScrollArea } from "@radix-ui/react-scroll-area"
import {
  BookOpenText,
  Laugh,
  MessageCircleMore,
  ScrollText,
  Swords,
} from "lucide-react"
import { useTheme } from "next-themes"
import { ClipLoader } from "react-spinners"

import { cn } from "@/lib/utils"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import DecoratedHeader from "@/components/decorated-header"

export default function LogsFeed({
  className,
}: React.HTMLAttributes<HTMLDivElement>) {
  const { feedItems, isRunning } = useFeedContext()
  const { theme } = useTheme()

  return (
    <ScrollArea
      className={cn("h-full overflow-auto rounded-md border p-4", className)}
    >
      {feedItems.length === 0 ? (
        <main className="flex h-full w-full items-center justify-center text-muted-foreground">
          {isRunning ? (
            <ClipLoader
              color={theme === "dark" ? "#FFFFFF" : "#000000"}
              size={15}
            />
          ) : (
            "No logs to show."
          )}
        </main>
      ) : (
        <>
          {feedItems.map((itemProps, index) => (
            <LogsFeedItem className="my-2" key={index} {...itemProps} />
          ))}
        </>
      )}
    </ScrollArea>
  )
}

export function LogsFeedItem({
  className,
  tag,
  is_compromised,
  thought,
  user_name,
  ...props
}: FeedItem & React.HTMLAttributes<HTMLDivElement>) {
  const {
    icon: Icon,
    iconClassName,
    outerClassName,
  } = getFeedItemStyle(is_compromised)
  const side = is_compromised ? "Attacker" : "Agent"

  switch (tag) {
    case "background":
      return (
        <Card className={cn("border-2 text-sm", className, outerClassName)}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <DecoratedHeader
                size="md"
                title={`${side} created persona '${thought.job_title}'`}
                icon={Icon}
                iconProps={{ className: iconClassName }}
                className="normal-case"
              />
              <BookOpenText strokeWidth={1.5} size={20} />
            </div>
          </CardHeader>
          <CardContent className="flex flex-col space-y-4">
            <span className="prose-sm">{thought.description}</span>
          </CardContent>
        </Card>
      )
    case "objective":
      return (
        <Card className={cn("border-2 text-sm", className, outerClassName)}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <DecoratedHeader
                size="md"
                title={`${side} planned actions`}
                icon={Icon}
                iconProps={{ className: iconClassName }}
                className="normal-case"
              />
              <MessageCircleMore strokeWidth={1.5} size={20} />
            </div>
          </CardHeader>
          <CardContent className="flex flex-col space-y-4">
            {thought.tasks?.map(({ name, description }, index) => (
              <div key={index} className="flex flex-col">
                <span className="text-md font-semibold">
                  {index + 1}) {name}
                </span>
                <span className="prose-sm">{description}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      )
    case "log":
      return (
        <Card className={cn("border-2 text-sm", className, outerClassName)}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <DecoratedHeader
                size="md"
                title={`${side} performed '${thought.eventName}'`}
                icon={Icon}
                iconProps={{ className: iconClassName }}
                className="normal-case"
              />
              <ScrollText strokeWidth={1.5} size={20} />
            </div>
          </CardHeader>
          <CardContent>
            <ScrollArea className="max-h-[300px] overflow-auto rounded-md border p-4">
              <pre>
                <code>{JSON.stringify(thought, null, 2)}</code>
              </pre>
            </ScrollArea>
          </CardContent>
        </Card>
      )
    default:
      return <span>Unknown log type</span>
  }
}

const getFeedItemStyle = (isCompromised: boolean) => {
  return isCompromised
    ? {
        icon: Swords,
        iconClassName: "text-red-500",
        outerClassName: "border-red-500",
      }
    : {
        icon: Laugh,
        iconClassName: "text-green-500",
        outerClassName: "border-green-500",
      }
}
