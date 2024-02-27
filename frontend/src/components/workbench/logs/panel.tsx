import * as React from "react"
import { CaretSortIcon, CheckIcon } from "@radix-ui/react-icons"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
} from "@/components/ui/command"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import LogsControls from "@/components/workbench/logs/controls"
import LogsFeed from "@/components/workbench/logs/feed"

const scenarios = [
  "codebuild_secrets",
  "ecs_efs_attack",
  "detection_evasion",
  "ec2_ssrf",
  "iam_privesec_by_attachment",
]
export default function LogsPanel() {
  const [open, setOpen] = React.useState(false)
  const [selectedPreset, setSelectedPreset] = React.useState<string>()

  return (
    <div className="flex h-full flex-col space-y-2 p-4">
      <h1 className="text-lg font-semibold">Log Feed</h1>
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="outline"
            role="combobox"
            aria-label="Load a scenario..."
            aria-expanded={open}
            className="w-full flex-1 justify-between"
          >
            {selectedPreset ?? "Load a preset..."}
            <CaretSortIcon className="ml-2 h-4 w-4 shrink-0 opacity-50" />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-[300px] p-0" align="start">
          <Command>
            <CommandInput placeholder="Search scenarios..." />
            <CommandEmpty>No presets found.</CommandEmpty>
            <CommandGroup heading="Scenarios">
              {scenarios.map((preset) => (
                <CommandItem
                  key={preset}
                  onSelect={() => {
                    setSelectedPreset(preset)
                    setOpen(false)
                  }}
                >
                  {preset}
                  <CheckIcon
                    className={cn(
                      "ml-auto h-4 w-4",
                      selectedPreset === preset ? "opacity-100" : "opacity-0"
                    )}
                  />
                </CommandItem>
              ))}
            </CommandGroup>
          </Command>
        </PopoverContent>
      </Popover>
      <LogsControls scenario={selectedPreset} />
      <LogsFeed className="h-full" />
    </div>
  )
}
