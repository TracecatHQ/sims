import { ThemeToggle } from "@/components/theme/toggle"

export default function ThemeControls() {
  return (
    <div className="container flex flex-1 items-center justify-center space-x-4 py-3">
      <nav className="flex items-center space-x-1">
        <ThemeToggle />
      </nav>
    </div>
  )
}
