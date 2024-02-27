import "@/styles/globals.css"
import { Metadata } from "next"
import { cookies } from "next/headers"
import PrimitiveLibProvider from "@/contexts/use-primitives-context"
import { Analytics } from "@vercel/analytics/react"
import { SpeedInsights } from "@vercel/speed-insights/next"

import { siteConfig } from "@/config/site"
import { fontSans } from "@/lib/fonts"
import { cn } from "@/lib/utils"
import { Toaster } from "@/components/ui/toaster"
import { SideNav } from "@/components/side-nav"
import { ThemeProvider } from "@/components/theme/provider"

export const metadata: Metadata = {
  title: {
    default: siteConfig.name,
    template: `%s - ${siteConfig.name}`,
  },
  description: siteConfig.description,
  icons: {
    icon: "/favicon.png",
    shortcut: "/favicon.png",
    apple: "/apple-touch-icon.png",
  },
}

export const viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "white" },
    { media: "(prefers-color-scheme: dark)", color: "black" },
  ],
}

interface RootLayoutProps {
  children: React.ReactNode
}

export default function RootLayout({ children }: RootLayoutProps) {
  const layout = cookies().get("react-resizable-panels:layout")
  const collapsed = cookies().get("react-resizable-panels:collapsed")

  const defaultLayout = layout ? JSON.parse(layout.value) : undefined
  const defaultCollapsed = collapsed ? JSON.parse(collapsed.value) : true
  return (
    <>
      <html
        lang="en"
        className="dark h-full min-h-screen"
        suppressHydrationWarning
      >
        <head>
          <script
            async
            src="https://tag.clearbitscripts.com/v1/pk_d32d00243aee0773786e72d768420610/tags.js"
            referrerPolicy="strict-origin-when-cross-origin"
          ></script>
        </head>
        <body
          className={cn(
            "h-screen min-h-screen bg-background font-sans antialiased",
            fontSans.variable
          )}
        >
          <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
            <PrimitiveLibProvider>
              <SideNav
                defaultLayout={defaultLayout}
                navCollapsedSize={2}
                defaultCollapsed={defaultCollapsed}
              >
                {children}
              </SideNav>
            </PrimitiveLibProvider>
          </ThemeProvider>
          <Toaster />
          <Analytics />
          <SpeedInsights />
        </body>
      </html>
    </>
  )
}
