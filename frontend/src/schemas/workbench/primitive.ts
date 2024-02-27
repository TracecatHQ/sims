import { z } from "zod"

export const primitiveSchema = z.object({
  platform: z.string(),
  tactic: z.string(),
  product: z.string(),
  severity: z.string(),
  displayName: z.string(),
  stratusId: z.string(),
})

export type Primitive = z.infer<typeof primitiveSchema>
