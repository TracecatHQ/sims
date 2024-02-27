"use client"

import React, { useEffect, useState } from "react"
import { Primitive, primitiveSchema } from "@/schemas/workbench/primitive"
import { z } from "zod"

import { primitivesList } from "@/components/workbench/library/primitives"

export const usePrimitiveLibContext = () =>
  React.useContext(PrimitiveLibContext)

const PrimitiveLibContext = React.createContext({
  primitives: [] as Primitive[],
})

const PrimitiveLibProvider = (props: { children: React.ReactNode }) => {
  const [primitives, setPrimitives] = useState<Primitive[]>([])

  useEffect(() => {
    const newPrimitives = z.array(primitiveSchema).parse(primitivesList)
    setPrimitives(newPrimitives)
  }, [])

  return (
    <PrimitiveLibContext.Provider
      value={{
        primitives,
      }}
    >
      {props.children}
    </PrimitiveLibContext.Provider>
  )
}
export default PrimitiveLibProvider
