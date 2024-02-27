import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function groupBy<T, K extends keyof T>(
  array: T[],
  key: K
): Record<string, T[]> {
  return array.reduce((accumulator, currentItem) => {
    const groupKey = currentItem[key] as unknown as string
    if (!accumulator[groupKey]) {
      accumulator[groupKey] = []
    }
    accumulator[groupKey].push(currentItem)
    return accumulator
  }, {} as Record<string, T[]>)
}

export function flattenMap(
  startNodeId: string,
  adj: Map<string, string>
): string[] {
  const result: string[] = []
  let currentId = startNodeId // Start from the initial node

  while (currentId) {
    result.push(currentId) // Add the current node to the result list
    currentId = adj.get(currentId) || "" // Move to the next node
    if (!currentId) break // If there is no next node, exit the loop
  }

  return result
}
