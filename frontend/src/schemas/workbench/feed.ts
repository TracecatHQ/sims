import { z } from "zod"

const userIdentitySchema = z
  .object({
    type: z.string(),
    principalId: z.string(),
    arn: z.string(),
    accountId: z.string(),
    accessKeyId: z.string(),
    userName: z.string(),
  })
  .partial()

const taskParametersSchema = z
  .object({
    commands: z.object({
      values: z.any(), // Could be more specific based on the actual data type expected
    }),
    executionTimeout: z.object({
      values: z.any(), // Could be more specific based on the actual data type expected
    }),
  })
  .partial()

const requestParametersSchema = z
  .object({
    windowId: z.string(),
    targets: z.any(), // Could be more specific based on the actual data type expected
    taskArn: z.string(),
    serviceRoleArn: z.string(),
    taskType: z.string(),
    taskParameters: taskParametersSchema,
    priority: z.number(),
    maxConcurrency: z.string(),
    maxErrors: z.string(),
  })
  .partial()

const responseElementsSchema = z
  .object({
    windowTaskId: z.string(),
  })
  .partial()

const taskSchema = z
  .object({
    name: z.string(),
    description: z.string(),
    actions: z.array(
      z.object({
        name: z.string(),
        description: z.string(),
        duration: z.number(),
      })
    ),
  })
  .partial()

const thoughtSchema = z
  .object({
    eventVersion: z.string(),
    userIdentity: userIdentitySchema.optional(),
    eventTime: z.string(),
    eventSource: z.string(),
    eventName: z.string(),
    awsRegion: z.string(),
    sourceIPAddress: z.string(),
    userAgent: z.string(),
    requestParameters: requestParametersSchema.nullable(),
    responseElements: responseElementsSchema.nullable(),
    requestID: z.string(),
    eventID: z.string(),
    eventType: z.string(),
    recipientAccountId: z.string(),
    name: z.string(),
    description: z.string(),
    tasks: z.array(taskSchema), // Could be more specific based on the actual data type expected
    job_title: z.string(),
  })
  .partial()

export const feedItemSchema = z.object({
  tag: z.enum(["background", "objective", "log"]),
  is_compromised: z.boolean(),
  uuid: z.string(),
  user_name: z.string(),
  thought: thoughtSchema,
  time: z.string(),
})

// Export the schema for use
export type FeedItem = z.infer<typeof feedItemSchema>
