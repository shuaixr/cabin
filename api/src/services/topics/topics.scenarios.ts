import type { Prisma } from '@prisma/client'

export const standard = defineScenario<Prisma.TopicCreateArgs>({
  topic: {
    one: { data: { title: 'String' } },
    two: { data: { title: 'String' } },
  },
})

export type StandardScenario = typeof standard
