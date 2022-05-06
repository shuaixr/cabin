export const schema = gql`
  type Topic {
    id: Int!
    title: String!
  }

  type Query {
    topics: [Topic!]! @requireAuth
    topic(id: Int!): Topic @requireAuth
  }

  input CreateTopicInput {
    title: String!
  }

  input UpdateTopicInput {
    title: String
  }

  type Mutation {
    createTopic(input: CreateTopicInput!): Topic! @requireAuth
    updateTopic(id: Int!, input: UpdateTopicInput!): Topic! @requireAuth
    deleteTopic(id: Int!): Topic! @requireAuth
  }
`
