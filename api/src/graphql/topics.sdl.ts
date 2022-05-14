export const schema = gql`
  type Topic {
    id: Int!
    title: String!
    content: String!
    authorId: Int!
  }

  type Query {
    topics: [Topic!]! @requireAuth
    topic(id: Int!): Topic @requireAuth
  }

  input CreateTopicInput {
    title: String!
    content: String!
    authorId: Int!
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
