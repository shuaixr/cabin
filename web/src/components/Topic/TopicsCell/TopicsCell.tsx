import type { FindTopics } from 'types/graphql'
import type { CellSuccessProps, CellFailureProps } from '@redwoodjs/web'

import { Link, routes } from '@redwoodjs/router'

import Topics from 'src/components/Topic/Topics'

export const QUERY = gql`
  query FindTopics {
    topics {
      id
      title
    }
  }
`

export const Loading = () => <div>Loading...</div>

export const Empty = () => {
  return (
    <div className="rw-text-center">
      {'No topics yet. '}
      <Link
        to={routes.newTopic()}
        className="rw-link"
      >
        {'Create one?'}
      </Link>
    </div>
  )
}

export const Failure = ({ error }: CellFailureProps) => (
  <div className="rw-cell-error">{error.message}</div>
)

export const Success = ({ topics }: CellSuccessProps<FindTopics>) => {
  return <Topics topics={topics} />
}
