import { Link, routes } from '@redwoodjs/router'
import { Toaster } from '@redwoodjs/web/toast'

type TopicLayoutProps = {
  children: React.ReactNode
}

const TopicsLayout = ({ children }: TopicLayoutProps) => {
  return (
    <div className="rw-scaffold">
      <Toaster toastOptions={{ className: 'rw-toast', duration: 6000 }} />
      <header className="rw-header">
        <h1 className="rw-heading rw-heading-primary">
          <Link to={routes.topics()} className="rw-link">
            Topics
          </Link>
        </h1>
        <Link to={routes.newTopic()} className="rw-button rw-button-green">
          <div className="rw-button-icon">+</div> New Topic
        </Link>
      </header>
      <main className="rw-main">{children}</main>
    </div>
  )
}

export default TopicsLayout
