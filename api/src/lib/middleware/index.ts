import { APIGatewayProxyHandler } from '../handler'
import { httpExceptionMiddleware } from '../httpExceptionMiddleware'

export type MiddlewareHandler = (
  handler: APIGatewayProxyHandler
) => APIGatewayProxyHandler

export const makeMiddleware = (
  ...list: MiddlewareHandler[]
): MiddlewareHandler => {
  return (handler) => {
    return list.reduce(
      (previousValue, currentValue) => currentValue(previousValue),
      handler
    )
  }
}

export const useMidleware = makeMiddleware(httpExceptionMiddleware)
