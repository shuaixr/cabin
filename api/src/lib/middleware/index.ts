import { APIGatewayProxyHandlerV2 } from 'aws-lambda'
import { httpExceptionMiddleware } from '../httpExceptionMiddleware'

export type MiddlewareHandler = (
  handler: APIGatewayProxyHandlerV2
) => APIGatewayProxyHandlerV2

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
