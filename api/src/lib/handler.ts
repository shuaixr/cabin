import {
  Context,
  Callback,
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
} from 'aws-lambda'
export type Handler<TEvent = unknown, TResult = unknown> = (
  event: TEvent,
  context: Context,
  callback: Callback<TResult>
) => Promise<TResult>

export type APIGatewayProxyHandler = Handler<
  APIGatewayProxyEvent,
  APIGatewayProxyResult
>
