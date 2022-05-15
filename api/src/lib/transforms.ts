import type { APIGatewayProxyEventV2 } from 'aws-lambda'
import { Headers } from 'cross-undici-fetch'

// This is the same interface used by GraphQL Yoga
// But not importing here to avoid adding a dependency
export interface Request {
  body?: APIGatewayProxyEventV2['body']
  headers: Headers
  method: string
  query: APIGatewayProxyEventV2['queryStringParameters']
}

/**
 * Extracts and parses body payload from event with base64 encoding check
 */
export const parseEventBody = (event: APIGatewayProxyEventV2) => {
  if (!event.body) {
    return
  }

  if (event.isBase64Encoded) {
    return JSON.parse(Buffer.from(event.body, 'base64').toString('utf-8'))
  } else {
    return JSON.parse(event.body)
  }
}

export function normalizeRequest(event: APIGatewayProxyEventV2): Request {
  const body = parseEventBody(event)

  return {
    headers: new Headers(event.headers as Record<string, string>),
    method: event.requestContext.http.method,
    query: event.queryStringParameters,
    body,
  }
}
