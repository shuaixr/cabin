import { MiddlewareHandler } from '../middleware'
import { HttpException } from './HttpExceptions'

export const httpExceptionMiddleware: MiddlewareHandler =
  (handler) => async (event, context, callback) => {
    try {
      return await handler(event, context, callback)
    } catch (error) {
      if (error instanceof HttpException) {
        return {
          statusCode: error.getStatus(),
          body: error.getStringReponse(),
        }
      } else {
        throw error
      }
    }
  }
export * from './HttpExceptions'
