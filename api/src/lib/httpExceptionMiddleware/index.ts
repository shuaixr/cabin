import { MiddlewareHandler } from '../middleware'
import { HttpException } from './HttpExceptions'

export const httpExceptionMiddleware: MiddlewareHandler =
  (handler) => (event, context, callback) => {
    try {
      return handler(event, context, callback)
    } catch (error) {
      return new Promise((resolve, reject) => {
        if (error instanceof HttpException) {
          resolve({
            statusCode: error.getStatus(),
            body: error.getStringReponse(),
          })
        } else {
          reject(error)
        }
      })
    }
  }
export * from './HttpExceptions'
