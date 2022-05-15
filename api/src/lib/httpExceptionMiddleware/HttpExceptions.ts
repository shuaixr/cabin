import { StatusCodes } from 'http-status-codes'

export class HttpException extends Error {
  constructor(
    private readonly response: string | Record<string, unknown>,
    private readonly status: number
  ) {
    super()
    this.response = response
    this.status = status
    if (typeof response == 'string') {
      this.message = response
    } else {
      this.message = JSON.stringify(this.response)
    }
  }
  getStringReponse() {
    return this.message
  }
  getStatus() {
    return this.status
  }
}

export class BadRequestException extends HttpException {
  constructor(body: Record<string, unknown> = { msg: 'Bad Request' }) {
    super(body, StatusCodes.BAD_REQUEST)
  }
}

export class UnauthorizedException extends HttpException {
  constructor(body: Record<string, unknown> = { msg: 'Unauthorized' }) {
    super(body, StatusCodes.UNAUTHORIZED)
  }
}

export class MethodNotAllowedException extends HttpException {
  constructor(body: Record<string, unknown> = { msg: 'Method Not Allowed' }) {
    super(body, StatusCodes.METHOD_NOT_ALLOWED)
  }
}
export class InternalServerErrorException extends HttpException {
  constructor(
    body: Record<string, unknown> = { msg: 'Internal Server Error' }
  ) {
    super(body, StatusCodes.INTERNAL_SERVER_ERROR)
  }
}
