import {
  BadRequestException,
  MethodNotAllowedException,
  UnauthorizedException,
} from '../httpExceptionMiddleware'

export class NoSessionSecretError extends Error {
  constructor() {
    super(
      'dbAuth requires a SESSION_SECRET environment variable that is used to encrypt session cookies. Use `yarn rw g secret` to create one, then add to your `.env` file. DO NOT check this variable in your version control system!!'
    )
    this.name = 'NoSessionSecretError'
  }
}

export class NoSessionExpirationError extends Error {
  constructor() {
    super('dbAuth requires login expiration time, in seconds')

    this.name = 'NoSessionExpirationError'
  }
}
export class UnknownAuthMethodError extends MethodNotAllowedException {
  constructor(name: string) {
    super({ code: 100, msg: `Unknown auth method '${name}'` })
  }
}

export class WrongVerbError extends Error {
  constructor(properVerb: string) {
    super(`Only accessible via ${properVerb}`)
    this.name = 'WrongVerbError'
  }
}

export class NotLoggedInError extends UnauthorizedException {
  constructor() {
    super({
      code: 101,
      msg: 'Cannot retrieve user details without being logged in',
    })
  }
}

export class UserNotFoundError extends BadRequestException {
  constructor() {
    super({ code: 102, msg: 'User not found' })
  }
}

export class UsernameAndPasswordRequiredError extends BadRequestException {
  constructor() {
    super({ code: 103, msg: 'Both username and password are required' })
  }
}

export class NoUserIdError extends Error {
  constructor() {
    super(
      'loginHandler() must return an object with an `id` field as set in `authFields.id`'
    )
    this.name = 'NoUserIdError'
  }
}
/*
export class FieldRequiredError extends Error {
  constructor(
    name: string,
    message: string | undefined = '${field} is required'
  ) {
    super(message.replace(/\$\{field\}/g, name))
    this.name = 'FieldRequiredError'
  }
}
*/
export class DuplicateEmailError extends BadRequestException {
  constructor() {
    super({ code: 105, msg: 'Email already in use' })
  }
}

export class IncorrectPasswordError extends BadRequestException {
  constructor() {
    super({ code: 106, msg: 'Incorrect password' })
  }
}

export class CsrfTokenMismatchError extends BadRequestException {
  constructor() {
    super({ code: 107, msg: 'CSRF token mismatch' })
  }
}

export class SessionDecryptionError extends BadRequestException {
  constructor() {
    super({ code: 108, msg: 'Session has potentially been tampered with' })
  }
}

export class EmailRequiredError extends BadRequestException {
  constructor() {
    super({ code: 109, msg: 'Email is required' })
  }
}

export class PasswordRequiredError extends BadRequestException {
  constructor() {
    super({ code: 110, msg: 'Password is required' })
  }
}

export class UsernameNotFoundError extends BadRequestException {
  constructor() {
    super({ code: 111, msg: 'Username not found' })
  }
}

export class ResetTokenExpiredError extends BadRequestException {
  constructor() {
    super({ code: 112, msg: 'resetToken is expired' })
  }
}

export class ResetTokenInvalidError extends BadRequestException {
  constructor() {
    super({ code: 113, msg: 'resetToken is invalid' })
  }
}

export class ResetTokenRequiredError extends BadRequestException {
  constructor() {
    super({ code: 114, msg: 'ResetTokenRequiredError' })
  }
}

export class ReusedPasswordError extends BadRequestException {
  constructor() {
    super({ code: 116, msg: 'Must choose a new password' })
  }
}

export class GenericError extends Error {
  constructor(message = 'unknown error occurred') {
    super(message)
    this.name = 'GenericError'
  }
}
