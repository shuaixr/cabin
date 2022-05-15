import { Prisma } from '@prisma/client'
import {
  CorsConfig,
  CorsContext,
  CorsHeaders,
  createCorsContext,
} from '@redwoodjs/api'
import {
  decryptSession,
  getSession,
} from '@redwoodjs/api/dist/functions/dbAuth/shared'
import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyResultV2 as APIGatewayProxyResult,
  Context as LambdaContext,
} from 'aws-lambda'
import CryptoJS from 'crypto-js'
import md5 from 'md5'
import { v4 as uuidv4 } from 'uuid'
import { db } from '../db'
import { normalizeRequest } from '../transforms'
import {
  CsrfTokenMismatchError,
  DuplicateEmailError,
  GenericError,
  IncorrectPasswordError,
  NoSessionExpirationError,
  NoSessionSecretError,
  NotLoggedInError,
  NoUserIdError,
  PasswordRequiredError,
  ResetTokenExpiredError,
  ResetTokenInvalidError,
  ResetTokenRequiredError,
  ReusedPasswordError,
  SessionDecryptionError,
  UnknownAuthMethodError,
  UsernameNotFoundError,
  EmailRequiredError,
  UserNotFoundError,
} from './errors'

interface AuthHandlerOptions {
  /**
   * Provide prisma db client
   */
  /*
  db: PrismaClient
  */
  /**
   * The name of the property you'd call on `db` to access your user table.
   * ie. if your Prisma model is named `User` this value would be `user`, as in `db.user`
   */
  /*
  authModelAccessor: keyof PrismaClient
  */
  /**
   *  A map of what dbAuth calls a field to what your database calls it.
   * `id` is whatever column you use to uniquely identify a user (probably
   * something like `id` or `userId` or even `email`)
   */ /*
  authFields: {
    id: string
    username: string
    hashedPassword: string
    salt: string
    resetToken: string
    resetTokenExpiresAt: string
  }*/
  /**
   * Object containing cookie config options
   */
  cookie?: {
    Path?: string
    HttpOnly?: boolean
    Secure?: boolean
    SameSite?: string
    Domain?: string
  }
  /**
   * Object containing forgot password options
   */
  forgotPassword: {
    /* handler: (user: Record<string, unknown>) => Promise<any>*/
    errors?: {
      usernameNotFound?: string
      usernameRequired?: string
    }
    expires: number
  }
  /**
   * Object containing login options
   */
  login: {
    /**
     * Anything you want to happen before logging the user in. This can include
     * throwing an error to prevent login. If you do want to allow login, this
     * function must return an object representing the user you want to be logged
     * in, containing at least an `id` field (whatever named field was provided
     * for `authFields.id`). For example: `return { id: user.id }`
     */
    /*handler: (user: Record<string, unknown>) => Promise<any>*/
    /**
     * Object containing error strings
     */
    errors?: {
      usernameOrPasswordMissing?: string
      usernameNotFound?: string
      incorrectPassword?: string
    }
    /**
     * How long a user will remain logged in, in seconds
     */
    expires: number
  }
  /**
   * Object containing reset password options
   */
  resetPassword: {
    /*handler: (user: Record<string, unknown>) => Promise<any>*/
    allowReusedPassword: boolean
    errors?: {
      resetTokenExpired?: string
      resetTokenInvalid?: string
      resetTokenRequired?: string
      reusedPassword?: string
    }
  }
  /**
   * Object containing login options
   */
  signup: {
    /**
     * Whatever you want to happen to your data on new user signup. Redwood will
     * check for duplicate usernames before calling this handler. At a minimum
     * you need to save the `username`, `hashedPassword` and `salt` to your
     * user table. `userAttributes` contains any additional object members that
     * were included in the object given to the `signUp()` function you got
     * from `useAuth()`
     */
    /*
    handler: (signupHandlerOptions: SignupHandlerOptions) => Promise<any>*/
    /**
     * Object containing error strings
     */
    errors?: {
      fieldMissing?: string
      usernameTaken?: string
    }
  }

  /**
   * CORS settings, same as in createGraphqlHandler
   */
  cors?: CorsConfig
}

interface SessionRecord {
  id: number
}

type AuthMethodNames =
  | 'forgotPassword'
  | 'getToken'
  | 'login'
  | 'logout'
  | 'resetPassword'
  | 'signup'
  | 'validateResetToken'
type AuthMethodReturn = {
  body: string
  headers: Record<string, string>
  options?: { statusCode: number }
}
type Params = {
  email?: string
  password?: string
  method: AuthMethodNames
  [key: string]: unknown
}

export class AuthHandler {
  event: APIGatewayProxyEventV2
  context: LambdaContext
  options: AuthHandlerOptions
  params: Params
  headerCsrfToken: string | undefined
  hasInvalidSession: boolean
  session: SessionRecord | undefined
  sessionCsrfToken: string | undefined
  corsContext: CorsContext | undefined
  futureExpiresDate: string

  // class constant: list of auth methods that are supported
  static get METHODS(): AuthMethodNames[] {
    return [
      'forgotPassword',
      'getToken',
      'login',
      'logout',
      'resetPassword',
      'signup',
      'validateResetToken',
    ]
  }

  // class constant: maps the auth functions to their required HTTP verb for access
  static get VERBS() {
    return {
      forgotPassword: 'POST',
      getToken: 'GET',
      login: 'POST',
      logout: 'POST',
      resetPassword: 'POST',
      signup: 'POST',
      validateResetToken: 'POST',
    }
  }

  // default to epoch when we want to expire
  static get PAST_EXPIRES_DATE() {
    return new Date('1970-01-01T00:00:00.000+00:00').toUTCString()
  }

  // generate a new token (standard UUID)
  static get CSRF_TOKEN() {
    return uuidv4()
  }

  // returns the Set-Cookie header to mark the cookie as expired ("deletes" the session)
  get _deleteSessionHeader() {
    return {
      'Set-Cookie': [
        'session=',
        ...this._cookieAttributes({ expires: 'now' }),
      ].join(';'),
    }
  }

  constructor(
    event: APIGatewayProxyEventV2,
    context: LambdaContext,
    options: AuthHandlerOptions
  ) {
    this.event = event
    this.context = context
    this.options = options

    this._validateOptions()

    this.params = this._parseBody()
    this.headerCsrfToken = this.event.headers['csrf-token']
    this.hasInvalidSession = false
    const futureDate = new Date()
    futureDate.setSeconds(futureDate.getSeconds() + this.options.login.expires)
    this.futureExpiresDate = futureDate.toUTCString()

    if (options.cors) {
      this.corsContext = createCorsContext(options.cors)
    }

    try {
      const [session, csrfToken] = decryptSession(
        getSession(this.event.headers['cookie'])
      )
      this.session = session
      this.sessionCsrfToken = csrfToken
    } catch (e) {
      // if session can't be decrypted, keep track so we can log them out when
      // the auth method is called
      if (e instanceof SessionDecryptionError) {
        this.hasInvalidSession = true
      } else {
        throw e
      }
    }
  }

  // Actual function that triggers everything else to happen: `login`, `signup`,
  // etc. is called from here, after some checks to make sure the request is good
  async invoke(): Promise<APIGatewayProxyResult> {
    const request = normalizeRequest(this.event)
    let corsHeaders = {}
    if (this.corsContext) {
      corsHeaders = this.corsContext.getRequestHeaders(request)
      // Return CORS headers for OPTIONS requests
      if (this.corsContext.shouldHandleCors(request)) {
        return this._buildResponseWithCorsHeaders(
          { body: '', statusCode: 200 },
          corsHeaders
        )
      }
    }

    // if there was a problem decryption the session, just return the logout
    // response immediately
    if (this.hasInvalidSession) {
      const { body, headers, options } = this._logoutResponse()
      return this._buildResponseWithCorsHeaders(
        this._ok(body, headers, options),
        corsHeaders
      )
    }
    /*
    try {*/
    const method = this._getAuthMethod()

    // get the auth method the incoming request is trying to call
    if (!AuthHandler.METHODS.includes(method)) {
      throw new UnknownAuthMethodError(method)
      // return this._buildResponseWithCorsHeaders(this._notFound(), corsHeaders)
    }

    // make sure it's using the correct verb, GET vs POST

    if (this.event.requestContext.http.method !== AuthHandler.VERBS[method]) {
      throw new UnknownAuthMethodError(method)
      // return this._buildResponseWithCorsHeaders(this._notFound(), corsHeaders)
    }

    // call whatever auth method was requested and return the body and headers
    const {
      body,
      headers,
      options = { statusCode: 200 },
    } = await this[method]()

    return this._buildResponseWithCorsHeaders(
      this._ok(body, headers, options),
      corsHeaders
    )
    /*
    } catch (e) {
      if (e instanceof WrongVerbError) {
        return this._buildResponseWithCorsHeaders(this._notFound(), corsHeaders)
      } else {
        return this._buildResponseWithCorsHeaders(
          this._badRequest(e.message || e),
          corsHeaders
        )
      }
    }*/
  }

  async forgotPassword(): Promise<AuthMethodReturn> {
    const { email } = this.params
    this._validateField(email, new EmailRequiredError())
    let user

    try {
      user = await db.user.findUnique({
        where: { email: email },
      })
    } catch (e) {
      console.log(e)
      throw new GenericError()
    }

    if (!user) {
      throw new UsernameNotFoundError()
    }
    const tokenExpires = new Date()
    tokenExpires.setSeconds(
      tokenExpires.getSeconds() + this.options.forgotPassword.expires
    )

    // generate a token
    let token = md5(uuidv4())
    const buffer = new Buffer(token)
    token = buffer.toString('base64').replace('=', '').substring(0, 16)

    try {
      // set token and expires time
      user = await db.user.update({
        where: {
          id: user.id,
        },
        data: {
          resetToken: token,
          resetTokenExpiresAt: tokenExpires,
        },
      })
    } catch (e) {
      console.log(e)
      throw new GenericError()
    }

    // call user-defined handler in their functions/auth.js
    /*const response = await this.options.forgotPassword.handler(
      this._sanitizeUser(user)
    )*/

    return {
      body: '',
      headers: {
        ...this._deleteSessionHeader,
      },
    }
  }

  async getToken(): Promise<AuthMethodReturn> {
    try {
      const user = await this._getCurrentUser()

      // need to return *something* for our existing Authorization header stuff
      // to work, so return the user's ID in case we can use it for something
      // in the future
      return { body: user.id.toString(), headers: {} }
    } catch (e) {
      if (e instanceof NotLoggedInError) {
        return this._logoutResponse()
      } else {
        return this._logoutResponse({ error: e.message })
      }
    }
  }

  async login(): Promise<AuthMethodReturn> {
    const { email, password } = this.params
    const dbUser = await this._verifyUser(email, password)
    if (dbUser == null || dbUser.id == null) {
      throw new NoUserIdError()
    }

    return this._loginResponse(dbUser.id)
  }

  logout() {
    return this._logoutResponse()
  }

  async resetPassword() {
    const { password, resetToken } = this.params

    this._validateField(resetToken, new ResetTokenRequiredError())
    this._validateField(password, new PasswordRequiredError())

    let user = await this._findUserByToken(resetToken as string)
    const [hashedPassword] = this._hashPassword(password, user.salt)

    if (
      !this.options.resetPassword.allowReusedPassword &&
      user.hashedPassword === hashedPassword
    ) {
      throw new ReusedPasswordError()
    }

    try {
      // if we got here then we can update the password in the database
      user = await db.user.update({
        where: {
          id: user.id,
        },
        data: {
          hashedPassword: hashedPassword,
          resetToken: null,
          resetTokenExpiresAt: null,
        },
      })
    } catch (e) {
      console.log(e)
      throw new GenericError()
    }

    // call the user-defined handler so they can decide what to do with this user
    /* const response = await this.options.resetPassword.handler(
      this._sanitizeUser(user)
    )*/

    // returning the user from the handler means to log them in automatically
    /* if (response) {
    } else {
      return this._logoutResponse({})
    }*/

    return this._loginResponse(user.id)
  }

  async signup(): Promise<AuthMethodReturn> {
    const userOrMessage = await this._createUser()

    // at this point `user` is either an actual user, in which case log the
    // user in automatically, or it's a string, which is a message to show
    // the user (something like "please verify your email")
    if (typeof userOrMessage === 'object') {
      const user = userOrMessage
      return this._loginResponse(user.id, 201)
    } else {
      const message = userOrMessage
      return {
        body: JSON.stringify({ message }),
        headers: {},
        options: { statusCode: 201 },
      }
    }
  }

  async validateResetToken(): Promise<AuthMethodReturn> {
    // is token present at all?

    this._validateField(this.params.resetToken, new ResetTokenRequiredError())

    const user = await this._findUserByToken(this.params.resetToken as string)

    return {
      body: JSON.stringify(this._sanitizeUser(user)),
      headers: {
        ...this._deleteSessionHeader,
      },
    }
  }

  // validates that we have all the ENV and options we need to login/signup
  _validateOptions() {
    // must have a SESSION_SECRET so we can encrypt/decrypt the cookie
    if (!process.env.SESSION_SECRET) {
      throw new NoSessionSecretError()
    }

    // must have an expiration time set for the session cookie
    if (!this.options?.login?.expires) {
      throw new NoSessionExpirationError()
    }
  }

  // removes sensative fields from user before sending over the wire
  _sanitizeUser(user: Record<string, unknown>) {
    const sanitized = JSON.parse(JSON.stringify(user))
    delete sanitized.hashedPassword
    delete sanitized.salt

    return sanitized
  }

  // parses the event body into JSON, whether it's base64 encoded or not
  _parseBody() {
    if (this.event.body) {
      if (this.event.isBase64Encoded) {
        return JSON.parse(
          Buffer.from(this.event.body || '', 'base64').toString('utf-8')
        )
      } else {
        return JSON.parse(this.event.body)
      }
    } else {
      return {}
    }
  }

  // returns all the cookie attributes in an array with the proper expiration date
  //
  // pass the argument `expires` set to "now" to get the attributes needed to expire
  // the session, or "future" (or left out completely) to set to `futureExpiresDate`
  _cookieAttributes({ expires = 'future' }: { expires?: 'now' | 'future' }) {
    const cookieOptions = this.options.cookie || {}
    const meta = Object.keys(cookieOptions)
      .map((key) => {
        const optionValue =
          cookieOptions[key as keyof AuthHandlerOptions['cookie']]

        // Convert the options to valid cookie string
        if (optionValue === true) {
          return key
        } else if (optionValue === false) {
          return null
        } else {
          return `${key}=${optionValue}`
        }
      })
      .filter((v) => v)

    const expiresAt =
      expires === 'now' ? AuthHandler.PAST_EXPIRES_DATE : this.futureExpiresDate
    meta.push(`Expires=${expiresAt}`)

    return meta
  }

  _encrypt(data: string) {
    return CryptoJS.AES.encrypt(data, process.env.SESSION_SECRET as string)
  }

  // returns the Set-Cookie header to be returned in the request (effectively creates the session)
  _createSessionHeader(
    data: SessionRecord,
    csrfToken: string
  ): Record<'Set-Cookie', string> {
    const session = JSON.stringify(data) + ';' + csrfToken
    const encrypted = this._encrypt(session)
    const cookie = [
      `session=${encrypted.toString()}`,
      ...this._cookieAttributes({ expires: 'future' }),
    ].join(';')

    return { 'Set-Cookie': cookie }
  }

  // checks the CSRF token in the header against the CSRF token in the session and
  // throw an error if they are not the same (not used yet)
  _validateCsrf() {
    if (this.sessionCsrfToken !== this.headerCsrfToken) {
      throw new CsrfTokenMismatchError()
    }
    return true
  }

  async _findUserByToken(token: string) {
    const tokenExpires = new Date()
    tokenExpires.setSeconds(
      tokenExpires.getSeconds() - this.options.forgotPassword.expires
    )

    const user = await db.user.findFirst({
      where: {
        resetToken: token,
      },
    })

    // user not found with the given token
    if (!user) {
      throw new ResetTokenInvalidError()
    }

    // token has expired
    if (user.resetTokenExpiresAt < tokenExpires) {
      await this._clearResetToken(user.id)
      throw new ResetTokenExpiredError()
    }

    return user
  }

  async _clearResetToken(userid: number) {
    try {
      await db.user.update({
        where: {
          id: userid,
        },
        data: {
          resetToken: null,
          resetTokenExpiresAt: null,
        },
      })
    } catch (e) {
      console.log(e)
      throw new GenericError()
    }
  }

  // verifies that a username and password are correct, and returns the user if so
  async _verifyUser(email: string | undefined, password: string | undefined) {
    // do we have all the query params we need to check the user?
    this._validateField(email, new EmailRequiredError())
    this._validateField(password, new PasswordRequiredError())

    try {
      // does user exist?
      const user = await db.user.findUnique({
        where: { email: email },
      })
      if (!user) {
        throw new UserNotFoundError()
      }

      // is password correct?
      const [hashedPassword, _salt] = this._hashPassword(password, user.salt)
      if (hashedPassword === user.hashedPassword) {
        return user
      } else {
        throw new IncorrectPasswordError()
      }
    } catch (e) {
      console.log(e)
      throw new GenericError()
    }
  }

  // gets the user from the database and returns only its ID
  async _getCurrentUser() {
    if (!this.session?.id) {
      throw new NotLoggedInError()
    }

    const user = await db.user.findUnique({
      where: { id: this.session?.id },
      select: { id: true },
    })

    if (!user) {
      throw new UserNotFoundError()
    }

    return user
  }

  // creates and returns a user, first checking that the username/password
  // values pass validation
  async _createUser() {
    const { email, password } = this.params
    if (
      this._validateField(email, new EmailRequiredError()) &&
      this._validateField(password, new PasswordRequiredError())
    ) {
      /*
      const user = await db.user.findUnique({
        where: { email: email },
      })
      if (user) {
        throw new DuplicateUsernameError(
          email,
          this.options.signup?.errors?.usernameTaken
        )
      }*/

      // if we get here everything is good, call the app's signup handler and let
      // them worry about scrubbing data and saving to the DB
      const [hashedPassword, salt] = this._hashPassword(password)
      try {
        const newUser = await db.user.create({
          data: {
            email,
            hashedPassword,
            salt,
          },
        })

        return newUser
      } catch (e) {
        if (e instanceof Prisma.PrismaClientKnownRequestError) {
          // The .code property can be accessed in a type-safe manner
          if (e.code === 'P2002') {
            throw new DuplicateEmailError()
          }
        }
        throw e
      }
    }
  }

  // hashes a password using either the given `salt` argument, or creates a new
  // salt and hashes using that. Either way, returns an array with [hash, salt]
  _hashPassword(text: string, salt?: string) {
    const useSalt = salt || CryptoJS.lib.WordArray.random(128 / 8).toString()

    return [
      CryptoJS.PBKDF2(text, useSalt, { keySize: 256 / 32 }).toString(),
      useSalt,
    ]
  }

  // figure out which auth method we're trying to call
  _getAuthMethod() {
    // try getting it from the query string, /.redwood/functions/auth?method=[methodName]
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    let methodName = this.event.queryStringParameters!.method as AuthMethodNames

    if (!AuthHandler.METHODS.includes(methodName) && this.params) {
      // try getting it from the body in JSON: { method: [methodName] }
      try {
        methodName = this.params.method
      } catch (e) {
        // there's no body, or it's not JSON, `handler` will return a 404
      }
    }

    return methodName
  }

  // checks that a single field meets validation requirements and
  // currently checks for presense only
  _validateField(value: unknown, error: Error): value is string {
    // check for presense
    if (!value || String(value).trim() === '') {
      throw error
    } else {
      return true
    }
  }

  _loginResponse(userid: number, statusCode = 200): AuthMethodReturn {
    const sessionData = { id: userid }

    // TODO: this needs to go into graphql somewhere so that each request makes
    // a new CSRF token and sets it in both the encrypted session and the
    // csrf-token header
    const csrfToken = AuthHandler.CSRF_TOKEN

    return {
      body: JSON.stringify(sessionData),
      headers: {
        'csrf-token': csrfToken,
        ...this._createSessionHeader(sessionData, csrfToken),
      },
      options: { statusCode },
    }
  }

  _logoutResponse(response?: Record<string, unknown>): AuthMethodReturn {
    return {
      body: response ? JSON.stringify(response) : '',
      headers: {
        ...this._deleteSessionHeader,
      },
    }
  }

  _ok(body: string, headers = {}, options = { statusCode: 200 }) {
    return {
      statusCode: options.statusCode,
      body: typeof body === 'string' ? body : JSON.stringify(body),
      headers: { 'Content-Type': 'application/json', ...headers },
    }
  }

  _notFound() {
    return {
      statusCode: 404,
    }
  }

  _badRequest(message: string) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: message }),
      headers: { 'Content-Type': 'application/json' },
    }
  }

  _buildResponseWithCorsHeaders(
    response: {
      body?: string
      statusCode: number
      headers?: Record<string, string>
    },
    corsHeaders: CorsHeaders
  ) {
    return {
      ...response,
      headers: {
        ...(response.headers || {}),
        ...corsHeaders,
      },
    }
  }
}
