import { APIGatewayProxyHandlerV2 } from 'aws-lambda'
import { AuthHandler } from 'src/lib/authHandler'
import { useMidleware } from 'src/lib/middleware'
export const handler: APIGatewayProxyHandlerV2 = useMidleware(
  async (event, context) => {
    const authHandler = new AuthHandler(event, context, {
      // Specifies attributes on the cookie that dbAuth sets in order to remember
      // who is logged in. See https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies
      cookie: {
        HttpOnly: true,
        Path: '/',
        SameSite: 'Strict',
        Secure: process.env.NODE_ENV !== 'development' ? true : false,

        // If you need to allow other domains (besides the api side) access to
        // the dbAuth session cookie:
        // Domain: 'example.com',
      },

      forgotPassword: {
        // How long the resetToken is valid for, in seconds (default is 24 hours)
        expires: 60 * 60 * 24,

        errors: {
          // for security reasons you may want to be vague here rather than expose
          // the fact that the email address wasn't found (prevents fishing for
          // valid email addresses)
          usernameNotFound: 'Username not found',
          // if the user somehow gets around client validation
          usernameRequired: 'Username is required',
        },
      },
      login: {
        errors: {
          usernameOrPasswordMissing: 'Both username and password are required',
          usernameNotFound: 'Username ${username} not found',
          // For security reasons you may want to make this the same as the
          // usernameNotFound error so that a malicious user can't use the error
          // to narrow down if it's the username or password that's incorrect
          incorrectPassword: 'Incorrect password for ${username}',
        },

        // How long a user will remain logged in, in seconds
        expires: 60 * 60 * 24 * 365 * 10,
      },
      resetPassword: {
        // If `false` then the new password MUST be different than the current one
        allowReusedPassword: true,

        errors: {
          // the resetToken is valid, but expired
          resetTokenExpired: 'resetToken is expired',
          // no user was found with the given resetToken
          resetTokenInvalid: 'resetToken is invalid',
          // the resetToken was not present in the URL
          resetTokenRequired: 'resetToken is required',
          // new password is the same as the old password (apparently they did not forget it)
          reusedPassword: 'Must choose a new password',
        },
      },
      signup: {
        errors: {
          // `field` will be either "username" or "password"
          fieldMissing: '${field} is required',
          usernameTaken: 'Username `${username}` already in use',
        },
      },
    })

    return await authHandler.invoke()
  }
)
