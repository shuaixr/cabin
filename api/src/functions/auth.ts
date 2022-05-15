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
      },
      login: {
        // How long a user will remain logged in, in seconds
        expires: 60 * 60 * 24 * 365 * 10,
      },
      resetPassword: {
        // If `false` then the new password MUST be different than the current one
        allowReusedPassword: true,
      },
    })

    return await authHandler.invoke()
  }
)
