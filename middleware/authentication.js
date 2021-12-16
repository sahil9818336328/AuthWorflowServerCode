const CustomError = require('../errors')
const Token = require('../models/Token')
const { isTokenValid, attachCookiesToResponse } = require('../utils')

// AUTHENTICATING USERS
const authenticateUser = async (req, res, next) => {
  // NEXT - BASICALLY PASSES CONTROL TO THE NEXT MIDDLEWARE IN PIPELINE
  const { refreshToken, accessToken } = req.signedCookies

  // ACCESS TOKEN HAS SHORTER EXPIRATION
  try {
    if (accessToken) {
      const { user } = isTokenValid(accessToken)
      req.user = user
      return next()
    }

    // REFRESH TOKEN HAS LONGER EXPIRATION

    const payload = isTokenValid(refreshToken)

    const existingToken = await Token.findOne({
      user: payload.user.userID,
      verificationToken: payload.verificationToken,
    })
    if (!existingToken || !existingToken?.isValid) {
      throw new CustomError.UnauthenticatedError('Authentication invalid...')
    }

    attachCookiesToResponse({
      res,
      user: payload.user,
      refreshToken: existingToken.refreshToken,
    })
    req.user = payload.user
    next()
  } catch (error) {
    throw new CustomError.UnauthenticatedError('ACCESS TOKEN INVALID...')
  }
}

// ONLY ADMIN CAN SEE ALL USERS
const authorizePermissions = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      throw new CustomError.AuthorizedError(
        'NOT AUTHORIZED TO ACCESS THIS ROUTE...'
      )
    }
    next()
  }
}

module.exports = {
  authenticateUser,
  authorizePermissions,
}
