const { createJWT, isTokenValid, attachCookiesToResponse } = require('./jwt')
const { createUserToken } = require('./createUserToken')
const checkPermissions = require('./checkPermissions')
const sendVerificationEmail = require('./sendVerificationEmail')
const sendResetPasswordEmail = require('./sendResetPasswordEmail')
const createHash = require('./createHash')

module.exports = {
  createJWT,
  isTokenValid,
  attachCookiesToResponse,
  createUserToken,
  checkPermissions,
  sendVerificationEmail,
  sendResetPasswordEmail,
  createHash,
}
