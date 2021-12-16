const CustomError = require('../errors')

const checkPermissions = (userRequest, resourceUserId) => {
  // ONLY ADMIN CAN VIEW ANY USER BY THEIR ID AND ONLY LOGGED IN USER CAN VIEW INFORMATION RELATED TO THEMSELVES BY THEIR ID
  if (userRequest.role === 'admin') return
  if (userRequest.userID === resourceUserId.toString()) return

  throw new CustomError.UnauthenticatedError(
    'NOT AUTHORIZED TO ACCESS THIS ROUTE, CANNOT VIEW INFORMATION RELATED TO OTHER USERS...'
  )
}

module.exports = checkPermissions
