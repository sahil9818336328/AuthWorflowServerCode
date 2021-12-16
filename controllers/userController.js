const User = require('../models/User')
const { StatusCodes } = require('http-status-codes')
const CustomError = require('../errors')
const {
  createUserToken,
  attachCookiesToResponse,
  checkPermissions,
} = require('../utils')

// GET ALL USERS WITH ROLE USER EXCLUDING PASSWORD
const getAllUsers = async (req, res) => {
  const users = await User.find({ role: 'user' }).select('-password')
  res.status(StatusCodes.OK).json({ users })
}

// GET SINGLE USER EXCLUDING PASSWORD
const getSingleUser = async (req, res) => {
  const user = await User.findOne({ _id: req.params.id }).select('-password')
  if (!user) {
    throw new CustomError.NotFoundError(
      `No user found with id : ${req.params.id}...`
    )
  }
  // ONLY ADMIN CAN VIEW USERS AND ONLY USER CAN VIEW INFORMATION RELATED TO THEMSELVES AND CANNOT VIEW OTHER USER'S
  checkPermissions(req.user, user._id)
  res.status(StatusCodes.OK).json({ user })
}

// SHOW CURRENT USER, USING DATA THAT WAS PREVIOUSLY ADDED TO THE REQUEST OBJECT
const showCurrentUser = async (req, res) => {
  res.status(StatusCodes.OK).json({ user: req.user })
}

// UPDATE USER , SECOND APPROACH USING SAVE METHOD
const updateUser = async (req, res) => {
  const { name, email } = req.body

  // CHECK FOR FALSE VALUES
  if (!name || !email) {
    throw new CustomError.BadRequestError('Please provide NAME and EMAIL...')
  }

  // FIND CURRENT USER WITH ID INSIDE REQ.USER OBJECT
  const user = await User.findOne({ _id: req.user.userID })

  // SET NEW VALUES TO EXISTING PROPERTIES
  user.name = name
  user.email = email

  // SAVE THE DOCUMENT
  await user.save() // WHEN USING SAVE METHOD PRE-HOOK GETS INVOKED
  const userPayload = createUserToken(user)
  attachCookiesToResponse({ res, user: userPayload })
  res.status(StatusCodes.OK).json({ user: userPayload })
}

// GENERATE NEW PASSWORD || FORGOT PASSWORD
const updateUserPassword = async (req, res) => {
  const { oldPassword, newPassword } = req.body

  // FOR GENERATING NEW PASSWORD BOTH OLD AND NEW VALUES FOR THE PASSWORD IS REQUIRED
  if (!oldPassword || !newPassword) {
    throw new CustomError.BadRequestError(
      'PLEASE PROVIDE BOTH VALUES FOR GENERATING NEW PASSWORD...'
    )
  }

  const user = await User.findOne({ _id: req.user.userID })

  // USER CANNOT CHANGE THE PASSWORD IF HE HASN'T REGISTERED
  if (!user) {
    throw new CustomError.UnauthenticatedError(
      'AUTHENTICATION INVALID, PLEASE REGISTER TO CONTINUE...'
    )
  }

  // SET NEW PASSWORD
  user.password = newPassword
  await user.save() // AN ALTERNATIVE TO TO UPDATE MONGOOSE METHOD

  res.status(StatusCodes.OK).json({ msg: 'PASSWORD UPDATED SUCCESSFULLY...' })
}

module.exports = {
  getAllUsers,
  getSingleUser,
  showCurrentUser,
  updateUser,
  updateUserPassword,
}

// FIRST APPROACH
// const updateUser = async (req, res) => {
//   const { name, email } = req.body

//   if (!name || !email) {
//     throw new CustomError.BadRequestError('Please provide NAME and EMAIL...')
//   }

//   const user = await User.findOneAndUpdate(
//     { _id: req.user.userID },
//     { name, email },
//     { new: true, runValidators: true }
//   )
//   const userPayload = createUserToken(user)
//   attachCookiesToResponse({ res, user: userPayload })
//   res.status(StatusCodes.OK).json({ user: userPayload })
// }
