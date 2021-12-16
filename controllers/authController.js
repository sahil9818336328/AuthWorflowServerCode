const User = require('../models/User')
const Token = require('../models/Token')
const { StatusCodes } = require('http-status-codes')
const CustomError = require('../errors')
const {
  attachCookiesToResponse,
  createUserToken,
  sendVerificationEmail,
  createHash,
} = require('../utils') // CUSTOM FUNCTION FOR GENERATING JWT
const crypto = require('crypto') // RANDOM STRING VALUES
const sendEmail = require('../utils/sendMail')
const sendResetPasswordEmail = require('../utils/sendResetPasswordEmail')

// REGISTER
const register = async (req, res) => {
  const { name, email, password } = req.body
  const isEmailInUse = await User.findOne({ email })

  // CHECK FOR EXISTING EMAIL
  if (isEmailInUse) {
    throw new CustomError.BadRequestError('Email already in-use...')
  }

  // MAKING THE ROLE OF FIRST USER AS ADMIN.
  const isFirstAccount = (await User.countDocuments({})) === 0
  const role = isFirstAccount ? 'admin' : 'user'

  // CREATE NEW USER
  const verificationToken = crypto.randomBytes(40).toString('hex') // VERIFICATION TOKEN
  const user = await User.create({
    name,
    email,
    password,
    role,
    verificationToken,
  })

  const origin = 'https://react-auth-workflow-node.netlify.app'

  // INVOKING THIS FUNCTION WHICH IN-TURNS INVOKE SEND_EMAIL FUNCTION WITH THE PASSED IN ARGUMENTS.
  await sendVerificationEmail({
    name: user.name,
    email: user.email,
    verificationToken: user.verificationToken,
    origin,
  })
  res.status(StatusCodes.CREATED).json({
    msg: 'Please check your e-mail to verify your account',
  })
}

// VERITY EMAIL
const verifyEmail = async (req, res) => {
  const { verificationToken, email } = req.body

  const user = await User.findOne({ email })
  if (!user) {
    throw new CustomError.UnauthenticatedError('Please register to continue...')
  }

  if (user.verificationToken !== verificationToken) {
    throw new CustomError.UnauthenticatedError('Token invalid...')
  }

  ;(user.isVerified = true), (user.verified = Date.now())
  user.verificationToken = ''

  await user.save()

  res.status(StatusCodes.OK).json({ msg: 'Email verified...' })
}

// LOGIN
const login = async (req, res) => {
  const { email, password } = req.body

  // CHECK FOR FALSY VALUES
  if (!email || !password) {
    throw new CustomError.BadRequestError(
      'Please provide proper credentials...'
    )
  }

  const user = await User.findOne({ email })

  // IF WE CANNOT FIND USER IN THE DATABASE
  if (!user) {
    throw new CustomError.UnauthenticatedError(
      'Please register to continue, invalid Credentials...'
    )
  }

  const isPasswordCorrect = await user.comparePassword(password)

  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials')
  }

  if (!user.isVerified) {
    throw new CustomError.UnauthenticatedError(
      'Please verify your account to continue...'
    )
  }

  // CONSTRUCTING PAYLOAD FOR GENERATING JWT
  const userPayload = createUserToken(user)

  let refreshToken = ''

  // CHECK FOR EXISTING TOKEN, DONT CREATE REFRESH TOKEN FROM SCRATCH
  const existingToken = await Token.findOne({ user: user._id })

  if (existingToken) {
    const { isValid } = existingToken
    if (!isValid) {
      throw new CustomError.UnauthenticatedError('Invalid credentials...')
    }
    refreshToken = existingToken.refreshToken
    attachCookiesToResponse({ res, user: userPayload, refreshToken })
    res.status(StatusCodes.OK).json({ user: userPayload })
    return
  }

  refreshToken = crypto.randomBytes(40).toString('hex')
  const userAgent = req.headers['user-agent']
  const ip = req.ip
  const userToken = { refreshToken, userAgent, ip, user: user._id }

  await Token.create(userToken)

  // A FUNCTION GENERATING JWT AND ATTACHING COOKIE WITH RESPONSE
  attachCookiesToResponse({ res, user: userPayload, refreshToken })

  res.status(StatusCodes.OK).json({ user: userPayload })
}

// LOGOUT
const logout = async (req, res) => {
  await Token.findOneAndDelete({ user: req.user.userID })

  // LOGGING OUT USER
  res.cookie('accessToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  })
  res.cookie('refreshToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  })

  res.status(StatusCodes.OK).json({ msg: 'User logged out successfully !' })
}

// FORGOT PASSWORD
const forgotPassword = async (req, res) => {
  const { email } = req.body

  if (!email) {
    throw new CustomError.BadRequestError('Please provide valid email')
  }
  const user = await User.findOne({ email })

  if (user) {
    const passwordToken = crypto.randomBytes(70).toString('hex')

    const origin = 'https://react-auth-workflow-node.netlify.app'
    await sendResetPasswordEmail({
      name: user.name,
      email: user.email,
      token: passwordToken,
      origin,
    })

    const tenMinutes = 1000 * 60 * 10
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes)

    user.passwordToken = createHash(passwordToken)
    user.passwordTokenExpirationDate = passwordTokenExpirationDate
    await user.save()
  }

  res
    .status(StatusCodes.OK)
    .json({ msg: 'Please check you email for reset password link...' })
}

// RESET PASSWORD
const resetPassword = async (req, res) => {
  const { token, email, password } = req.body
  if (!token || !email || !password) {
    throw new CustomError.BadRequestError('Please provide all values')
  }
  const user = await User.findOne({ email })
  console.log(user)

  if (user) {
    const currentDate = new Date()

    if (
      user.passwordToken === createHash(token) &&
      user.passwordTokenExpirationDate > currentDate
    ) {
      user.password = password
      user.passwordToken = null
      user.passwordTokenExpirationDate = null
      await user.save()
    }
  }
  res.send('password updated')
}

module.exports = {
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
}
