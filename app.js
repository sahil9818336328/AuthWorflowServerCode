// ACCESS TO ENVIRONMENT VARIABLES
require('dotenv').config()
require('express-async-errors') // AUTOMATICALLY PROVIDES TRY/CATCH TO ALL CONTROLLERS.

const express = require('express')
const app = express()

// PACKAGES
const morgan = require('morgan') //HTTP REQUEST LOGGER MIDDLEWARE, IN DEVELOPMENT MODE ONLY
const cookieParser = require('cookie-parser') // ACCESSING COOKIE ON REQUEST
const fileUpload = require('express-fileupload') // GIVES ACCESS TO THE UPLOADED IMAGE FILE/DATA

// CUSTOM MIDDLEWARE
const notFoundMiddleware = require('./middleware/not-found')
const errorHandlerMiddleware = require('./middleware/error-handler')
const { authenticateUser } = require('./middleware/authentication')

// SECURITY PACKAGES
const rateLimiter = require('express-rate-limit') // RATE LIMITING MIDDLEWARE FOR EXPRESS
const helmet = require('helmet') // HELPS SECURE EXPRESS APPS BY SETTING VARIOUS HTTP HEADERS
const cors = require('cors') // ENABLES CROSS ORIGIN RESOURCE SHARING
const xxs = require('xss-clean') // SANITIZES USER INPUT COMING FROM REQ.BODY , REQ.PARAMS
const mongoSanitize = require('express-mongo-sanitize') // SANITIZES USER SUPPLIED DATA TO PREVENT MONGODB OPERATOR($) INJECTION

// ROUTERS
const authRouter = require('./routes/authRoutes')
const userRouter = require('./routes/userRoutes')

// DATABASE CONNECTION FUNCTION
const connectDB = require('./db/connect')

// FOR ACCESSING DATA IN REQ.BODY
app.use(express.json())

app.use(cookieParser(process.env.JWT_SECRET)) // SIGNED COOKIE
app.use(fileUpload())

app.use(express.static('./public'))
// APP.USER ROUTES
app.use('/api/v1/auth', authRouter)
app.use('/api/v1/users', authenticateUser, userRouter) // ATTACHING MIDDLEWARE

// INVOKING SECURITY PACKAGES
app.set('trust proxy', 1)
app.use(
  rateLimiter({
    windowMs: 15 * 60 * 1000,
    max: 60,
  })
)
app.use(helmet())
app.use(cors())
app.use(xxs())
app.use(mongoSanitize())

app.use(notFoundMiddleware)
app.use(errorHandlerMiddleware)

const port = process.env.PORT || 5000

const start = async () => {
  try {
    await connectDB(process.env.MONGO_URI)
    app.listen(port, () => console.log(`Server listening on port ${port}...`))
  } catch (error) {
    console.log(error)
  }
}

start()
