const mongoose = require('mongoose')
const validator = require('validator') //EMAIL VALIDATOR
const bcrypt = require('bcryptjs') // HASHING PASSWORD FOR SECURITY

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name value is required...'],
    minlength: 3,
    maxlength: 15,
  },
  email: {
    type: String,
    required: [true, 'E-mail value is required...'],
    unique: true, // CHECKING FOR DUPLICATE EMAIL
    // CHECKING FOR VALID EMAIL
    validate: {
      validator: validator.isEmail,
      message: 'Please provide a valid email...',
    },
  },
  password: {
    type: String,
    required: [true, 'Password is required...'],
    minlength: 6,
  },
  role: {
    type: String,
    enum: ['admin', 'user'],
    default: 'user',
  },
  verificationToken: String,
  isVerified: {
    type: Boolean,
    default: false,
  },
  verified: Date,
  passwordToken: {
    type: String,
  },
  passwordTokenExpirationDate: {
    type: Date,
  },
})

// MONGOOSE PRE-SAVE HOOK
userSchema.pre('save', async function () {
  if (!this.isModified('password')) return // IF PASSWORD IS NOT MODIFIED SIMPLY RETURN, DONT HASH THE PASSWORD AGAIN
  // BEFORE SAVING THE DOCUMENT INTO THE DATABASE HASH THE PASSWORD
  const salt = await bcrypt.genSalt(10)
  this.password = await bcrypt.hash(this.password, salt) // PASSWORD FOR THE DOCUMENT THAT IS BEING CURRENTLY CREATED
})

// SCHEMA INSTANCE METHOD
userSchema.methods.comparePassword = async function (passFromReq) {
  // COMPARING PASSWORD WITH THAT IN THE DATABASE WHILE LOGGING IN
  const isMatch = await bcrypt.compare(passFromReq, this.password)
  return isMatch
}

module.exports = mongoose.model('User', userSchema)
