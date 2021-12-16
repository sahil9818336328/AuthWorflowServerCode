const sendEmail = require('./sendMail')

const sendResetPasswordEmail = ({ name, email, token, origin }) => {
  const resetPasswordUrl = `${origin}/user/reset-password?token=${token}&email=${email}`
  const message = `Please click on the following link to reset you password <a href=${resetPasswordUrl}>reset password</a>`
  return sendEmail({
    to: email,
    subject: 'Reset Password',
    html: `<h3>Hello ${name}</h3> ${message}`,
  })
}

module.exports = sendResetPasswordEmail
