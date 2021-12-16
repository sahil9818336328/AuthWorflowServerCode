const sendEmail = require('./sendMail')

const sendVerificationEmail = async ({
  name,
  email,
  verificationToken,
  origin,
}) => {
  const verifyEmailUrl = `${origin}/user/verify-email?token=${verificationToken}&email=${email}`
  const message = `<p>Please confirm your e-mail by clicking on the following link <a href="${verifyEmailUrl}">Verify Email</a></p>`

  return sendEmail({
    to: email,
    subject: 'E-mail Confirmation',
    html: `<h4>Hello ${name}</h4> ${message} `,
  })
}

module.exports = sendVerificationEmail
