const nodemailer = require('nodemailer')
const nodemailerConfig = require('./nodemailerConfig')

const sendEmail = async ({ to, subject, html }) => {
  // Generate test SMTP service account from ethereal.email
  // Only needed if you don't have a real mail account for testing
  let testAccount = await nodemailer.createTestAccount()

  // create reusable transporter object using the default SMTP transport
  const transporter = nodemailer.createTransport(nodemailerConfig)

  // send mail with defined transport object
  return transporter.sendMail({
    from: '"Sahil Keshav 👻" <sahilkeshav@example.com>', // sender address
    to,
    subject,
    html,
  })
}

module.exports = sendEmail
