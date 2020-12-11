const nodemailer = require('nodemailer');

module.exports = async (options) => {
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const emailOptions = {
    from: 'Simple User System <forgotpassword@simpleusersystem.dev>',
    to: options.email,
    subject: options.subject,
    text: options.message,
    //html
  };

  await transporter.sendMail(emailOptions);
};
