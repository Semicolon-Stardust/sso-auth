// src/services/emailService.js
import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

const transporter = nodemailer.createTransport({
	host: process.env.SMTP_HOST, // e.g. "smtp.gmail.com"
	port: Number(process.env.SMTP_PORT), // e.g. 587
	secure: false, // false for port 587; true for port 465
	auth: {
		user: process.env.SMTP_USER,
		pass: process.env.SMTP_PASS,
	},
});

// =======================
// Verification Emails
// =======================

export const sendUserVerificationEmail = async (to, token) => {
	const verificationLink = `http://dayadevraha.com/api/v${process.env.API_VERSION}/user/verify-email?token=${token}`;
	const mailOptions = {
		from: `"No Reply" <${process.env.SMTP_USER}>`,
		to,
		subject: "Verify Your Email Address - Dayadevraha",
		text: `Please verify your email by clicking the following link: ${verificationLink}`,
		html: `<html>
  <head>
    <style type="text/css">
      .email-container { width: 100%; background: #f5f5f5; padding: 20px; font-family: Arial, sans-serif; }
      .email-content { max-width: 600px; margin: 0 auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
      .header { background: #007BFF; padding: 15px; text-align: center; color: #ffffff; border-top-left-radius: 8px; border-top-right-radius: 8px; }
      .body-text { color: #333333; line-height: 1.5; }
      .button { display: inline-block; margin-top: 20px; padding: 12px 20px; background: #28a745; color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold; }
      .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #999999; }
    </style>
  </head>
  <body>
    <div class="email-container">
      <div class="email-content">
        <div class="header">
          <h2>Verify Your Email</h2>
        </div>
        <div class="body-text">
          <p>Hello,</p>
          <p>Thank you for registering with Dayadevraha! Please verify your email address by clicking the button below:</p>
          <p style="text-align:center;"><a href="${verificationLink}" class="button">Verify Email</a></p>
          <p>If the button doesn’t work, copy and paste the following link into your browser: ${verificationLink}</p>
          <p>If you did not sign up, please ignore this email.</p>
        </div>
        <div class="footer">
          <p>&copy; 2025 Dayadevraha. All rights reserved.</p>
        </div>
      </div>
    </div>
  </body>
</html>`,
	};
	return transporter.sendMail(mailOptions);
};

export const sendAdminVerificationEmail = async (to, token) => {
	const verificationLink = `http://dayadevraha.com/api/v${process.env.API_VERSION}/admin/verify-email?token=${token}`;
	const mailOptions = {
		from: `"No Reply" <${process.env.SMTP_USER}>`,
		to,
		subject: "Verify Your Admin Email Address - Dayadevraha",
		text: `Please verify your admin email by clicking the following link: ${verificationLink}`,
		html: `<html>
  <head>
    <style type="text/css">
      .email-container { width: 100%; background: #f5f5f5; padding: 20px; font-family: Arial, sans-serif; }
      .email-content { max-width: 600px; margin: 0 auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
      .header { background: #007BFF; padding: 15px; text-align: center; color: #ffffff; border-top-left-radius: 8px; border-top-right-radius: 8px; }
      .body-text { color: #333333; line-height: 1.5; }
      .button { display: inline-block; margin-top: 20px; padding: 12px 20px; background: #28a745; color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold; }
      .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #999999; }
    </style>
  </head>
  <body>
    <div class="email-container">
      <div class="email-content">
        <div class="header">
          <h2>Verify Your Admin Email</h2>
        </div>
        <div class="body-text">
          <p>Hello,</p>
          <p>Thank you for registering as an admin at Dayadevraha! Please verify your admin email address by clicking the button below:</p>
          <p style="text-align:center;"><a href="${verificationLink}" class="button">Verify Admin Email</a></p>
          <p>If the button doesn’t work, copy and paste the following link into your browser: ${verificationLink}</p>
          <p>If you did not sign up, please ignore this email.</p>
        </div>
        <div class="footer">
          <p>&copy; 2025 Dayadevraha. All rights reserved.</p>
        </div>
      </div>
    </div>
  </body>
</html>`,
	};
	return transporter.sendMail(mailOptions);
};

// =======================
// Reset Password Emails
// =======================

export const sendUserResetPasswordEmail = async (to, token) => {
	const resetLink = `http://dayadevraha.com/api/v${process.env.API_VERSION}/user/reset-password?token=${token}`;
	const mailOptions = {
		from: `"No Reply" <${process.env.SMTP_USER}>`,
		to,
		subject: "Reset Your Password - Dayadevraha",
		text: `You requested a password reset. Click the following link to reset your password: ${resetLink}`,
		html: `<html>
  <head>
    <style type="text/css">
      .email-container { width: 100%; background: #f5f5f5; padding: 20px; font-family: Arial, sans-serif; }
      .email-content { max-width: 600px; margin: 0 auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
      .header { background: #dc3545; padding: 15px; text-align: center; color: #ffffff; border-top-left-radius: 8px; border-top-right-radius: 8px; }
      .body-text { color: #333333; line-height: 1.5; }
      .button { display: inline-block; margin-top: 20px; padding: 12px 20px; background: #28a745; color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold; }
      .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #999999; }
    </style>
  </head>
  <body>
    <div class="email-container">
      <div class="email-content">
        <div class="header">
          <h2>Reset Your Password</h2>
        </div>
        <div class="body-text">
          <p>Hello,</p>
          <p>You requested a password reset for your Dayadevraha account. Click the button below to reset your password:</p>
          <p style="text-align:center;"><a href="${resetLink}" class="button">Reset Password</a></p>
          <p>If the button doesn’t work, please copy and paste the following link into your browser: ${resetLink}</p>
          <p>If you did not request a password reset, please ignore this email.</p>
        </div>
        <div class="footer">
          <p>&copy; 2025 Dayadevraha. All rights reserved.</p>
        </div>
      </div>
    </div>
  </body>
</html>`,
	};
	return transporter.sendMail(mailOptions);
};

export const sendAdminResetPasswordEmail = async (to, token) => {
	const resetLink = `http://dayadevraha.com/api/v${process.env.API_VERSION}/admin/reset-password?token=${token}`;
	const mailOptions = {
		from: `"No Reply" <${process.env.SMTP_USER}>`,
		to,
		subject: "Reset Your Admin Password - Dayadevraha",
		text: `You requested a password reset for your Dayadevraha admin account. Click the following link to reset your password: ${resetLink}`,
		html: `<html>
  <head>
    <style type="text/css">
      .email-container { width: 100%; background: #f5f5f5; padding: 20px; font-family: Arial, sans-serif; }
      .email-content { max-width: 600px; margin: 0 auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
      .header { background: #dc3545; padding: 15px; text-align: center; color: #ffffff; border-top-left-radius: 8px; border-top-right-radius: 8px; }
      .body-text { color: #333333; line-height: 1.5; }
      .button { display: inline-block; margin-top: 20px; padding: 12px 20px; background: #28a745; color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold; }
      .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #999999; }
    </style>
  </head>
  <body>
    <div class="email-container">
      <div class="email-content">
        <div class="header">
          <h2>Reset Your Admin Password</h2>
        </div>
        <div class="body-text">
          <p>Hello,</p>
          <p>You requested a password reset for your Dayadevraha admin account. Click the button below to reset your password:</p>
          <p style="text-align:center;"><a href="${resetLink}" class="button">Reset Admin Password</a></p>
          <p>If the button doesn’t work, please copy and paste the following link into your browser: ${resetLink}</p>
          <p>If you did not request a password reset, please ignore this email.</p>
        </div>
        <div class="footer">
          <p>&copy; 2025 Dayadevraha. All rights reserved.</p>
        </div>
      </div>
    </div>
  </body>
</html>`,
	};
	return transporter.sendMail(mailOptions);
};

// =======================
// Two-Factor Authentication Emails
// =======================

export const sendUserTwoFactorOTPEmail = async (to, otp) => {
	const mailOptions = {
		from: `"No Reply" <${process.env.SMTP_USER}>`,
		to,
		subject: "Your Two-Factor Authentication Code - Dayadevraha",
		text: `Your OTP code is: ${otp}`,
		html: `<html>
  <head>
    <style type="text/css">
      .email-container { width: 100%; background: #f5f5f5; padding: 20px; font-family: Arial, sans-serif; }
      .email-content { max-width: 600px; margin: 0 auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
      .header { background: #6f42c1; padding: 15px; text-align: center; color: #ffffff; border-top-left-radius: 8px; border-top-right-radius: 8px; }
      .body-text { color: #333333; line-height: 1.5; text-align: center; }
      .otp-code { font-size: 24px; font-weight: bold; color: #dc3545; margin: 20px 0; }
      .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #999999; }
    </style>
  </head>
  <body>
    <div class="email-container">
      <div class="email-content">
        <div class="header">
          <h2>Your OTP Code</h2>
        </div>
        <div class="body-text">
          <p>Hello,</p>
          <p>Your one-time password (OTP) for two-factor authentication is:</p>
          <p class="otp-code">${otp}</p>
          <p>This code is valid for 5 minutes.</p>
        </div>
        <div class="footer">
          <p>&copy; 2025 Dayadevraha. All rights reserved.</p>
        </div>
      </div>
    </div>
  </body>
</html>`,
	};
	return transporter.sendMail(mailOptions);
};

export const sendAdminTwoFactorOTPEmail = async (to, otp) => {
	const mailOptions = {
		from: `"No Reply" <${process.env.SMTP_USER}>`,
		to,
		subject: "Your Admin Two-Factor Authentication Code - Dayadevraha",
		text: `Your OTP code is: ${otp}`,
		html: `<html>
  <head>
    <style type="text/css">
      .email-container { width: 100%; background: #f5f5f5; padding: 20px; font-family: Arial, sans-serif; }
      .email-content { max-width: 600px; margin: 0 auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
      .header { background: #6f42c1; padding: 15px; text-align: center; color: #ffffff; border-top-left-radius: 8px; border-top-right-radius: 8px; }
      .body-text { color: #333333; line-height: 1.5; text-align: center; }
      .otp-code { font-size: 24px; font-weight: bold; color: #dc3545; margin: 20px 0; }
      .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #999999; }
    </style>
  </head>
  <body>
    <div class="email-container">
      <div class="email-content">
        <div class="header">
          <h2>Your Admin OTP Code</h2>
        </div>
        <div class="body-text">
          <p>Hello,</p>
          <p>Your admin one-time password (OTP) for two-factor authentication is:</p>
          <p class="otp-code">${otp}</p>
          <p>This code is valid for 5 minutes.</p>
        </div>
        <div class="footer">
          <p>&copy; 2025 Dayadevraha. All rights reserved.</p>
        </div>
      </div>
    </div>
  </body>
</html>`,
	};
	return transporter.sendMail(mailOptions);
};
