import nodemailer from 'nodemailer';

interface EmailOptions {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

class EmailService {
  private transporter: nodemailer.Transporter | null = null;

  constructor() {
    this.initializeTransporter();
  }

  private initializeTransporter(): void {
    const emailService = process.env.EMAIL_SERVICE || 'gmail';
    const emailUser = "shahzaibzafar093@gmail.com";
    const emailPass = "zxjvtqrfhctqhwrd";

    if (!emailUser || !emailPass) {
      console.warn('⚠️ Email configuration missing. Set EMAIL_USER and EMAIL_PASS in .env file');
      return;
    }

    try {
      this.transporter = nodemailer.createTransport({
        service: emailService,
        auth: {
          user: emailUser,
          pass: emailPass
        }
      });
      console.log('✅ Email transporter initialized successfully');
    } catch (error) {
      console.error('❌ Failed to initialize email transporter:', error);
    }
  }

  async sendEmail(options: EmailOptions): Promise<void> {
    if (!this.transporter) {
      throw new Error('Email service not configured. Please check your .env file.');
    }

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: options.to,
      subject: options.subject,
      html: options.html,
      text: options.text
    };

    try {
      await this.transporter.sendMail(mailOptions);
      console.log(`✅ Email sent successfully to ${options.to}`);
    } catch (error) {
      console.error('❌ Email sending failed:', error);
      throw new Error('Failed to send email');
    }
  }

  async sendVerificationEmail(email: string, token: string, username: string): Promise<void> {
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
    
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Welcome to Ransfer!</h2>
        <p>Hi ${username},</p>
        <p>Thank you for signing up! Please verify your email address by clicking the button below:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${verificationUrl}" 
             style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Verify Email Address
          </a>
        </div>
        <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #666;">${verificationUrl}</p>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't create an account, you can safely ignore this email.</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          This email was sent from Ransfer. Please do not reply to this email.
        </p>
      </div>
    `;

    const text = `
      Welcome to Ransfer!
      
      Hi ${username},
      
      Thank you for signing up! Please verify your email address by visiting this link:
      ${verificationUrl}
      
      This link will expire in 24 hours.
      
      If you didn't create an account, you can safely ignore this email.
    `;

    await this.sendEmail({
      to: email,
      subject: 'Verify your email address - Ransfer',
      html,
      text
    });
  }

  async sendPasswordResetEmail(email: string, token: string, username: string): Promise<void> {
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Password Reset Request</h2>
        <p>Hi ${username},</p>
        <p>We received a request to reset your password. Click the button below to create a new password:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetUrl}" 
             style="background-color: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Reset Password
          </a>
        </div>
        <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #666;">${resetUrl}</p>
        <p>This link will expire in 10 minutes.</p>
        <p>If you didn't request a password reset, you can safely ignore this email.</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          This email was sent from Ransfer. Please do not reply to this email.
        </p>
      </div>
    `;

    const text = `
      Password Reset Request
      
      Hi ${username},
      
      We received a request to reset your password. Visit this link to create a new password:
      ${resetUrl}
      
      This link will expire in 10 minutes.
      
      If you didn't request a password reset, you can safely ignore this email.
    `;

    await this.sendEmail({
      to: email,
      subject: 'Reset your password - Ransfer',
      html,
      text
    });
  }

  async sendShareNotificationEmail(email: string, shareData: { shareId: string; ownerName: string; fileName: string; fileSize: string }): Promise<void> {
    const shareUrl = `${process.env.FRONTEND_URL}/share/${shareData.shareId}`;
    
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">File Shared with You</h2>
        <p>Hi there,</p>
        <p>${shareData.ownerName} has shared a file with you:</p>
        <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
          <h3 style="margin: 0 0 10px 0;">${shareData.fileName}</h3>
          <p style="margin: 0; color: #666;">Size: ${shareData.fileSize}</p>
        </div>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${shareUrl}" 
             style="background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
            View File
          </a>
        </div>
        <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #666;">${shareUrl}</p>
        <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
        <p style="color: #666; font-size: 12px;">
          This email was sent from Ransfer. Please do not reply to this email.
        </p>
      </div>
    `;

    const text = `
      File Shared with You
      
      Hi there,
      
      ${shareData.ownerName} has shared a file with you: ${shareData.fileName}
      
      View the file here: ${shareUrl}
    `;

    await this.sendEmail({
      to: email,
      subject: `${shareData.ownerName} shared a file with you - Ransfer`,
      html,
      text
    });
  }
}

export default new EmailService(); 