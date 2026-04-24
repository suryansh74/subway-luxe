package adapters

import (
	"context"
	"fmt"

	"gopkg.in/gomail.v2"
)

type EmailSender struct {
	smtpHost     string
	smtpPort     int
	smtpUsername string
	smtpPassword string
}

func NewEmailSender(host, port, username, password string) *EmailSender {
	return &EmailSender{
		smtpHost:     host,
		smtpPort:     587,
		smtpUsername: username,
		smtpPassword: password,
	}
}

func (e *EmailSender) SendEmailOTP(_ context.Context, to string, otp string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", e.smtpUsername)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Verify your email - Subway Luxe")

	html := "<!DOCTYPE html>" +
		"<html>" +
		"<head>" +
		"<style>" +
		"body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }" +
		".container { max-width: 500px; margin: 0 auto; padding: 20px; }" +
		".otp-box { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px; text-align: center; margin: 20px 0; }" +
		".otp-code { font-size: 32px; font-weight: bold; color: white; letter-spacing: 5px; }" +
		"</style>" +
		"</head>" +
		"<body>" +
		"<div class='container'>" +
		"<h2>Welcome to Subway Luxe!</h2>" +
		"<p>Your verification code is:</p>" +
		"<div class='otp-box'>" +
		"<span class='otp-code'>" + otp + "</span>" +
		"</div>" +
		"<p>This code expires in 15 minutes.</p>" +
		"<p>If you didn't request this, please ignore this email.</p>" +
		"</div>" +
		"</body>" +
		"</html>"

	m.SetBody("text/html", html)

	d := gomail.NewDialer(e.smtpHost, e.smtpPort, e.smtpUsername, e.smtpPassword)

	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	return nil
}
