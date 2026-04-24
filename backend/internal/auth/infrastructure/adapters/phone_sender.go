package adapters

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type PhoneSender struct {
	accountSid          string
	authToken           string
	messagingServiceSid string
}

func NewPhoneSender(accountSid, authToken, messagingServiceSid string) *PhoneSender {
	return &PhoneSender{
		accountSid:          accountSid,
		authToken:           authToken,
		messagingServiceSid: messagingServiceSid,
	}
}

func (p *PhoneSender) SendPhoneOTP(_ context.Context, to string, otp string) error {
	msg := fmt.Sprintf("Your Subway Luxe verification code is: %s. This code expires in 15 minutes.", otp)
	return p.sendSMS(to, msg)
}

func (p *PhoneSender) sendSMS(to, message string) error {
	data := url.Values{}
	data.Set("To", to)
	data.Set("MessagingServiceSid", p.messagingServiceSid)
	data.Set("Body", message)

	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", p.accountSid)
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	auth := p.accountSid + ":" + p.authToken
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
	req.Header.Set("Authorization", "Basic "+encodedAuth)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send SMS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("twilio API error: status %d", resp.StatusCode)
	}
	return nil
}
