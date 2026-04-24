package adapters

import (
	"context"
	"sync"
)

type MockEmailSender struct {
	mu       sync.Mutex
	SentOTPs map[string]string
}

func NewMockEmailSender() *MockEmailSender {
	return &MockEmailSender{
		SentOTPs: make(map[string]string),
	}
}

func (m *MockEmailSender) SendEmailOTP(_ context.Context, to string, otp string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SentOTPs[to] = otp
	return nil
}

type MockPhoneSender struct {
	mu       sync.Mutex
	SentOTPs map[string]string
}

func NewMockPhoneSender() *MockPhoneSender {
	return &MockPhoneSender{
		SentOTPs: make(map[string]string),
	}
}

func (m *MockPhoneSender) SendPhoneOTP(_ context.Context, to string, otp string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SentOTPs[to] = otp
	return nil
}
