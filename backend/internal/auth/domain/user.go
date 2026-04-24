package domain

import "time"

type Role string

const (
	Admin          Role = "admin"
	Customer       Role = "customer"
	Seller         Role = "seller"
	DeliveryPerson Role = "delivery_person"
)

type User struct {
	ID               string    `json:"id"`
	Name             string    `json:"name" validate:"max=50,required"`
	ImagePath        string    `json:"image_path"`
	Email            string    `json:"email" validate:"email,unique,max=50,required"`
	Password         string    `json:"password" validate:"required,min=6,max=50,password"`
	Phone            string    `json:"phone" validate:"len=10,number"`
	PhoneCountryCode string    `json:"phone_country_code"`
	Role             Role      `json:"role"`
	Address          string    `json:"address"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	IsEmailVerified  bool      `json:"is_email_verified"`
	IsPhoneVerified  bool      `json:"is_phone_verified"`
}
