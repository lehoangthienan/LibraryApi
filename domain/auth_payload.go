package domain

// AuthPayload .
type AuthPayload struct {
	Token string `json:"token,omitempty"`
	User  *User  `json:"user,omitempty"`
}
