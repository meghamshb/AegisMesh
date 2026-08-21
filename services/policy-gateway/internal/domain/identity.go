package domain

import "time"

type Organization struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type User struct {
	ID              string    `json:"id"`
	OrgID           string    `json:"org_id"`
	DisplayName     string    `json:"display_name"`
	Email           *string   `json:"email,omitempty"`
	Role            string    `json:"role"`
	Status          string    `json:"status"`
	ExternalSubject *string   `json:"external_subject,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type Agent struct {
	ID               string     `json:"id"`
	OrgID            string     `json:"org_id"`
	OwnerUserID      string     `json:"owner_user_id"`
	OwnerDisplayName string     `json:"owner_display_name,omitempty"`
	Name             string     `json:"name"`
	ContainerID      *string    `json:"container_id,omitempty"`
	Status           string     `json:"status"`
	LastSeenAt       *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	MetadataJSON     []byte     `json:"-"`
	Metadata         map[string]any `json:"metadata"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}
