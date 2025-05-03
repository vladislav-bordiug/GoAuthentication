package models

import "time"

type Request struct {
	GUID int `json:"guid" binding:"required" example:"1"`
}

type Response struct {
	AccessToken  string `json:"access_token" binding:"required" example:"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDYzOTY5ODEsImd1aWQiOjEsImlkIjo0LCJpcCI6IjE3Mi4xOC4wLjEiLCJ0eXBlIjoiYWNjZXNzIiwidWEiOiJNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvMTM1LjAuMC4wIFNhZmFyaS81MzcuMzYifQ.0xbb2C65uji1yPjQG4xz4eSGwd4J813F1vAkVBThzgJPRuuvR-mdClD9N2zljVPcFJ01XlB-q6AYBvXZui6Eqg"`
	RefreshToken string `json:"refresh_token" binding:"required" example:"2nNAhnaawM5P1z8vKMXk9jvkSuuqUjoMWWEV1w/TqnM="`
}

type TokenRecord struct {
	ID          int
	GUID        int
	IP          string
	UserAgent   string
	RefreshHash string
	Status      string
	CreatedAt   time.Time
}

type CurrentUserResponse struct {
	GUID int `json:"guid" binding:"required" example:"1"`
}

type IPChangeRequest struct {
	GUID     int       `json:"guid" binding:"required" example:"1"`
	FromIP   string    `json:"from_ip" binding:"required" example:"192.168.1.100"`
	NewIP    string    `json:"new_ip" binding:"required" example:"203.0.113.42"`
	DateTime time.Time `json:"datetime" binding:"required" example:"2025-05-03T14:25:00Z"`
}
