package auth

// EncryptorInterface encryptor interface
type EncryptorInterface interface {
	Digest(password string) (string, error)
}
