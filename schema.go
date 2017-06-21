package auth

// Schema auth schema
type Schema struct {
	Provider string
	UID      string

	Name      string
	Email     string
	FirstName string
	LastName  string
	Location  string
	Image     string
	Phone     string

	RawInfo interface{}
}
