package domain

type Username string

type User struct {
	username     Username
	password     string
	passwordHash string
}

func NewUser(username string, password string) *User {
	return &User{
		username:     Username(username),
		password:     password,
		passwordHash: "",
	}
}

// NewUserWithPasswordHash creates a user representation suitable for storage
// and authentication. It never contains the raw password.
func NewUserWithPasswordHash(username string, passwordHash string) *User {
	return &User{
		username:     Username(username),
		password:     "",
		passwordHash: passwordHash,
	}
}

func (u *User) Username() string {
	return string(u.username)
}

func (u *User) Password() string {
	return u.password
}

func (u *User) PasswordHash() string {
	return u.passwordHash
}
