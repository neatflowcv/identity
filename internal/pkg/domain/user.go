package domain

type Username string

type User struct {
	username Username
	password string
}

func NewUser(username string, password string) *User {
	return &User{
		username: Username(username),
		password: password,
	}
}

func (u *User) Username() string {
	return string(u.username)
}

func (u *User) Password() string {
	return u.password
}

func (u *User) EqualPassword(other *User) bool {
	return u.password == other.password
}
