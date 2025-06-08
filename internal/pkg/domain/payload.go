package domain

type Payload struct {
	username string
}

func NewPayload(username string) *Payload {
	return &Payload{
		username: username,
	}
}

func (p *Payload) Username() string {
	return p.username
}
