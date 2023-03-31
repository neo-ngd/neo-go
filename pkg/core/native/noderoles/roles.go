package noderoles

// Role represents type of participant.
type Role byte

// Role enumeration.
const (
	Validator      Role = 0
	StateValidator Role = 1
)

func IsValid(r Role) bool {
	return r == Validator || r == StateValidator
}
