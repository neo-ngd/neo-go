package nativenames

const (
	Management  = "ContractManagement"
	Ledger      = "LedgerContract"
	GAS         = "GASToken"
	Policy      = "PolicyContract"
	Designation = "RoleManagement"
)

// IsValid checks that name is a valid native contract's name.
func IsValid(name string) bool {
	return name == Management ||
		name == Ledger ||
		name == GAS ||
		name == Policy ||
		name == Designation
}
