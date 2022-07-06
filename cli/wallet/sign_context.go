package wallet

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/neo-ngd/neo-go/cli/input"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/neo-ngd/neo-go/pkg/core/transaction"
	"github.com/neo-ngd/neo-go/pkg/crypto"
	"github.com/neo-ngd/neo-go/pkg/crypto/hash"
	"github.com/neo-ngd/neo-go/pkg/crypto/keys"
	"github.com/neo-ngd/neo-go/pkg/wallet"
)

type SignContext struct {
	ChainID    uint64
	Tx         transaction.NeoTx
	Sigs       [][]byte
	PublicKeys keys.PublicKeys
	M          int
}

func (sc *SignContext) Check() error {
	if sc.Tx.From != hash.Hash160(sc.Tx.Witness.VerificationScript) {
		return errors.New("invalid verification")
	}
	pks, m, err := crypto.ParseMultiVerificationScript(sc.Tx.Witness.VerificationScript)
	if err != nil {
		return err
	}
	sc.PublicKeys = *pks
	if len(sc.Sigs) != len(sc.PublicKeys) {
		return errors.New("invalid sigs count")
	}
	sc.M = m
	for i, sig := range sc.Sigs {
		if len(sig) > 0 {
			if !sc.PublicKeys[i].VerifyHashable(sig, sc.ChainID, &sc.Tx) {
				return errors.New("invalid signature")
			}
		}
	}
	return nil
}

func (sc *SignContext) AddSig(pk *keys.PublicKey, sig []byte) error {
	if !pk.VerifyHashable(sig, sc.ChainID, &sc.Tx) {
		return errors.New("invalid signature")
	}
	for i, p := range sc.PublicKeys {
		if p.Address() == pk.Address() {
			sc.Sigs[i] = sig
		}
	}
	return nil
}

func (sc SignContext) IsComplete() bool {
	sigCount := 0
	for _, sig := range sc.Sigs {
		if len(sig) > 0 {
			sigCount++
		}
	}
	return sc.M == sigCount
}

func (sc *SignContext) CreateTx() *transaction.Transaction {
	if !sc.IsComplete() {
		return nil
	}
	sigs := make([][]byte, sc.M)
	for i, j := 0, 0; i < sc.M && j < len(sc.Sigs); j++ {
		if len(sc.Sigs[j]) > 0 {
			sigs[i] = sc.Sigs[j]
			i++
		}
	}
	sc.Tx.Witness.InvocationScript = crypto.CreateMultiInvocationScript(sigs)
	return transaction.NewTx(&sc.Tx)
}

type signContextJson struct {
	ChainID hexutil.Uint64    `json:"chainId"`
	Tx      transaction.NeoTx `json:"tx"`
	Sigs    []hexutil.Bytes   `json:"signatures"`
}

func (sc SignContext) MarshalJSON() ([]byte, error) {
	scj := &signContextJson{
		ChainID: hexutil.Uint64(sc.ChainID),
		Tx:      sc.Tx,
	}
	scj.Sigs = make([]hexutil.Bytes, len(sc.Sigs))
	for i, sig := range sc.Sigs {
		scj.Sigs[i] = sig
	}
	return json.Marshal(scj)
}

func (sc *SignContext) UnmarshalJSON(b []byte) error {
	scj := new(signContextJson)
	err := json.Unmarshal(b, scj)
	if err != nil {
		return err
	}
	sc.ChainID = uint64(scj.ChainID)
	sc.Tx = scj.Tx
	sc.Sigs = make([][]byte, len(scj.Sigs))
	for i, sig := range scj.Sigs {
		sc.Sigs[i] = sig
	}
	err = sc.Check()
	if err != nil {
		return err
	}
	return nil
}

func Sign(wall *wallet.Wallet, context *SignContext) error {
	for _, acc := range wall.Accounts {
		for i, p := range context.PublicKeys {
			if p.Address() == acc.Address {
				pass, err := input.ReadPassword(fmt.Sprintf("Enter password for %s > ", acc.Address))
				if err != nil {
					return fmt.Errorf("error reading password: %w", err)
				}
				err = acc.Decrypt(pass, wall.Scrypt)
				if err != nil {
					return fmt.Errorf("unable to decrypt account: %s", acc.Address)
				}
				sig := acc.PrivateKey().SignHashable(context.ChainID, &context.Tx)
				context.Sigs[i] = sig
			}
		}
	}
	return nil
}
