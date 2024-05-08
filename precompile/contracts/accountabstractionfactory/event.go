package accountabstractionfactory

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

const (
	// AccountCreatedEventGasCost is the gas cost of the AccountCreated event.
	// It is the base gas cost + the gas cost of the topics (signature, sender, recipient)
	// and the gas cost of the non-indexed data (32 bytes for amount).
	AccountCreatedEventGasCost = 0
)

// PackAccountCreatedEvent packs the event into the appropriate arguments for AccountCreated.
// It returns topic hashes and the encoded non-indexed data.
func PackAccountCreatedEvent(account common.Address, owner common.Address, salt *big.Int) ([]common.Hash, []byte, error) {
	return AccountAbstractionFactoryABI.PackEvent("AccountCreated", account, owner, salt)
}
