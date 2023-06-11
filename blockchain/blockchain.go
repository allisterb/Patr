package blockchain

import (
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	logging "github.com/ipfs/go-log/v2"
	ens "github.com/wealdtech/go-ens/v3"
)

var log = logging.Logger("patr/blockchain")

func foo() {
	client, err := ethclient.Dial("https://mainnet.infura.io/v3/SECRET")
	if err != nil {
		panic(err)
	}

	// Resolve a name to an address.
	domain := "ethereum.eth"
	address, err := ens.Resolve(client, domain)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Address of %s is %s\n", domain, address.Hex())
}
