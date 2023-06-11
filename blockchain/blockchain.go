package blockchain

import (
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	logging "github.com/ipfs/go-log/v2"
	ens "github.com/wealdtech/go-ens/v3"
)

var log = logging.Logger("patr/blockchain")

func ResolveENS(name string, apiSecret string) (string, error) {
	client, err := ethclient.Dial(fmt.Sprintf("https://mainnet.infura.io/v3/%s", apiSecret))
	if err != nil {
		panic(err)
	}

	// Resolve a name to an address.
	//address, err := ens.Resolve(client, name)
	namex, err := ens.NewName(client, name)
	//namex.Address(())

	return namex.Name, err
	//fmt.Printf("Address of %s is %s\n", name, address.)
}
