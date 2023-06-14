package blockchain

import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	logging "github.com/ipfs/go-log/v2"
	ens "github.com/wealdtech/go-ens/v3"
)

type ENSName struct {
	Address     string
	ContentHash string
	Avatar      string
	Pubkey      string
}

var log = logging.Logger("patr/blockchain")

func ResolveENS(name string, apikey string) (ENSName, error) {
	log.Infof("Resolving ENS name %v...", name)
	client, err := ethclient.Dial(fmt.Sprintf("https://mainnet.infura.io/v3/%s", apikey))
	if err != nil {
		log.Errorf("Could not create Infura Ethereum API client: %v", err)
		return ENSName{}, err
	}
	r, err := ens.NewResolver(client, name)
	if err != nil {
		log.Errorf("Could not create resolver ENS name %s: %v", name, err)
		return ENSName{}, err
	}
	address, err := r.Address()
	if err != nil {
		log.Errorf("Could not resolve address for ENS name %s: %v", name, err)
		return ENSName{}, err
	}
	chash, err := r.Contenthash()
	if err != nil {
		log.Errorf("Could not resolve content hash record for ENS name %s: %v", name, err)
		return ENSName{}, err
	}
	avatar, err := r.Text("avatar")
	if err != nil {
		log.Warnf("Could not resolve avatar text record for ENS name %s: %v", name, err)
	}
	pk1, _, err := r.PubKey()
	if err != nil {
		log.Errorf("Could not resolve public key for ENS name %s: %v", name, err)
		return ENSName{}, err
	}

	log.Infof("Resolved ENS name %v", name)

	record := ENSName{
		Address:     address.Hex(),
		ContentHash: string(chash),
		Avatar:      avatar,
		Pubkey:      hex.EncodeToString(pk1[:]),
	}

	return record, err
}
