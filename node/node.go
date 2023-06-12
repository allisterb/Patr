package node

import (
	"context"

	logging "github.com/ipfs/go-log/v2"

	"github.com/allisterb/patr/ipfs"
)

type Config struct {
	Pubkey  []byte
	PrivKey []byte
}

var log = logging.Logger("patr/node")

func Run(ctx context.Context, config Config) error {
	log.Info("starting patr node...")
	_, ipfsStop, err := ipfs.StartIPFSNode(ctx, config.PrivKey, config.Pubkey)
	if err != nil {
		log.Errorf("error starting IPFS node: %v", err)
		return err
	}
	ipfsStop()
	return nil
}
