package node

import (
	logging "github.com/ipfs/go-log/v2"
)

type Config struct {
	Pubkey  []byte
	PrivKey []byte
}

var log = logging.Logger("patr/node")
