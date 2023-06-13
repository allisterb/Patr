package node

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	logging "github.com/ipfs/go-log/v2"

	"github.com/allisterb/patr/ipfs"
	"github.com/allisterb/patr/util"
)

type Config struct {
	Pubkey  []byte
	PrivKey []byte
}

var log = logging.Logger("patr/node")

func LoadConfig() (Config, error) {
	f := filepath.Join(filepath.Join(util.GetUserHomeDir(), ".patr"), "node.json")
	if _, err := os.Stat(f); err != nil {
		log.Errorf("could not find node configuration file %s", f)
		return Config{}, err
	}
	c, err := os.ReadFile(f)
	if err != nil {
		log.Errorf("could not read data from node configuration file: %v", err)
		return Config{}, err
	}
	var config Config
	if json.Unmarshal(c, &config) != nil {
		log.Errorf("could not read JSON data from node configuration file: %v", err)
		return Config{}, err
	}
	return config, nil
}

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
