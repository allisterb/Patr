package node

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	logging "github.com/ipfs/go-log/v2"

	"github.com/allisterb/patr/ipfs"
	"github.com/allisterb/patr/util"
)

type Config struct {
	Did             string
	NostrPrivKey    []byte
	NostrPubKey     []byte
	IPFSPubKey      []byte
	IPFSPrivKey     []byte
	InfuraSecretKey string
	W3SSecretKey    string
	IPNSKeys        map[byte]byte
}

var log = logging.Logger("patr/node")

var CurrentConfig = Config{}
var CurrentConfigInitialized = false

func PanicIfNotInitialized() {
	if !CurrentConfigInitialized {
		panic("node configuration is not initialized")
	}
}
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
	if err = json.Unmarshal(c, &config); err != nil {
		log.Errorf("could not read JSON data from node configuration file: %v", err)
		return Config{}, err
	}
	if config.NostrPrivKey == nil || config.NostrPubKey == nil {
		log.Errorf("Nostr private or public key not set in configuration file")
		return Config{}, fmt.Errorf("NOSTR PRIVATE OR PUBLIC KEY NOT SET IN CONFIGURATION FILE")
	}
	if config.IPFSPrivKey == nil || config.IPFSPubKey == nil {
		log.Errorf("IPFS node private or public key not set in configuration file")
		return Config{}, fmt.Errorf("IPFS NODE PRIVATE OR PUBLIC KEY NOT SET IN CONFIGURATION FILE")
	}
	if config.InfuraSecretKey == "" {
		log.Warnf("Infura API secret key not set in configuration file")
		return Config{}, fmt.Errorf("INFURA API SECRET KEY NOT SET IN CONFIGURATION FILE")
	}
	if config.W3SSecretKey == "" {
		log.Warnf("Web3.Storage API secret key not set in configuration file")
		return Config{}, fmt.Errorf("WEB3.STORAGE API SECRET KEY NOT SET IN CONFIGURATION FILE")
	}
	CurrentConfig = config
	CurrentConfigInitialized = true
	return config, nil
}

func Run(ctx context.Context) error {
	PanicIfNotInitialized()
	log.Info("starting patr node...")
	_, ipfsStop, err := ipfs.StartIPFSNode(ctx, CurrentConfig.IPFSPrivKey, CurrentConfig.IPFSPubKey)
	if err != nil {
		log.Errorf("error starting IPFS node: %v", err)
		return err
	}
	ipfsStop()
	return nil
}
