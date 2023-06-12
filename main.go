package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kong"
	logging "github.com/ipfs/go-log/v2"
	"github.com/mbndr/figlet4go"
	"github.com/multiformats/go-multibase"

	"github.com/allisterb/patr/blockchain"
	"github.com/allisterb/patr/did"
	"github.com/allisterb/patr/feed"
	"github.com/allisterb/patr/ipfs"
	"github.com/allisterb/patr/node"
	"github.com/allisterb/patr/nostr"
	"github.com/allisterb/patr/util"
)

type DidCmd struct {
	Cmd       string `arg:"" name:"cmd" help:"The command to run. Can be one of: resolve, profile."`
	Name      string `arg:"" name:"name" help:"Get the DID linked to this name."`
	ApiSecret string `arg:"" name:"api-secret" help:"The Infura API secret key to use."`
}

type NostrCmd struct {
	Cmd string `arg:"" name:"cmd" help:"The command to run. Can be one of: gen-keys."`
}

type FeedCmd struct {
	Cmd string `arg:"" name:"cmd" help:"The command to run. Can be one of: gen-keys."`
}

type NodeCmd struct {
	Cmd string `arg:"" name:"cmd" help:"The command to run. Can be one of: init."`
}

var log = logging.Logger("patr/main")

// Command-line arguments
var CLI struct {
	Debug bool     `help:"Enable debug mode."`
	Did   DidCmd   `cmd:"" help:"Run commands on the DID linked to a name."`
	Nostr NostrCmd `cmd:"" help:"Run Nostr commands."`
	Feed  FeedCmd  `cmd:"" help:"Run Patr feed commands."`
	Node  NodeCmd  `cmd:"" help:"Run Patr node commands."`
}

func init() {
	if os.Getenv("GOLOG_LOG_LEVEL") == "info" { // Reduce noise level of some loggers
		logging.SetLogLevel("dht/RtRefreshManager", "error")
		logging.SetLogLevel("bitswap", "error")
		logging.SetLogLevel("connmgr", "error")
	} else if os.Getenv("GOLOG_LOG_LEVEL") == "" {
		logging.SetAllLoggers(logging.LevelInfo)
		logging.SetLogLevel("dht/RtRefreshManager", "error")
		logging.SetLogLevel("bitswap", "error")
		logging.SetLogLevel("connmgr", "error")
		logging.SetLogLevel("net/identify", "error")
	}
}

func main() {
	ascii := figlet4go.NewAsciiRender()
	options := figlet4go.NewRenderOptions()
	options.FontColor = []figlet4go.Color{
		figlet4go.ColorCyan,
		figlet4go.ColorBlue,
		figlet4go.ColorRed,
		figlet4go.ColorYellow,
	}
	renderStr, _ := ascii.RenderOpts("Patr", options)
	fmt.Print(renderStr)

	ctx := kong.Parse(&CLI)
	ctx.FatalIfErrorf(ctx.Run(&kong.Context{}))
}

func (c *DidCmd) Run(clictx *kong.Context) error {
	switch strings.ToLower(c.Cmd) {
	case "resolve":
		d, err := did.Parse(c.Name)
		if err != nil {
			log.Errorf("Could not parse DID %s: %v", c.Name, err)
			return err
		}
		if d.ID.Method != "ens" {
			log.Errorf("Only ENS DIDs are supported currently.")
			return nil
		}
		r, err := blockchain.ResolveENS(d.ID.ID, c.ApiSecret)
		if err == nil {
			fmt.Printf("Address: %s\nContent-Hash: %s\nAvatar: %s\nPublic-Key: %s", r.Address, r.ContentHash, r.Avatar, r.Pubkey)
			return nil
		} else {
			return err
		}

	default:
		log.Errorf("Unknown did command: %s", c.Cmd)
		return fmt.Errorf("UNKNOWN DID COMMAND: %s", c.Cmd)
	}

	//priv, pub := crypto.GenerateIdentity()
	//clientConfig := models.Config{Pubkey: pub, PrivKey: priv}
	//data, _ := json.MarshalIndent(clientConfig, "", " ")
	//err := ioutil.WriteFile(filepath.Join(util.GetUserHomeDir(), ".citizen5", "client.json"), data, 0644)
	//if err != nil {
	//	log.Errorf("error creating client configuration file: %v", err)
	//	return nil
	//}
	//log.Infof("client identity is %s.", crypto.GetIdentity(pub).Pretty())
	//log.Infof("citizen5 client initialized.")

}

func (c *NostrCmd) Run(clictx *kong.Context) error {
	switch strings.ToLower(c.Cmd) {
	case "gen-keys":
		log.Info("Generating Nostr secp256k1 key-pair...")
		priv, pub, err := nostr.GenerateKeyPair()
		if err != nil {
			log.Errorf("Error generating Nostr secp256k1 key-pair: %v", err)
			return err
		} else {
			log.Info("Generated Nostr secp256k1 key-pair.")
			privs, _ := multibase.Encode(multibase.Base16, priv)
			pubs, _ := multibase.Encode(multibase.Base16, pub)
			fmt.Printf("Private key: %s (KEEP THIS SAFE AND NEVER SHARE IT)\nPublic key: %s", privs, pubs)
			return nil
		}

	}
	//priv, pub := crypto.GenerateIdentity()
	//clientConfig := models.Config{Pubkey: pub, PrivKey: priv}
	//data, _ := json.MarshalIndent(clientConfig, "", " ")
	//err := ioutil.WriteFile(filepath.Join(util.GetUserHomeDir(), ".citizen5", "client.json"), data, 0644)
	//if err != nil {
	//	log.Errorf("error creating client configuration file: %v", err)
	//	return nil
	//}
	//log.Infof("client identity is %s.", crypto.GetIdentity(pub).Pretty())
	//log.Infof("citizen5 client initialized.")
	return nil
}

func (c *FeedCmd) Run(clictx *kong.Context) error {
	switch strings.ToLower(c.Cmd) {
	case "gen-keys":
		log.Info("Generating IPNS RSA 2048-bit key-pair...")
		priv, pub, err := feed.GenerateIPNSKeyPair()
		if err != nil {
			log.Errorf("Error generating IPNS RSA 2048-bit key-pair: %v", err)
			return err
		} else {
			log.Errorf("Generated IPNS RSA 2048-bit key-pair.")
			privs, _ := multibase.Encode(multibase.Base16, priv)
			pubs, _ := multibase.Encode(multibase.Base16, pub)
			fmt.Printf("Private key: %s (KEEP THIS SAFE AND NEVER SHARE IT)\nPublic key: %s", privs, pubs)
			return nil
		}
	default:
		log.Errorf("Unknown feed command: %s", c.Cmd)
		return fmt.Errorf("UNKNOWN FEED COMMAND: %s", c.Cmd)
	}
}

func (c *NodeCmd) Run(clictx *kong.Context) error {
	switch strings.ToLower(c.Cmd) {
	case "init":
		d := filepath.Join(util.GetUserHomeDir(), ".patr")
		if _, err := os.Stat(d); err != nil {
			err := os.Mkdir(d, 0755)
			if err != nil {
				log.Errorf("error creating node configuration directory %s: %v", d, err)
				return err
			}
		}
		f := filepath.Join(d, "node.json")
		if _, err := os.Stat(f); err == nil {
			log.Errorf("node configuration file %s already exists", f)
			return nil
		}
		priv, pub, err := ipfs.GenerateIPFSNodeKeyPair()
		if err != nil {
			return err
		}
		config := node.Config{Pubkey: pub, PrivKey: priv}
		data, _ := json.MarshalIndent(config, "", " ")
		err = os.WriteFile(filepath.Join(d, "node.json"), data, 0644)
		if err != nil {
			log.Errorf("error creating node configuration file: %v", err)
			return err
		}
		log.Infof("node identity is %s", ipfs.GetIPFSNodeIdentity(pub).Pretty())
		log.Infof("patr node configuration initialized at %s", filepath.Join(d, "node.json"))
		return nil
	case "run":
		f := filepath.Join(filepath.Join(util.GetUserHomeDir(), ".patr"), "node.json")
		if _, err := os.Stat(f); err != nil {
			log.Errorf("could not find node configuration file %s", f)
			return nil
		}
		c, err := os.ReadFile(f)
		if err != nil {
			log.Errorf("could not read data from node configuration file: %v", err)
			return err
		}
		var config node.Config
		if json.Unmarshal(c, &config) != nil {
			log.Errorf("could not read JSON data from node configuration file: %v", err)
			return err
		}
		ctx, _ := context.WithCancel(context.Background())
		err = node.Run(ctx, config)
		return err
	default:
		log.Errorf("Unknown node command: %s", c.Cmd)
		return fmt.Errorf("UNKNOWN NODE COMMAND: %s", c.Cmd)
	}

}
