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
	nip19 "github.com/nbd-wtf/go-nostr/nip19"

	"github.com/allisterb/patr/blockchain"
	"github.com/allisterb/patr/did"
	"github.com/allisterb/patr/feed"
	"github.com/allisterb/patr/ipfs"
	"github.com/allisterb/patr/node"
	"github.com/allisterb/patr/nostr"
	"github.com/allisterb/patr/util"
)

type NodeCmd struct {
	Cmd string `arg:"" name:"cmd" help:"The command to run. Can be one of: init."`
	Did string `arg:"" optional:"" name:"did" help:"Use the DID linked to this name."`
}

type DidCmd struct {
	Cmd  string `arg:"" name:"cmd" help:"The command to run. Can be one of: resolve, init-user, profile."`
	Name string `arg:"" name:"name" help:"Get the DID linked to this name."`
}

type FeedCmd struct {
	Cmd string `arg:"" name:"cmd" help:"The command to run. Can be one of: gen-keys."`
}

type NostrCmd struct {
	Cmd string `arg:"" name:"cmd" help:"The command to run. Can be one of: gen-keys."`
}

var log = logging.Logger("patr/main")

// Command-line arguments
var CLI struct {
	Node  NodeCmd  `cmd:"" help:"Run Patr node commands."`
	Did   DidCmd   `cmd:"" help:"Run commands on the DID linked to a name."`
	Feed  FeedCmd  `cmd:"" help:"Run Patr feed commands."`
	Nostr NostrCmd `cmd:"" help:"Run Nostr commands."`
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

func (c *NodeCmd) Run(clictx *kong.Context) error {
	switch strings.ToLower(c.Cmd) {
	case "init":
		if c.Did == "" {
			return fmt.Errorf("you must specify a user DID to initialize the node")
		}
		if !did.IsValid(c.Did) {
			return fmt.Errorf("Invalid DID: %s", c.Did)
		}
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
		} else {
			ppub, _ := ipfs.GetIPNSPublicKeyName(pub)
			log.Infof("IPFS rsa-2048 public key (ipfsKey): %s", ppub)
		}
		nsk, npk, err := nostr.GenerateKeyPair()
		if err != nil {
			log.Errorf("Could not generate Nostr secp256k1 keypair for %s: %v", c.Did, err)
			return err
		} else {
			nppk, _ := nip19.EncodePublicKey(npk)
			log.Infof("Nostr secp256k1 public key (nostrKey): %s\n", nppk)
		}

		//nssk, _ := nip19.EncodePrivateKey(nsk)
		//nppk, _ := nip19.EncodePublicKey(npk)
		config := node.Config{
			Did:          c.Did,
			IPFSPubKey:   pub,
			IPFSPrivKey:  priv,
			NostrPrivKey: nsk,
			NostrPubKey:  npk,
		}
		data, _ := json.MarshalIndent(config, "", " ")
		err = os.WriteFile(filepath.Join(d, "node.json"), data, 0644)
		if err != nil {
			log.Errorf("error creating node configuration file: %v", err)
			return err
		}
		log.Infof("user DID is %s", c.Did)
		log.Infof("node identity is %s", ipfs.GetIPFSNodeIdentity(pub).Pretty())
		log.Infof("patr node configuration initialized at %s", filepath.Join(d, "node.json"))
		log.Info("add your Infura and Web3.Storage API secret keys to this file to complete the configuration")
		return nil

	case "run":
		ctx, _ := context.WithCancel(context.Background())
		err := node.Run(ctx)
		return err

	default:
		return fmt.Errorf("Unknown node command: %s", c.Cmd)
	}
}

func (c *DidCmd) Run(clictx *kong.Context) error {
	switch strings.ToLower(c.Cmd) {
	case "resolve":
		d, err := did.Parse(c.Name)
		if err != nil {
			log.Errorf("could not parse DID %s: %v", c.Name, err)
			return err
		}
		if d.ID.Method != "ens" {
			log.Errorf("only ENS DIDs are supported currently.")
			return nil
		}
		config, err := node.LoadConfig()
		if err != nil {
			log.Error("could not load patr node config")
			return err
		}
		r, err := blockchain.ResolveENS(d.ID.ID, config.InfuraSecretKey)
		if err == nil {
			fmt.Printf("ETH Address: %s\nNostr Public-Key: %v\nIPFS Public-Key: %s\nContent-Hash: %s\nAvatar: %s", r.Address, r.NostrPubKey, r.IPFSPubKey, r.ContentHash, r.Avatar)
			return nil
		} else {
			return err
		}

	default:
		log.Errorf("Unknown did command: %s", c.Cmd)
		return fmt.Errorf("UNKNOWN DID COMMAND: %s", c.Cmd)
	}
}

func (c *FeedCmd) Run(clictx *kong.Context) error {
	switch strings.ToLower(c.Cmd) {
	case "create":
		_, err := node.LoadConfig()
		if err != nil {
			return err
		}
		ctx, _ := context.WithCancel(context.Background())
		feed.CreateFeed(ctx)
		return nil

	default:
		log.Errorf("Unknown feed command: %s", c.Cmd)
		return fmt.Errorf("UNKNOWN FEED COMMAND: %s", c.Cmd)
	}
}

func (c *NostrCmd) Run(clictx *kong.Context) error {
	switch strings.ToLower(c.Cmd) {
	case "create-event":
		_, err := node.LoadConfig()
		if err != nil {
			return err
		}
		ctx, _ := context.WithCancel(context.Background())
		ipfscore, err := ipfs.StartIPFSNode(ctx, node.CurrentConfig.IPFSPrivKey, node.CurrentConfig.IPFSPubKey)
		ipfscore.W3S.SetAuthToken(node.CurrentConfig.W3SSecretKey)
		if err != nil {
			return err
		}
		return nostr.CreateTestEvent(node.CurrentConfig.NostrPrivKey, "test event", *ipfscore)
	default:
		log.Errorf("Unknown nostr command: %s", c.Cmd)
		return fmt.Errorf("UNKNOWN NOSTR COMMAND: %s", c.Cmd)
	}

}
