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
	Cmd  string `arg:"" name:"cmd" help:"The command to run. Can be one of: resolve, init-user, profile."`
	Name string `arg:"" name:"name" help:"Get the DID linked to this name."`
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

type ProfileCmd struct {
	Cmd      string `arg:"" name:"cmd" help:"The command to run. Can be one of: create."`
	Did      string `arg:"" name:"name" help:"Use the DID linked to this name."`
	UserFile string `arg:"" name:"name" help:"Load user configuration from this file."`
}

var log = logging.Logger("patr/main")

// Command-line arguments
var CLI struct {
	Did     DidCmd     `cmd:"" help:"Run commands on the DID linked to a name."`
	Nostr   NostrCmd   `cmd:"" help:"Run Nostr commands."`
	Feed    FeedCmd    `cmd:"" help:"Run Patr feed commands."`
	Node    NodeCmd    `cmd:"" help:"Run Patr node commands."`
	Profile ProfileCmd `cmd:"" help:"Run Patr node commands."`
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
		config, err := node.LoadConfig()
		if err != nil {
			log.Error("could not load patr node config")
			return err
		}
		r, err := blockchain.ResolveENS(d.ID.ID, config.InfuraSecretKey)
		if err == nil {
			fmt.Printf("ETH Address: %s\nNostr Public-Key: %v\nIPNS Public-Key: %s\nContent-Hash: %s\nAvatar: %s", r.Address, r.NostrPubKey, r.IPNSPubKey, r.ContentHash, r.Avatar)
			return nil
		} else {
			return err
		}

	default:
		log.Errorf("Unknown did command: %s", c.Cmd)
		return fmt.Errorf("UNKNOWN DID COMMAND: %s", c.Cmd)
	}
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
			privs, _ := multibase.Encode(multibase.Base58BTC, priv)
			pubs, _ := multibase.Encode(multibase.Base58BTC, pub)
			fmt.Printf("Private key: %s (KEEP THIS SAFE AND NEVER SHARE IT)\nPublic key: %s", privs, pubs)
			return nil
		}

	}
	return nil
}

func (c *FeedCmd) Run(clictx *kong.Context) error {
	switch strings.ToLower(c.Cmd) {
	case "gen-keys":
		log.Info("Generating IPNS RSA 2048-bit key-pair...")
		priv, pub, err := ipfs.GenerateIPNSKeyPair()
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
		log.Info("add your Infura and Web3.Storage API secret keys to this file to complete the configuration")
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
		err = node.Run(ctx)
		return err
	default:
		log.Errorf("Unknown node command: %s", c.Cmd)
		return fmt.Errorf("UNKNOWN NODE COMMAND: %s", c.Cmd)
	}
}

func (c *ProfileCmd) Run(clictx *kong.Context) error {
	switch strings.ToLower(c.Cmd) {
	case "init-user":
		d, err := did.Parse(c.Did)
		if err != nil {
			log.Errorf("Could not parse DID %s: %v", c.Did, err)
			return err
		}
		if d.ID.Method != "ens" {
			log.Errorf("invalid DID: %s. Only ENS DIDs are supported currently", c.Did)
			return fmt.Errorf("INVALID DID: %s. ONLY ENS DIDS ARE SUPPORTED CURRENTLY", c.Did)
		}
		if _, err := os.Stat(c.UserFile); err == nil {
			log.Errorf("user configuration file %s already exists", c.UserFile)
			return fmt.Errorf("USER CONFIGURATION FILE %s ALREADY EXISTS", c.UserFile)
		}
		nsk, npk, err := nostr.GenerateKeyPair()
		if err != nil {
			log.Errorf("Could not generate Nostr keypair for %s: %v", c.Did, err)
			return err
		}
		isk, ipk, err := ipfs.GenerateIPNSKeyPair()
		if err != nil {
			log.Errorf("Could not generate IPNS keypair for %s: %v", c.Did, err)
			return err
		}
		user := feed.User{
			Did:          c.Did,
			NostrPrivKey: nsk,
			NostrPubkey:  npk,
			IPNSPrivKey:  isk,
			IPNSPubKey:   ipk,
		}
		data, _ := json.MarshalIndent(user, "", " ")
		err = os.WriteFile(c.UserFile, data, 0644)
		if err != nil {
			log.Errorf("error creating patr user configuration file: %v", err)
			return err
		} else {
			log.Infof("created patr user configuration file for %s at %s", c.Did, c.UserFile)
			snpub, _ := multibase.Encode(multibase.Base58BTC, user.NostrPubkey)
			sipub, _ := multibase.Encode(multibase.Base58BTC, user.IPNSPubKey)
			fmt.Printf("Nostr secp256k1 public key (nostrKey): %s\nIPNS rsa-2048 public key (ipnsKey): %s", snpub, sipub)
			return nil
		}
	case "create":
		_, err := node.LoadConfig()
		if err != nil {
			return err
		}
		ctx, _ := context.WithCancel(context.Background())
		feed.CreateProfile(ctx, feed.User{Did: "allisterb.eth"})
		return nil
	default:
		log.Errorf("Unknown profile command: %s", c.Cmd)
		return fmt.Errorf("UNKNOWN PROFILE COMMAND: %s", c.Cmd)
	}
}
