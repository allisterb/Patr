package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	logging "github.com/ipfs/go-log/v2"
	"github.com/mbndr/figlet4go"

	"github.com/allisterb/patr/blockchain"
	"github.com/allisterb/patr/did"
)

type DidCmd struct {
	Cmd       string `arg:"" name:"cmd" help:"Command to run. Can be one of: resolve, profile."`
	Name      string `arg:"" name:"name" help:"Get the DID linked to this name."`
	ApiSecret string `arg:"" name:"api-secret" help:"The Infura API secret key to use."`
}

type InitUserCmd struct {
	Name string `arg:"" name:"name" help:"Initialize the client for this name."`
}

var log = logging.Logger("patr/main")

// Command-line arguments
var CLI struct {
	Debug    bool        `help:"Enable debug mode."`
	Did      DidCmd      `cmd:"" help:"Get the DID linked to this name."`
	InitUser InitUserCmd `cmd:"" help:"Initialize the citizen5 server."`
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
		} else {
			return err
		}

	default:
		log.Errorf("Unknown command: %s", c.Cmd)
	}
	return nil

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

func (c *InitUserCmd) Run(clictx *kong.Context) error {
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
