package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"
	logging "github.com/ipfs/go-log/v2"
	"github.com/mbndr/figlet4go"
)

type InitUserCmd struct {
	Name string `arg:"" name:"name" help:"Initialize the client for this name."`
}

var log = logging.Logger("patr/main")

// Command-line arguments
var CLI struct {
	Debug    bool        `help:"Enable debug mode."`
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

	log.Info("starting")
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
