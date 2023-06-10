package main

import (
	"fmt"
	"os"

	logging "github.com/ipfs/go-log/v2"
	"github.com/mbndr/figlet4go"
)

var log = logging.Logger("patr/main")

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
}
