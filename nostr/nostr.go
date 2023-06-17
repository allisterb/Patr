package nostr

import (
	"encoding/hex"

	"net/http"

	"github.com/allisterb/patr/ipfs"
	"github.com/fiatjaf/relayer"
	logging "github.com/ipfs/go-log/v2"
	"github.com/nbd-wtf/go-nostr"

	iface "github.com/ipfs/boxo/coreiface"
)

var log = logging.Logger("patr/nostr")

func GenerateKeyPair() ([]byte, []byte, error) {
	sk := nostr.GeneratePrivateKey()
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		log.Errorf("Error generating secp256k1 keypair: %v", err)
		return []byte{}, []byte{}, err
	}
	priv, err := hex.DecodeString(sk)
	if err != nil {
		log.Errorf("Error encoding secp256k1 private key: %v", err)
		return []byte{}, []byte{}, err
	}
	pub, _ := hex.DecodeString(pk)
	if err != nil {
		log.Errorf("Error encoding secp256k1 public key: %v", err)
		return []byte{}, []byte{}, err
	}
	return priv, pub, err
}

type Logger struct {
}

type Relay struct {
	Ipfs ipfs.IPFSCore
}

type Storage struct {
	ipfs iface.CoreAPI
}

func (l *Logger) Infof(format string, v ...any) {
	log.Infof(format, v)
}

func (l *Logger) Warningf(format string, v ...any) {
	log.Warnf(format, v)
}

func (l *Logger) Errorf(format string, v ...any) {
	log.Errorf(format, v)
}

func (s *Storage) SaveEvent(evt *nostr.Event) error {
	//evt.Kind == nostr.
	return nil
}
func (r *Relay) Name() string {
	return "PatrRelay"
}

func (r *Relay) Init() error {
	log.Infof("patr relay initializing...")
	return nil
}

func (r *Relay) OnInitialized(s *relayer.Server) {
	// special handlers
	//s.Router().Path("/").HandlerFunc(handleWebpage)
	s.Router().Path("/dm").HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {

	})
	log.Info("patr relay initialized")
}

func CreateBlankEvent() nostr.Event {
	return nostr.Event{
		ID:        "0",
		Content:   "test",
		CreatedAt: 1,
	}

}
