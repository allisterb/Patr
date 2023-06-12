package nostr

import (
	"encoding/hex"

	logging "github.com/ipfs/go-log/v2"
	"github.com/nbd-wtf/go-nostr"
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
