package feed

import (
	"crypto/rand"

	logging "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/crypto"
)

var log = logging.Logger("patr/feed")

func GenerateIPNSKeyPair() ([]byte, []byte, error) {
	priv, pub, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, rand.Reader)
	if err != nil {
		log.Errorf("Error generating RSA 2048-bit keypair: %v", err)
		return []byte{}, []byte{}, err
	}
	privkeyb, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		log.Errorf("Error marshalling RSA 2048-bit private key: %v", err)
		return []byte{}, []byte{}, err
	}
	pubkeyb, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		log.Errorf("Error marshalling RSA 2048-bit public key: %v", err)
		return []byte{}, []byte{}, err
	}
	return privkeyb, pubkeyb, err
}
