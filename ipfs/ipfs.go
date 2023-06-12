package ipfs

import (
	"context"
	"crypto/rand"
	"encoding/base64"

	iface "github.com/ipfs/boxo/coreiface"
	logging "github.com/ipfs/go-log/v2"

	ds "github.com/ipfs/go-datastore"
	dsync "github.com/ipfs/go-datastore/sync"
	cfg "github.com/ipfs/kubo/config"
	ipfsCore "github.com/ipfs/kubo/core"
	coreapi "github.com/ipfs/kubo/core/coreapi"
	"github.com/ipfs/kubo/core/node/libp2p"
	repo "github.com/ipfs/kubo/repo"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

var log = logging.Logger("patr/ipfs")

func GenerateIPFSNodeKeyPair() ([]byte, []byte, error) {
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
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		panic(err)
	}
	log.Infof("generated identity %s", id.Pretty())
	return privkeyb, pubkeyb, err
}

func GetIPFSNodeIdentity(pubb []byte) peer.ID {
	pub, err := crypto.UnmarshalPublicKey(pubb)
	if err != nil {
		panic(err)
	}
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return id
}

func initIPFSRepo(ctx context.Context, privkey []byte, pubkey []byte) repo.Repo {
	pid := GetIPFSNodeIdentity(pubkey)
	c := cfg.Config{}
	c.Pubsub.Enabled = cfg.True
	c.Bootstrap = []string{
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
		"/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
	}
	c.Addresses.Swarm = []string{"/ip4/127.0.0.1/tcp/4001", "/ip4/127.0.0.1/udp/4001/quic"}
	c.Identity.PeerID = pid.Pretty()
	c.Identity.PrivKey = base64.StdEncoding.EncodeToString(privkey)

	return &repo.Mock{
		D: dsync.MutexWrap(ds.NewMapDatastore()),
		C: c,
	}
}

func InitIPFSApi(ctx context.Context, privkey []byte, pubkey []byte) (iface.CoreAPI, func(), error) {
	log.Infof("starting IPFS node %s...", GetIPFSNodeIdentity(pubkey).Pretty())
	node, err := ipfsCore.NewNode(ctx, &ipfsCore.BuildCfg{
		Online:  true,
		Routing: libp2p.DHTOption,
		Repo:    initIPFSRepo(ctx, privkey, pubkey),
		ExtraOpts: map[string]bool{
			"pubsub": true,
		},
	})
	if err != nil {
		return nil, nil, err
	}
	log.Infof("IPFS node %s started.", node.Identity.Pretty())
	c, e := coreapi.NewCoreAPI(node)
	if e != nil {
		return nil, nil, e
	} else {
		clean := func() {
			log.Infof("shutting down IPFS node %s...", node.Identity.Pretty())
			node.Close()
			log.Infof("IPFS node %s shutdown completed.", node.Identity.Pretty())
		}
		return c, clean, e
	}
}
