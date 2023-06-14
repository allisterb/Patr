package ipfs

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

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

	blocks "github.com/ipfs/go-block-format"

	"github.com/allisterb/patr/w3s"
)

type IPFSLinkStorage struct {
	ipfs iface.CoreAPI
}

var log = logging.Logger("patr/ipfs")

func (store *IPFSLinkStorage) IsInitialized() error {
	if store.ipfs != nil {
		return nil
	} else {
		return fmt.Errorf("IPFS link storage not initialized")
	}
}

/*
	"github.com/ipfs/go-block-format"
	"github.com/ipfs/go-block-service"
	"github.com/ipfs/go-cid"
	ifacePath "github.com/ipfs/boxo/coreiface/path"

	func (store *IPFSLinkStorage) Has(ctx context.Context, cid cid.Cid) (bool, error) {
		_, err := store.ipfs.Block().Get(ctx, ifacePath.IpldPath(cid))
		return err != nil, err
	}

	func (store *IPFSLinkStorage) Put(ctx context.Context, block blocks.Block) error {
		b, err := store.ipfs.Block().Put()

}

	func (store *IPFSLinkStorage) OpenRead(lnkCtx linking.LinkContext, lnk datamodel.Link) (io.Reader, error) {
		return store.ipfs.Block().Get(lnkCtx.Ctx, ifacePath.New(lnk.Binary()))
	}

	func (store *IPFSLinkStorage) OpenWrite(lnkCtx linking.LinkContext) (io.Writer, linking.BlockWriteCommitter, error) {
		//store.beInitialized()
		buf := bytes.Buffer{}
		return &buf, func(lnk datamodel.Link) error {
			store.ipfs.Object().Put()
			cl, ok := lnk.(Link)
			if !ok {
				return fmt.Errorf("incompatible link type: %T", lnk)
			}

			store.Bag[string(cl.Hash())] = buf.Bytes()
			return nil
		}, nil
	}
*/
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

func GenerateIPFSNodeKeyPair() ([]byte, []byte, error) {
	priv, pub, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, rand.Reader)
	if err != nil {
		log.Errorf("error generating RSA 2048-bit keypair: %v", err)
		return []byte{}, []byte{}, err
	}
	privkeyb, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		log.Errorf("error marshalling RSA 2048-bit private key: %v", err)
		return []byte{}, []byte{}, err
	}
	pubkeyb, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		log.Errorf("error marshalling RSA 2048-bit public key: %v", err)
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
		"/ip4/149.56.89.144/tcp/4001/p2p/12D3KooWDiybBBYDvEEJQmNEp1yJeTgVr6mMgxqDrm9Gi8AKeNww",
	}
	c.Addresses.Swarm = []string{"/ip4/127.0.0.1/tcp/4001", "/ip4/127.0.0.1/udp/4001/quic"}
	c.Identity.PeerID = pid.Pretty()
	c.Identity.PrivKey = base64.StdEncoding.EncodeToString(privkey)

	return &repo.Mock{
		D: dsync.MutexWrap(ds.NewMapDatastore()),
		C: c,
	}
}

func StartIPFSNode(ctx context.Context, privkey []byte, pubkey []byte) (iface.CoreAPI, func(), error) {
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
		log.Errorf("error staring IPFS node %s: %v", GetIPFSNodeIdentity(pubkey).Pretty(), err)
		return nil, nil, err
	}
	log.Infof("IPFS node %s started", node.Identity.Pretty())
	c, e := coreapi.NewCoreAPI(node)
	if e != nil {
		return nil, nil, e
	} else {
		shutdown := func() {
			log.Infof("shutting down IPFS node %s...", node.Identity.Pretty())
			node.Close()
			log.Infof("IPFS node %s shutdown completed", node.Identity.Pretty())
		}
		return c, shutdown, e
	}
}

func PinIPFSBlockToW3S(ctx context.Context, ipfs iface.CoreAPI, authToken string, block *blocks.BasicBlock) error {
	c, err := w3s.NewClient(w3s.WithToken(authToken))
	if err != nil {
		log.Errorf("could not create W3S client: %v", err)
		return err
	}
	l, err := ipfs.Swarm().LocalAddrs(ctx)
	if err != nil {
		log.Errorf("could not get IPFS node local addresses: %v", err)
		return err
	}
	us := make([]w3s.PinOption, len(l))
	for i := range l {
		us[i] = w3s.WithPinOrigin(l[i].String())
	}
	r, err := c.Pin(ctx, block.Cid(), us[0])
	if err != nil {
		return err
	}
	log.Infof("%s", r.Status)
	return err

}
