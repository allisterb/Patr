package ipfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	iface "github.com/ipfs/boxo/coreiface"
	ipfspath "github.com/ipfs/boxo/coreiface/path"
	ipns "github.com/ipfs/boxo/ipns"
	path "github.com/ipfs/boxo/path"
	"github.com/multiformats/go-multibase"

	logging "github.com/ipfs/go-log/v2"

	blocks "github.com/ipfs/go-block-format"
	ds "github.com/ipfs/go-datastore"
	dsync "github.com/ipfs/go-datastore/sync"
	cfg "github.com/ipfs/kubo/config"
	ipfsCore "github.com/ipfs/kubo/core"
	coreapi "github.com/ipfs/kubo/core/coreapi"
	"github.com/ipfs/kubo/core/node/libp2p"
	repo "github.com/ipfs/kubo/repo"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/ipfs/go-cid"
	"github.com/ipld/go-ipld-prime/datamodel"
	"github.com/ipld/go-ipld-prime/fluent/qp"
	"github.com/ipld/go-ipld-prime/linking"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	mh "github.com/multiformats/go-multihash"

	"github.com/nbd-wtf/go-nostr"

	"github.com/allisterb/patr/w3s"
)

type IPFSCore struct {
	Api  iface.CoreAPI
	Node ipfsCore.IpfsNode
	LS   linking.LinkSystem
}

type IPFSLinkStorage struct {
	ipfs iface.CoreAPI
}

type IPFSLinkWriter struct {
	ctx  context.Context
	ipfs iface.CoreAPI
	cid  cid.Cid
	data bytes.Buffer
}

var log = logging.Logger("patr/ipfs")

func (w *IPFSLinkWriter) Write(d []byte) (int, error) {
	return w.data.Read(d)
}

func (w *IPFSLinkWriter) BlockWriteCommit(lnk datamodel.Link) error {
	b, err := blocks.NewBlockWithCid(w.data.Bytes(), w.cid)
	if err != nil {
		return err
	}
	_, err = w.ipfs.Block().Put(w.ctx, bytes.NewReader(b.RawData()))
	return err
}

func (store *IPFSLinkStorage) Has(ctx context.Context, key string) (bool, error) {
	_, cid, err := cid.CidFromBytes([]byte(key))
	if err != nil {
		log.Errorf("could not create CID from key string %s: %v", key, err)
		return false, err
	}
	_, err = store.ipfs.Block().Stat(ctx, ipfspath.IpldPath(cid))
	return err != nil, err
}

func (store *IPFSLinkStorage) Get(ctx context.Context, key string) ([]byte, error) {
	_, k, err := cid.CidFromBytes([]byte(key))
	if err != nil {
		log.Errorf("could not create CID from key string %s: %v", key, err)
		return []byte{}, err
	}
	r, err := store.ipfs.Block().Get(ctx, ipfspath.IpldPath(k))
	if err != nil {
		log.Errorf("could not get CID %v at path %v from IPFS block storage: %v", key, ipfspath.IpldPath(k), err)
		return []byte{}, err
	}
	return io.ReadAll(r)
}

func (store *IPFSLinkStorage) Put(ctx context.Context, key string, data []byte) error {
	_, k, err := cid.CidFromBytes([]byte(key))
	if err != nil {
		log.Errorf("could not create CID from key string %s: %v", key, err)
		return err
	}
	b, _ := blocks.NewBlockWithCid(data, k)
	r := bytes.NewReader(b.RawData())
	_, err = store.ipfs.Block().Put(ctx, r)
	return err
}

func (store *IPFSLinkStorage) OpenRead(lnkCtx linking.LinkContext, lnk datamodel.Link) (io.Reader, error) {
	_, k, err := cid.CidFromBytes([]byte(lnk.Binary()))
	if err != nil {
		log.Errorf("could not create CID from key string %s: %v", lnk.Binary(), err)
		return nil, err
	}
	return store.ipfs.Block().Get(lnkCtx.Ctx, ipfspath.IpldPath(k))
}

func (store *IPFSLinkStorage) OpenWrite(lnkCtx linking.LinkContext, lnk datamodel.Link) (io.Writer, linking.BlockWriteCommitter, error) {
	_, k, err := cid.CidFromBytes([]byte(lnk.Binary()))
	if err != nil {
		log.Errorf("could not create CID from key string %s: %v", lnk.Binary(), err)
		return nil, nil, err
	}
	lw := IPFSLinkWriter{
		ctx:  lnkCtx.Ctx,
		ipfs: store.ipfs,
		cid:  k,
	}
	return &lw, lw.BlockWriteCommit, nil
}

// func
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

func GetIPNSPublicKeyName(pubb []byte) (string, error) {
	pub, err := crypto.UnmarshalPublicKey(pubb)
	if err != nil {
		log.Errorf("could not unmarshal IPNS public key: %v", err)
		return "", err
	}
	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		log.Errorf("could not get peer ID public key: %v", err)
		return "", err
	}
	return peer.ToCid(pid).StringOfBase(multibase.Base36)
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

func StartIPFSNode(ctx context.Context, privkey []byte, pubkey []byte) (*ipfsCore.IpfsNode, iface.CoreAPI, func(), error) {
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
		return nil, nil, nil, err
	}
	log.Infof("IPFS node %s started", node.Identity.Pretty())
	c, e := coreapi.NewCoreAPI(node)
	if e != nil {
		return nil, nil, nil, e
	} else {
		shutdown := func() {
			log.Infof("shutting down IPFS node %s...", node.Identity.Pretty())
			node.Close()
			log.Infof("IPFS node %s shutdown completed", node.Identity.Pretty())
		}
		return node, c, shutdown, e
	}
}

func PublishIPNSRecordForDAGNode(ctx context.Context, ipfs iface.CoreAPI, cid cid.Cid) {
	k, _ := ipfs.Key().Self(ctx)
	log.Infof("Key is %v", k.Path())
	//r, err := ipfs.Name().Publish(ctx, ipfspath.IpldPath(cid).String())

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
	} else {
		log.Infof("IPFS block %v pinned using Web3.Storage pinning service at %v", block.Cid(), r.Pin.Cid)
		return err
	}
}

func PutIPFSDAGBlockToW3S(ctx context.Context, ipfsNode iface.CoreAPI, authToken string, block *blocks.BasicBlock) (cid.Cid, error) {
	c, err := w3s.NewClient(w3s.WithToken(authToken))
	if err != nil {
		log.Errorf("could not create W3S client: %v", err)
		return cid.Cid{}, err
	}
	var buf bytes.Buffer
	err = w3s.WriteCar(ctx, ipfsNode.Dag(), []cid.Cid{block.Cid()}, &buf)
	if err != nil {
		log.Errorf("could not serialize block %v as CAR: %v", block.Cid(), err)
		return cid.Cid{}, err
	}
	pcid, err := c.PutCar(ctx, &buf)
	if err != nil {
		log.Errorf("could not put block %v as CAR to W3S: %v", block.Cid(), err)
		return cid.Cid{}, err
	} else {
		log.Infof("IPFS block %v pinned using Web3.Storage pinning service at %v", block.Cid(), pcid)

		return pcid, err
	}
}

func GetIPNSRecordFromW3S(ctx context.Context, authToken string, name string) (cid.Cid, error) {
	c, err := w3s.NewClient(w3s.WithToken(authToken))
	if err != nil {
		log.Errorf("could not create W3S client: %v", err)
		return cid.Cid{}, err
	}
	r, err := c.GetName(ctx, name)
	if err != nil {
		log.Errorf("could not lookup name %s on Web3.Storage: %v", name, err)
	}
	if r == nil {
		log.Infof("name %s does not exist on Web3.Storage", name)
		return cid.Undef, err
	}
	v := string(r.GetValue())
	p := path.FromString(v)
	log.Infof("IPNS name points to path %v", p)
	return cid.Parse(p.Segments()[1])
}

func PublishIPNSRecordForDAGNodeToW3S(ctx context.Context, authToken string, cid cid.Cid, privkey []byte, pubkey []byte) error {
	name, err := GetIPNSPublicKeyName(pubkey)
	if err != nil {
		return err
	}

	p := ipfspath.IpldPath(cid).String()
	log.Infof("publishing DAG node %v at path %s to IPNS name %s using Web3.Storage...", cid, p, name)
	c, err := w3s.NewClient(w3s.WithToken(authToken))
	if err != nil {
		log.Errorf("could not create W3S client: %v", err)
		return err
	}
	sk, err := crypto.UnmarshalPrivateKey(privkey)
	if err != nil {
		log.Errorf("could not unmarshal IPNS private key: %v", err)
		return err
	}
	var seq uint64 = 1
	r, err := c.GetName(ctx, p)
	if r != nil && err == nil {
		seq = r.GetSequence() + 1
	}
	nr, err := ipns.Create(sk, []byte(p), seq, time.Now().Add(time.Hour*48), 0)
	if err != nil {
		log.Errorf("could not create new IPNS record for path %v: %v", p, err)
		return err
	}
	pk, err := crypto.UnmarshalPublicKey(pubkey)
	if err != nil {
		log.Errorf("could not unmarshal IPNS public key: %v", err)
		return err
	}
	if err = ipns.EmbedPublicKey(pk, nr); err != nil {
		log.Errorf("could not embed IPNS public key in record: %v", err)
		return err
	}

	err = c.PutName(ctx, nr, "k51qzi5uqu5dlcuzv5xhg1zqn48gobcvn2mx13uoig7zfj8rz6zvqdxsugka9z")
	if err == nil {
		log.Infof("published DAG node %v at path %s to IPNS name %s using Web3.Storage", cid, p, name)
	} else {
		log.Errorf("could not publishe DAG node %v at path %s to IPNS name %s using Web3.Storage: %v", cid, p, name, err)
	}

	return err
	//r, err := c.GetName(ctx)
	//ipfsNode.
	//ipfsNode.Name().Publish(ctx, path.IpldPath(cid), options.Name.Key())
	//sk, err := crypto.UnmarshalPrivateKey(privkey)
	//ipfsNode.Name().(ctx, path.IpldPath(cid), options.Name.Key())
	//ipnsRecord, err := ipns.Create(sk, cid.Bytes(), 0, time.Now().Add(1*time.Hour))
	//ipnsRecord.
	//ipnsRecord.
}

func PutNostrEventAsIPLDLink(ctx context.Context, ipfs IPFSCore, evt nostr.Event) (datamodel.Link, error) {
	dagnode, err := qp.BuildMap(basicnode.Prototype.Any, 4, func(ma datamodel.MapAssembler) {
		qp.MapEntry(ma, "id", qp.String(evt.ID))
		qp.MapEntry(ma, "pubkey", qp.String(evt.PubKey))
		qp.MapEntry(ma, "created_at", qp.String(evt.CreatedAt.Time().String()))
		qp.MapEntry(ma, "kind", qp.Int(int64(evt.Kind)))
		qp.MapEntry(ma, "tags", qp.Map(int64(len(evt.Tags)), func(ma datamodel.MapAssembler) {
			for _, t := range evt.Tags {
				qp.MapEntry(ma, t.Key(), qp.String(t.Value()))
			}
		}))
		qp.MapEntry(ma, "content", qp.String(evt.Content))
		qp.MapEntry(ma, "sig", qp.String(evt.Sig))
		//PutIPFSDAGBlockToW3S(ctx, ipfscore.Api, )
	})
	if err != nil {
		return nil, fmt.Errorf("could not create IPLD node from Nostr event %s: %v", evt.ID, err)
	}
	lp := cidlink.LinkPrototype{
		Prefix: cid.Prefix{
			Version:  1,           // Usually '1'.
			Codec:    cid.DagJSON, // 0x71 means "dag-cbor" -- See the multicodecs table: https://github.com/multiformats/multicodec/
			MhType:   mh.SHA3_384, // 0x20 means "sha2-512" -- See the multicodecs table: https://github.com/multiformats/multicodec/
			MhLength: 48,          // sha2-512 hash has a 64-byte sum.
		}}
	return ipfs.LS.Store(linking.LinkContext{}, lp, dagnode)
}
