package feed

import (
	"context"
	"encoding/json"
	"os"

	path "github.com/ipfs/boxo/coreiface/path"
	cbornode "github.com/ipfs/go-ipld-cbor"
	logging "github.com/ipfs/go-log/v2"
	mh "github.com/multiformats/go-multihash"

	"github.com/allisterb/patr/ipfs"
	"github.com/allisterb/patr/node"
)

type User struct {
	Did          string
	NostrPrivKey []byte
	NostrPubkey  []byte
	IPNSPrivKey  []byte
	IPNSPubKey   []byte
}

type Profile struct {
	Did string
}

var log = logging.Logger("patr/feed")

func init() {
	cbornode.RegisterCborType(Profile{})
}

func LoadUser(file string) (User, error) {
	u, err := os.ReadFile(file)
	if err != nil {
		log.Errorf("could not read user file: %v", err)
		return User{}, err
	}
	var user User
	if json.Unmarshal(u, &user) != nil {
		log.Errorf("could not read JSON data from user file: %v", err)
		return User{}, err
	}
	return user, nil
}
func CreateProfile(ctx context.Context, user User) error {
	log.Infof("creating patr profile for %s...", user.Did)
	c, err := node.LoadConfig()
	if err != nil {
		return err
	}
	ipfsNode, ipfsShutdown, err := ipfs.StartIPFSNode(ctx, c.PrivKey, c.Pubkey)
	if err != nil {
		return err
	}
	profile := Profile{Did: user.Did}

	n2, err := cbornode.WrapObject(profile, mh.SHA2_256, -1)
	log.Infof("cid: %v", n2.Cid())
	err = ipfsNode.Dag().Pinning().Add(ctx, n2)
	bb, err := ipfsNode.Dag().Get(ctx, n2.Cid())
	s, i, err := ipfsNode.Pin().IsPinned(ctx, path.IpldPath(bb.Cid()))
	ipfsNode.Pin().
		log.Infof("%v is pinned %v %v", path.IpldPath(bb.Cid()), s, i)
	if err != nil {
		return err
	}
	//ipfsNode.Dag().Pinning().

	/*
		n := bindnode.Wrap(profile, nil)
		"github.com/ipld/go-ipld-prime/codec/dagjson"
		cidlink "github.com/ipld/go-ipld-prime/linking/cid"
		"github.com/ipld/go-ipld-prime/node/bindnode"
		err = dagjson.Encode(n, &buf)
		b, err := ipfsNode.Block().Put(ctx, &buf)
		lnk := cidlink.Link{Cid: b.Path().Cid()}

		lsys := cidlink.DefaultLinkSystem()
		//lsys.SetReadStorage()
	*/

	ipfsShutdown()
	return err
}
