package feed

import (
	"bytes"
	"context"
	"encoding/json"
	"os"

	path "github.com/ipfs/boxo/coreiface/path"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	cbornode "github.com/ipfs/go-ipld-cbor"
	ipldlegacy "github.com/ipfs/go-ipld-legacy"
	logging "github.com/ipfs/go-log/v2"
	"github.com/ipld/go-ipld-prime/codec/dagjson"
	"github.com/ipld/go-ipld-prime/node/bindnode"
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
func CreateProfile(ctx context.Context, user User, w3stoken string) error {
	log.Infof("creating patr profile for %s...", user.Did)
	c, err := node.LoadConfig()
	if err != nil {
		return err
	}
	ipfsNode, ipfsShutdown, err := ipfs.StartIPFSNode(ctx, c.PrivKey, c.Pubkey)
	if err != nil {
		return err
	}
	profile := Profile{Did: "foo"}

	n2, err := cbornode.WrapObject(profile, mh.SHA2_256, -1)
	log.Infof("cid: %v", n2.Cid())
	err = ipfsNode.Dag().Pinning().Add(ctx, n2)
	bb, err := ipfsNode.Dag().Get(ctx, n2.Cid())
	s, i, err := ipfsNode.Pin().IsPinned(ctx, path.IpldPath(bb.Cid()))
	log.Infof("%v is pinned %v %v", path.IpldPath(bb.Cid()), s, i)
	if err != nil {
		return err
	}
	n := bindnode.Wrap(&profile, nil)
	var buf bytes.Buffer
	err = dagjson.Encode(n, &buf)
	if err != nil {
		return err
	}
	cidprefix := cid.Prefix{
		Version:  1, // Usually '1'.
		Codec:    cid.DagJSON,
		MhType:   mh.SHA3_384, // 0x15 means "sha3-384" -- See the multicodecs table: https://github.com/multiformats/multicodec/
		MhLength: 48,          // sha3-384 hash has a 48-byte sum.
	}
	xcid, err := cidprefix.Sum(buf.Bytes())
	blk, err := blocks.NewBlockWithCid(buf.Bytes(), xcid)
	formatNd := ipldlegacy.LegacyNode{blk, n}
	log.Infof("Block cid: %s", blk.Cid().String())
	ipfsNode.Dag().Pinning().Add(ctx, &formatNd)

	err = ipfs.PinIPFSBlockToW3S(ctx, ipfsNode, w3stoken, blk)

	pcid, err := ipfs.PutIPFSDAGBlockToW3S(ctx, ipfsNode, w3stoken, blk)
	log.Infof("Put block: %v", pcid)

	ipfsShutdown()
	return err
}
