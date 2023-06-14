package feed

import (
	"bytes"
	"context"
	"encoding/json"
	"os"

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
func CreateProfile(ctx context.Context, user User) error {
	log.Infof("creating patr profile for %s...", user.Did)
	node.PanicIfNotInitialized()
	ipfsNode, ipfsShutdown, err := ipfs.StartIPFSNode(ctx, node.CurrentConfig.PrivKey, node.CurrentConfig.Pubkey)
	if err != nil {
		return err
	}
	profile := Profile{Did: "foo"}
	n := bindnode.Wrap(&profile, nil)
	var buf bytes.Buffer
	err = dagjson.Encode(n, &buf)
	if err != nil {
		log.Errorf("error encoding DAG node for profile %v as DAG-JSON: %v", profile.Did, err)
		ipfsShutdown()
		return err
	}
	cidprefix := cid.Prefix{
		Version:  1, // Usually '1'.
		Codec:    cid.DagJSON,
		MhType:   mh.SHA3_384, // 0x15 means "sha3-384" -- See the multicodecs table: https://github.com/multiformats/multicodec/
		MhLength: 48,          // sha3-384 hash has a 48-byte sum.
	}
	xcid, err := cidprefix.Sum(buf.Bytes())
	if err != nil {
		log.Errorf("error creating CID for DAG node for profile %v as DAG-JSON: %v", profile.Did, err)
		ipfsShutdown()
		return err
	}
	blk, err := blocks.NewBlockWithCid(buf.Bytes(), xcid)
	if err != nil {
		log.Errorf("error creating IPFS block for DAG node for profile %v as DAG-JSON: %v", profile.Did, err)
		ipfsShutdown()
		return err
	}
	log.Infof("IPFS block cid for DAG node for profile %s : %s", profile.Did, blk.Cid().String())
	err = ipfsNode.Dag().Pinning().Add(ctx, &ipldlegacy.LegacyNode{blk, n})
	if err != nil {
		log.Errorf("error pinning IPFS block %v for DAG node for profile %v: %v", blk.Cid(), profile.Did, err)
		ipfsShutdown()
		return err
	}
	_, err = ipfs.PutIPFSDAGBlockToW3S(ctx, ipfsNode, node.CurrentConfig.W3SSecretKey, blk)

	ipfsShutdown()
	return err
}
