package feed

import (
	"bytes"
	"context"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	cbornode "github.com/ipfs/go-ipld-cbor"
	ipldlegacy "github.com/ipfs/go-ipld-legacy"
	logging "github.com/ipfs/go-log/v2"
	"github.com/ipld/go-ipld-prime/codec/dagjson"
	"github.com/ipld/go-ipld-prime/datamodel"
	"github.com/ipld/go-ipld-prime/fluent/qp"
	"github.com/ipld/go-ipld-prime/linking"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/ipld/go-ipld-prime/node/bindnode"
	mh "github.com/multiformats/go-multihash"
	"github.com/nbd-wtf/go-nostr"

	"github.com/allisterb/patr/blockchain"
	"github.com/allisterb/patr/did"
	"github.com/allisterb/patr/ipfs"
	"github.com/allisterb/patr/node"
)

type Feed struct {
	Did    string
	Events map[string]cidlink.Link
}

var log = logging.Logger("patr/feed")

func init() {
	cbornode.RegisterCborType(Feed{})
}

func CreateFeed(ctx context.Context) error {
	d, err := did.Parse(node.CurrentConfig.Did)
	if err != nil {
		log.Errorf("could not parse DID %s: %v", node.CurrentConfig.Did, err)
		return err
	}
	log.Infof("creating patr feed for %s...", node.CurrentConfig.Did)
	node.PanicIfNotInitialized()
	_, err = blockchain.ResolveENS(d.ID.ID, node.CurrentConfig.InfuraSecretKey)
	if err != nil {
		log.Errorf("could not resolve ENS name %s", node.CurrentConfig.Did)
		return err
	}
	_, ipfsNode, ipfsShutdown, err := ipfs.StartIPFSNode(ctx, node.CurrentConfig.IPFSPrivKey, node.CurrentConfig.IPFSPubKey)
	if err != nil {
		return err
	}
	feed := Feed{Did: node.CurrentConfig.Did}
	//dagnode := bindnode.Wrap(&feed, nil)
	dagnode, err := qp.BuildMap(basicnode.Prototype.Any, 4, func(ma datamodel.MapAssembler) {
		qp.MapEntry(ma, "Did", qp.String(feed.Did))
		qp.MapEntry(ma, "Events", qp.Map(100, func(ma datamodel.MapAssembler) {
			for k, v := range feed.Events {
				qp.MapEntry(ma, k, qp.Link(v))
			}
		}))
	})
	var buf bytes.Buffer
	err = dagjson.Encode(dagnode, &buf)
	if err != nil {
		log.Errorf("error encoding DAG node for feed %v as DAG-JSON: %v", feed.Did, err)
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
		log.Errorf("error creating CID for DAG node for feed %v as DAG-JSON: %v", feed.Did, err)
		ipfsShutdown()
		return err
	}
	blk, err := blocks.NewBlockWithCid(buf.Bytes(), xcid)
	if err != nil {
		log.Errorf("error creating IPFS block for DAG node for feed %v as DAG-JSON: %v", feed.Did, err)
		ipfsShutdown()
		return err
	}
	log.Infof("IPFS block cid for DAG node for feed %s : %s", feed.Did, blk.Cid())
	err = ipfsNode.Dag().Pinning().Add(ctx, &ipldlegacy.LegacyNode{blk, dagnode})
	if err != nil {

		log.Errorf("error pinning IPFS block %v for DAG node for feed %v: %v", blk.Cid(), feed.Did, err)
		ipfsShutdown()
		return err
	}
	ipfs.PublishIPNSRecordForDAGNode(ctx, ipfsNode, blk.Cid())
	_, err = ipfs.PutIPFSDAGBlockToW3S(ctx, ipfsNode, node.CurrentConfig.W3SSecretKey, blk)
	if err != nil {
		log.Errorf("could not pin IPFS block %v using Web3.Storage service")
		ipfsShutdown()
		return err
	}
	err = ipfs.PublishIPNSRecordForDAGNodeToW3S(ctx, node.CurrentConfig.W3SSecretKey, blk.Cid(), node.CurrentConfig.IPFSPrivKey, node.CurrentConfig.IPFSPubKey)
	ipfsShutdown()
	return err
}

func SaveNostrEvent(ctx context.Context, evt nostr.Event, ipfscore ipfs.IPFSCore) error {

	store := ipfs.IPFSLinkStorage{
		//ipfs: ipfscore.api,
	}
	//ipfscore.Api.Dag().
	lsys := cidlink.DefaultLinkSystem()
	lsys.SetReadStorage(&store)
	lsys.SetWriteStorage(&store)
	lp := cidlink.LinkPrototype{
		Prefix: cid.Prefix{
			Version:  1,           // Usually '1'.
			Codec:    cid.DagJSON, // 0x71 means "dag-cbor" -- See the multicodecs table: https://github.com/multiformats/multicodec/
			MhType:   mh.SHA3_384, // 0x20 means "sha2-512" -- See the multicodecs table: https://github.com/multiformats/multicodec/
			MhLength: 48,          // sha2-512 hash has a 64-byte sum.
		}}
	dagnode := bindnode.Wrap(&evt, nil)
	_, err := lsys.Store(linking.LinkContext{}, lp, dagnode)
	//lsys.Load()

	return err
}
