package feed

import (
	"bytes"
	"context"
	"fmt"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	cbornode "github.com/ipfs/go-ipld-cbor"
	ipldlegacy "github.com/ipfs/go-ipld-legacy"
	logging "github.com/ipfs/go-log/v2"
	"github.com/ipld/go-ipld-prime/codec/dagjson"
	"github.com/ipld/go-ipld-prime/datamodel"
	"github.com/ipld/go-ipld-prime/fluent/qp"

	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/basicnode"

	mh "github.com/multiformats/go-multihash"

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
	ipfscore, err := ipfs.StartIPFSNode(ctx, node.CurrentConfig.IPFSPrivKey, node.CurrentConfig.IPFSPubKey)
	if err != nil {
		return err
	}
	ipfscore.W3S.SetAuthToken(node.CurrentConfig.W3SSecretKey)
	feed := Feed{Did: node.CurrentConfig.Did}
	dagnode, err := qp.BuildMap(basicnode.Prototype.Any, 4, func(ma datamodel.MapAssembler) {
		qp.MapEntry(ma, "Did", qp.String(feed.Did))
		qp.MapEntry(ma, "Events", qp.Map(100, func(ma datamodel.MapAssembler) {
			for k, v := range feed.Events {
				qp.MapEntry(ma, k, qp.Link(v))
			}
		}))
	})
	if err != nil {
		return fmt.Errorf("error creating IPLD node from feed for %s: %v", feed.Did, err)
	}
	var buf bytes.Buffer
	err = dagjson.Encode(dagnode, &buf)
	if err != nil {
		log.Errorf("error encoding DAG node for feed %v as DAG-JSON: %v", feed.Did, err)
		ipfscore.Shutdown()
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
		ipfscore.Shutdown()
		return err
	}
	blk, err := blocks.NewBlockWithCid(buf.Bytes(), xcid)
	if err != nil {
		log.Errorf("error creating IPFS block for DAG node for feed %v as DAG-JSON: %v", feed.Did, err)
		ipfscore.Shutdown()
		return err
	}
	log.Infof("IPFS block cid for DAG node for feed %s : %s", feed.Did, blk.Cid())
	err = ipfscore.Api.Dag().Pinning().Add(ctx, &ipldlegacy.LegacyNode{blk, dagnode})
	if err != nil {

		log.Errorf("error pinning IPFS block %v for DAG node for feed %v: %v", blk.Cid(), feed.Did, err)
		ipfscore.Shutdown()
		return err
	}
	ipfs.PublishIPNSRecordForDAGNode(ctx, ipfscore.Api, blk.Cid())
	_, err = ipfs.PinIPLDBlockToW3S(ctx, ipfscore.Api, node.CurrentConfig.W3SSecretKey, blk)
	if err != nil {
		log.Errorf("could not pin IPFS block %v using Web3.Storage service")
		ipfscore.Shutdown()
		return err
	}
	_ = ipfs.PublishIPNSRecordForDAGNodeToW3S(ctx, node.CurrentConfig.W3SSecretKey, blk.Cid(), node.CurrentConfig.IPFSPrivKey, node.CurrentConfig.IPFSPubKey)
	ipfscore.Shutdown()
	return err
}

func CreateEvent(ctx context.Context, text string) {

	//e := nostr.CreateBlankEvent()
	//e.
}
