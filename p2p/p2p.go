package p2p

import (
	"bufio"
	"encoding/json"

	logging "github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/allisterb/patr/blockchain"
	"github.com/allisterb/patr/did"
	"github.com/allisterb/patr/ipfs"
)

type DM struct {
	Did     string
	Content string
}

var log = logging.Logger("patr/p2p")

func SetDMStreamHandler(ipfscore ipfs.IPFSCore, apikey string) {
	ipfscore.Node.PeerHost.SetStreamHandler(protocol.ID("patrchat/0.1"), func(s network.Stream) {
		DMHandler(s, apikey)
	})
}

func DMHandler(_s network.Stream, apiKey string) {
	log.Infof("Incoming DM stream from %v...", _s.Conn().RemotePeer())
	_rw := bufio.NewReadWriter(bufio.NewReader(_s), bufio.NewWriter(_s))
	go func(s network.Stream, rw *bufio.ReadWriter) {
		str, err := rw.ReadString(byte(0))
		if err != nil {
			log.Errorf("error reading DM data from stream: %v", err)
			return
		}
		dm := DM{}
		json.Unmarshal([]byte(str), &dm)
		if !did.IsValid(dm.Did) {
			log.Errorf("The DID %s in the DM is not valid")
			return
		}
		did, _ := did.Parse(dm.Did)
		n, err := blockchain.ResolveENS(did.ID.ID, apiKey)
		if err != nil {
			log.Errorf("could not resolve ENS name %s: %v", did.ID.ID, err)
		}
		pid, err := ipfs.GetIPFSNodeIdentityFromPublicKeyName(n.IPFSPubKey)
		if err != nil {
			log.Errorf("could not get IPFS node identity from string %s: %v", n.IPFSPubKey, err)
			return
		}
		if s.Conn().RemotePeer() != pid {
			log.Errorf("the remote peer ID %v does not match the DID peer ID %v for %s", s.Conn().RemotePeer(), pid, did.ID.ID)
			return
		}
		log.Infof("the remote peer ID %v matches the DID peer ID %v for %s", s.Conn().RemotePeer(), pid, did.ID.ID)
		log.Infof("direct message from %v: %s", did.ID.ID, dm.Content)
	}(_s, _rw)
}

func EventQueryHandler(s network.Stream) {

}
