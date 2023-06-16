package did

import (
	"fmt"

	logging "github.com/ipfs/go-log/v2"
	ssi "github.com/nuts-foundation/go-did"
	godid "github.com/nuts-foundation/go-did/did"
)

var log = logging.Logger("patr/did")

func Parse(str string) (*godid.Document, error) {
	didID, err := godid.ParseDID(str)
	if err != nil {
		return &godid.Document{}, err
	}
	doc := &godid.Document{
		Context: []ssi.URI{godid.DIDContextV1URI()},
		ID:      *didID,
	}
	return doc, err
}

func IsValid(str string) (bool, error) {
	d, err := Parse(str)
	if err != nil {
		log.Errorf("Could not parse DID %s: %v", str, err)
		return false, err
	} else if d.ID.Method != "ens" {
		log.Errorf("invalid DID: %s. Only ENS DIDs are supported currently", str)
		return false, fmt.Errorf("INVALID DID: %s. ONLY ENS DIDS ARE SUPPORTED CURRENTLY", str)
	} else {
		return true, nil
	}
}
