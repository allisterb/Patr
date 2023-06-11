package did

import (
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
