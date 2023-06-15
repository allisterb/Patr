package w3s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	//ipns "github.com/ipfs/boxo/ipns"
	ipns_pb "github.com/ipfs/boxo/ipns/pb"
	"github.com/ipfs/go-cid"
)

type IPNSRecordData struct {
	key      string
	record   string
	hasV2Sig bool
	seqno    string
	validity string
}

func (c *client) GetName(ctx context.Context, name string) (*ipns_pb.IpnsEntry, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/name/%s", "https://name.web3.storage", name), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.cfg.token))
	req.Header.Add("X-Client", clientName)
	res, err := c.cfg.hc.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode == 404 {
		return nil, err
	} else if res.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected response status: %d", res.StatusCode)
	}

	d := json.NewDecoder(res.Body)
	var out struct {
		Value  string `json:"value"`
		Record string `json:"record"`
	}
	err = d.Decode(&out)
	if err != nil {
		return nil, err
	}
	ll, err := base64.StdEncoding.WithPadding(base64.StdPadding).DecodeString(out.Record)

	n := ipns_pb.IpnsEntry{}

	err = n.Unmarshal(ll)

	return &n, err
}

func (c *client) PublishName(ctx context.Context, name string) (cid.Cid, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/name/%s", "https://name.web3.storage", name), nil)
	if err != nil {
		return cid.Undef, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.cfg.token))
	req.Header.Add("X-Client", clientName)
	res, err := c.cfg.hc.Do(req)
	if err != nil {
		return cid.Undef, err
	}
	if res.StatusCode != 200 {
		return cid.Undef, fmt.Errorf("unexpected response status: %d", res.StatusCode)
	}
	d := json.NewDecoder(res.Body)
	var out struct {
		Value  string `json:"value"`
		Record string `json:"record"`
	}
	err = d.Decode(&out)
	if err != nil {
		return cid.Undef, err
	}
	//_, err := base64.StdEncoding.WithPadding(base64.StdPadding).DecodeString(out.Record)
	return cid.Parse(out.Value)
}
