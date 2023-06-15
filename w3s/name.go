package w3s

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ipfs/go-cid"
)

func (c *client) GetName(ctx context.Context, name string) (cid.Cid, error) {
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
