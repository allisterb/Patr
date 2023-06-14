package w3s

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ipfs/go-cid"
)

// TODO: retry
func (c *client) sendCar(ctx context.Context, r io.Reader) (cid.Cid, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.endpoint+"/car", r)
	if err != nil {
		return cid.Undef, err
	}
	req.Header.Add("Content-Type", "application/car")
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
		Cid string `json:"cid"`
	}
	err = d.Decode(&out)
	if err != nil {
		return cid.Undef, err
	}
	return cid.Parse(out.Cid)
}

// PutCar uploads a CAR (Content Addressable Archive) to Web3.Storage.
func (c *client) PutCar(ctx context.Context, car io.Reader) (cid.Cid, error) {
	root, err := c.sendCar(ctx, car)
	return root, err
}
