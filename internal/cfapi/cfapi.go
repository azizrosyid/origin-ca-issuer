package cfapi

import (
	"context"
	"slices"
	"time"

	cloudflare "github.com/cloudflare/cloudflare-go/v2"
	"github.com/cloudflare/cloudflare-go/v2/option"
	"github.com/cloudflare/cloudflare-go/v2/origin_ca_certificates"
)

type Interface interface {
	Sign(context.Context, *SignRequest) (*SignResponse, error)
}

type Client struct {
	serviceKey []byte
	client     *cloudflare.Client
	endpoint   string
}

func New(serviceKey []byte, options ...option.RequestOption) *Client {
	opts := slices.Clone(options)
	opts = append(opts,
		option.WithUserServiceKey(string(serviceKey)),
		option.WithHeader("user-agent", "github.com/cloudflare/origin-ca-issuer"),
	)

	return &Client{
		client: cloudflare.NewClient(opts...),
	}
}

var WithClient = option.WithHTTPClient

type SignRequest struct {
	Hostnames []string `json:"hostnames"`
	Validity  int      `json:"requested_validity"`
	Type      string   `json:"request_type"`
	CSR       string   `json:"csr"`
}

type SignResponse struct {
	Id          string    `json:"id"`
	Certificate string    `json:"certificate"`
	Hostnames   []string  `json:"hostnames"`
	Expiration  time.Time `json:"expires_on"`
	Type        string    `json:"request_type"`
	Validity    int       `json:"requested_validity"`
	CSR         string    `json:"csr"`
}

func (c *Client) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	hostnames := make([]any, 0, len(req.Hostnames))
	for _, hostname := range req.Hostnames {
		hostnames = append(hostnames, hostname)
	}

	_, err := c.client.OriginCACertificates.New(ctx, origin_ca_certificates.OriginCACertificateNewParams{
		Csr:               cloudflare.F(req.CSR),
		Hostnames:         cloudflare.F(hostnames),
		RequestType:       cloudflare.F(origin_ca_certificates.OriginCACertificateNewParamsRequestType(req.Type)),
		RequestedValidity: cloudflare.F(origin_ca_certificates.OriginCACertificateNewParamsRequestedValidity(req.Validity)),
	})

	if err != nil {
		return nil, err
	}

	return nil, nil
}
