// Copyright Red Hat

package dex

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	api "github.com/dexidp/dex/api/v2"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Options keeps some configuration options for Dex client
type Options struct {
	// HostAndPort host name and port of gRPC server
	HostAndPort string
	// ClientCrt TLS certificate for gRPC client
	CrtBuffer *bytes.Buffer
	// ClientKey TLS certificate key for gRPC client
	KeyBuffer *bytes.Buffer
	// ClientCA self signed CA certificate for gRPC TLS connection
	CABuffer *bytes.Buffer
}

// APIClient represent a client wrapper for Dex
type APIClient struct {
	dex api.DexClient
	cc  *grpc.ClientConn
}

func NewClientPEM(opts *Options) (*APIClient, error) {
	certPool := x509.NewCertPool()
	appended := certPool.AppendCertsFromPEM(opts.CABuffer.Bytes())
	if !appended {
		return nil, errors.New("failed to append the CA cert to the certs pool")
	}

	clientCert, err := tls.X509KeyPair(opts.CrtBuffer.Bytes(), opts.KeyBuffer.Bytes())
	if err != nil {
		return nil, errors.Wrapf(err, "loading the client cert %q and private key %q",
			opts.CrtBuffer.Bytes(), opts.KeyBuffer.Bytes())
	}

	clientTLSConfig := &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{clientCert},
	}
	creds := credentials.NewTLS(clientTLSConfig)

	conn, err := grpc.Dial(opts.HostAndPort, grpc.WithTransportCredentials(creds), grpc.WithBlock(), grpc.FailOnNonTempDialError(true))
	if err != nil {
		return nil, errors.Wrapf(err, "opening the gRPC connection with server %q", opts.HostAndPort)
	}
	return &APIClient{
		dex: api.NewDexClient(conn),
		cc:  conn,
	}, nil
}

// GetServerInfo returns server info
func (c *APIClient) GetServerInfo(ctx context.Context) (string, error) {
	req := &api.VersionReq{}
	res, err := c.dex.GetVersion(ctx, req)
	if err != nil {
		return "", errors.Wrap(err, "failed to to get DEX version")
	}
	return res.Server, nil
}

type CreateClientError struct {
	ApiError      error
	AlreadyExists bool
}

// CreateClient a new OIDC client in Dex
func (c *APIClient) CreateClient(ctx context.Context, redirectUris []string, trustedPeers []string,
	public bool, name string, id string, logoURL string, secret string) (*api.Client, *CreateClientError) {
	req := &api.CreateClientReq{
		Client: &api.Client{
			RedirectUris: redirectUris,
			TrustedPeers: trustedPeers,
			Public:       public,
			Name:         name,
			LogoUrl:      logoURL,
			Secret:       secret,
			Id:           id,
		},
	}

	res, err := c.dex.CreateClient(ctx, req)
	if err != nil {
		return nil, &CreateClientError{errors.Wrap(err, "failed to create the OIDC client"), false}
	}

	if res.AlreadyExists {
		return nil, &CreateClientError{errors.Errorf("client %q already exists", id), true}
	}

	return res.Client, nil
}

// UpdateClient updates an already registered OIDC client
func (c *APIClient) UpdateClient(ctx context.Context, clientID string, redirectUris []string,
	trustedPeers []string, public bool, name string, logoURL string) error {
	req := &api.UpdateClientReq{
		Id:           clientID,
		RedirectUris: redirectUris,
		TrustedPeers: trustedPeers,
		Name:         name,
		LogoUrl:      logoURL,
	}
	res, err := c.dex.UpdateClient(ctx, req)
	if err != nil {
		return errors.Wrapf(err, "failed to update the client with id %q", clientID)
	}

	if res.NotFound {
		return fmt.Errorf("update did not find the client with id %q", clientID)
	}
	return nil
}

// DeleteClient deletes the client with given Id from Dex
func (c *APIClient) DeleteClient(ctx context.Context, id string) error {
	req := &api.DeleteClientReq{
		Id: id,
	}
	res, err := c.dex.DeleteClient(ctx, req)
	if err != nil {
		return errors.Wrapf(err, "failed to delete the client with id %q", id)
	}
	if res.NotFound {
		return fmt.Errorf("delete did not find the client with id %q", id)
	}
	return nil
}

// CloseConnection calls Close on the ClientConn
func (c *APIClient) CloseConnection() error {
	err := c.cc.Close()
	if err != nil {
		return errors.Wrapf(err, "error occurred closing the connection")
	}
	return nil
}
