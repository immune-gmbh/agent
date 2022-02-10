package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/google/jsonapi"
	"github.com/sirupsen/logrus"
)

const DefaultHTTPRequestTimeoutSec = 30
const DefaultPostRequestTimeoutSec = 60

var (
	ServerError  = errors.New("API server error")
	NetworkError = errors.New("Connection error")
	AuthError    = errors.New("Authentication token invalid")
	FormatError  = errors.New("Data invalid")
	PaymentError = errors.New("Payment required")
)

func Cookie(rng io.Reader) (string, error) {
	buf := make([]byte, 32)
	if l, err := rng.Read(buf); err != nil {
		return "", err
	} else if l != len(buf) {
		return "", errors.New("no random")
	} else {
		return base64.StdEncoding.EncodeToString(buf), nil
	}
}

type Client struct {
	HTTP               *http.Client
	Base               *url.URL
	Auth               string
	HTTPRequestTimeout time.Duration // Timeout for all HTTP requests except POST
	PostRequestTimeout time.Duration // POST requests may contain lots of data and need a different timeout
}

func NewClient(base *url.URL, ca *x509.Certificate) Client {
	var tlsConfig *tls.Config

	if ca != nil {
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		tlsConfig = &tls.Config{
			RootCAs: pool,
		}
	}

	return Client{
		HTTP:               &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}},
		Base:               base,
		HTTPRequestTimeout: time.Second * DefaultHTTPRequestTimeoutSec,
		PostRequestTimeout: time.Second * DefaultPostRequestTimeoutSec,
	}
}

func (c *Client) Enroll(ctx context.Context, enrollToken string, enroll Enrollment) ([]*EncryptedCredential, error) {
	logrus.Traceln("enrolling with SaaS")
	c.Auth = enrollToken

	// encode enrollment
	pdoc, err := jsonapi.Marshal(&enroll)
	if err != nil {
		return nil, err
	}
	doc, ok := pdoc.(*jsonapi.OnePayload)
	if !ok {
		return nil, err
	}
	doc.Data.Type = "enrollment"

	// decode credentials
	payload, err := c.Post(ctx, "enroll", doc)
	if err != nil {
		return nil, err
	}
	many, ok := payload.(*jsonapi.ManyPayload)
	if !ok {
		return nil, FormatError
	}

	var attribs []map[string]interface{} = make([]map[string]interface{}, len(many.Data))
	for i, d := range many.Data {
		attribs[i] = d.Attributes
	}
	buf, err := json.Marshal(attribs)
	if err != nil {
		return nil, err
	}
	var creds []*EncryptedCredential
	err = json.Unmarshal(buf, &creds)

	return creds, err
}

func (c *Client) Attest(ctx context.Context, quoteCredential string, ev Evidence) (*Appraisal, error) {
	logrus.Traceln("attesting to SaaS")
	c.Auth = quoteCredential

	pdoc, err := jsonapi.Marshal(&ev)
	if err != nil {
		return nil, err
	}
	doc, ok := pdoc.(*jsonapi.OnePayload)
	if !ok {
		return nil, err
	}
	doc.Data.Type = "evidence"

	payload, err := c.Post(ctx, "attest", doc)
	if err != nil {
		return nil, err
	}

	one, ok := payload.(*jsonapi.OnePayload)
	if !ok || one.Data == nil {
		return nil, FormatError
	}
	buf, err := json.Marshal(one.Data.Attributes)
	if err != nil {
		return nil, err
	}
	var appr Appraisal
	err = json.Unmarshal(buf, &appr)

	return &appr, err
}

// Client.Configuration returns a nil Configuration when lastUpdate is not nil and the server tells us to use a cached configuration
func (c *Client) Configuration(ctx context.Context, lastUpdate *time.Time) (*Configuration, error) {
	c.Auth = ""

	payload, err := c.Get(ctx, "configuration", lastUpdate)
	if err != nil {
		return nil, err
	}

	// this means we don't have a config and the server didn't serve one
	if lastUpdate != nil && payload == nil {
		return nil, nil
	}

	one, ok := payload.(*jsonapi.OnePayload)
	if !ok || one.Data == nil {
		return nil, FormatError
	}
	buf, err := json.Marshal(one.Data.Attributes)
	if err != nil {
		return nil, err
	}
	var cfg Configuration
	err = json.Unmarshal(buf, &cfg)

	return &cfg, err
}

func (c *Client) Post(ctx context.Context, route string, doc interface{}) (jsonapi.Payloader, error) {
	var err error
	var ev jsonapi.Payloader

	for i := 0; i < 3; i += 1 {
		ctx, cancel := context.WithTimeout(ctx, c.PostRequestTimeout)
		defer cancel()
		ev, err = c.doPost(ctx, route, doc)

		// our post requests don't use if-modified-since headers and thus do not allow empty bodies
		if ev == nil && err == nil {
			return nil, FormatError
		}

		if err == nil || errors.Is(err, FormatError) || errors.Is(err, AuthError) {
			return ev, err
		}
	}

	return ev, err
}

// Client.Get returns a nil jsonapi.Payloader if the server sent no body in case of a 304
func (c *Client) Get(ctx context.Context, route string, ifModifiedSince *time.Time) (jsonapi.Payloader, error) {
	var err error
	var ev jsonapi.Payloader

	for i := 0; i < 3; i += 1 {
		ctx, cancel := context.WithTimeout(ctx, c.HTTPRequestTimeout)
		defer cancel()
		ev, err = c.doGet(ctx, route, ifModifiedSince)

		if err == nil || errors.Is(err, FormatError) || errors.Is(err, AuthError) {
			return ev, err
		}
	}

	return ev, err
}

func (c *Client) doPost(ctx context.Context, route string, doc interface{}) (jsonapi.Payloader, error) {
	endpoint := *c.Base
	endpoint.Path = path.Join(endpoint.Path, route)

	pipe := new(bytes.Buffer)
	gz := gzip.NewWriter(pipe)
	err := json.NewEncoder(gz).Encode(doc)
	gz.Flush()

	if err != nil {
		return nil, FormatError
	}
	logrus.Debugf("POST %s", endpoint.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), pipe)
	if err != nil {
		return nil, FormatError
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Encoding", "gzip")

	return c.doRequest(req)
}

func (c *Client) doGet(ctx context.Context, route string, ifModifiedSince *time.Time) (jsonapi.Payloader, error) {
	endpoint := *c.Base
	endpoint.Path = path.Join(endpoint.Path, route)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, FormatError
	}

	if ifModifiedSince != nil {
		req.Header.Set("If-Modified-Since", ifModifiedSince.UTC().Format(http.TimeFormat))
	}

	logrus.Debugf("GET %s", endpoint.String())
	return c.doRequest(req)
}

func (c *Client) doRequest(req *http.Request) (jsonapi.Payloader, error) {
	if c.Auth != "" {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.Auth))
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		logrus.Debugf("HTTP response: %s", err)
		return nil, NetworkError
	}
	defer resp.Body.Close()

	code := resp.StatusCode
	logrus.Debugf("HTTP status: %d", code)

	var readBody bool
	var retErr error
	debugging := logrus.GetLevel() == logrus.TraceLevel

	switch {
	case code == 304:
		// server tells us to use cached response and sends no body
		retErr = nil
		readBody = false
	case code <= 400:
		retErr = nil
		readBody = true
	case code == 401:
		retErr = AuthError
		readBody = debugging
	case code == 402:
		retErr = PaymentError
		readBody = debugging
	case code < 500:
		retErr = FormatError
		readBody = debugging
	case code < 600:
		retErr = ServerError
		readBody = debugging
	default:
		retErr = fmt.Errorf("unexpected HTTP status code: %d", code)
		readBody = false
	}

	if readBody {
		respBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logrus.Debugf("Reading server response: %s", err)
			return nil, NetworkError
		}

		logrus.Debugf("HTTP body: %s", string(respBytes))

		var one jsonapi.OnePayload
		if err = json.Unmarshal(respBytes, &one); err != nil {
			var many jsonapi.ManyPayload
			if err = json.Unmarshal(respBytes, &many); err != nil {
				logrus.Debugf("Parsing server response: %s", err)
				return nil, ServerError
			} else {
				return &many, retErr
			}
		} else {
			return &one, retErr
		}
	}

	return nil, retErr
}
