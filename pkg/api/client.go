package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"reflect"
	"strconv"
	"time"

	"github.com/google/jsonapi"
	"github.com/immune-gmbh/agent/v3/pkg/typevisit"
	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

func errIsClientSide(err error) bool {
	// client side errors do not retry requests
	return errors.Is(err, FormatError) || errors.Is(err, AuthError) || errors.Is(err, PaymentError)
}

var hashBlobVisitor *typevisit.TypeVisitorTree

func init() {
	// construct a type visitor tree for re-use
	tvt, err := typevisit.New(&FirmwareProperties{}, HashBlob{}, "")
	if err != nil {
		panic(err)
	}
	hashBlobVisitor = tvt
}

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
	AgentVersion       string
}

func NewClient(base *url.URL, ca *x509.Certificate, agentVersion string) Client {
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
		AgentVersion:       agentVersion,
	}
}

func (c *Client) Enroll(ctx context.Context, enrollToken string, enroll Enrollment) ([]*EncryptedCredential, error) {
	log.Trace().Msg("enrolling with SaaS")
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
	payload, err := c.Post(ctx, "enroll", doc, nil)
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

func handleHashBlob(blobs map[string][]byte, blob *HashBlob, encoder *zstd.Encoder) {
	// only compress data if it is at least 1KiB
	// when compression is moved from per-member to zstd compressing the whole HTTP stream then this should change as follows:
	// only move the data to OOB when the length of the base64 encoded data would be larger than the length of the unencoded data plus the hash
	if len(blob.Data) > 1023 && encoder != nil {
		sum := sha256.Sum256(blob.Data)
		blob.Sha256 = Buffer(sum[:])
		blob.ZData = encoder.EncodeAll(blob.Data, make([]byte, 0, len(blob.Data)))
	}

	if len(blob.ZData) > 0 && len(blob.Sha256) == 32 {
		blobs[hex.EncodeToString(blob.Sha256)] = blob.ZData
		blob.ZData = nil
		blob.Data = nil
	}
}

// ProcessFirmwarePropertiesHashBlobs compresses and strips hash blobs from the given firmware properties only leaving their hashes; the blobs can then be transmitted out-of-band
func ProcessFirmwarePropertiesHashBlobs(fw *FirmwareProperties) map[string][]byte {
	// without opts this can't err and thus the panic signals a programming error
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		panic(err)
	}

	blobs := make(map[string][]byte)
	hashBlobVisitor.Visit(fw, func(v reflect.Value, opts typevisit.FieldOpts) {
		// we need a special treatment for maps because there are no pointers to map elements
		if v.Kind() == reflect.Map {
			mi := v.MapRange()
			for mi.Next() {
				hb := mi.Value().Interface().(HashBlob)
				handleHashBlob(blobs, &hb, encoder)
				v.SetMapIndex(mi.Key(), reflect.ValueOf(hb))
			}
		} else {
			hb := v.Addr().Interface().(*HashBlob)
			handleHashBlob(blobs, hb, encoder)
		}
	})
	if len(blobs) == 0 {
		return nil
	}
	return blobs
}

func (c *Client) Attest(ctx context.Context, quoteCredential string, ev Evidence, multiPartFiles map[string][]byte) (*Appraisal, string, error) {
	log.Trace().Msg("attesting to SaaS")
	c.Auth = quoteCredential

	pdoc, err := jsonapi.Marshal(&ev)
	if err != nil {
		return nil, "", err
	}
	doc, ok := pdoc.(*jsonapi.OnePayload)
	if !ok {
		return nil, "", err
	}
	doc.Data.Type = "evidence"

	payload, err := c.Post(ctx, "attest", doc, multiPartFiles)
	if err != nil {
		return nil, "", err
	}

	// attestation in progress w/o result
	if payload == nil {
		return nil, "", nil
	}

	one, ok := payload.(*jsonapi.OnePayload)
	if !ok || one.Data == nil {
		return nil, "", FormatError
	}

	// we might get a device type back which contains a self-web link but then we don't want to unmarshal it
	var appr *Appraisal
	var buf []byte
	if one.Data.Type == "appraisals" {
		buf, err = json.Marshal(one.Data.Attributes)
		if err != nil {
			return nil, "", err
		}
		appr = &Appraisal{}
		err = json.Unmarshal(buf, appr)
	}

	var webLink string
	if one.Data.Links != nil {
		if v, ok := (*one.Data.Links)["self-web"]; ok {
			webLink, _ = v.(string)
		}
	}

	return appr, webLink, err
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

func (c *Client) Post(ctx context.Context, route string, doc interface{}, multiPartFiles map[string][]byte) (jsonapi.Payloader, error) {
	var err error
	var ev jsonapi.Payloader

	for i := 0; i < 3; i += 1 {
		if i > 0 {
			log.Warn().Msgf("Retry %v/3", i+1)
		}
		ctx, cancel := context.WithTimeout(ctx, c.PostRequestTimeout)
		defer cancel()
		ev, err = c.doPost(ctx, route, doc, multiPartFiles)

		if err == nil || errIsClientSide(err) {
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
		if i > 0 {
			log.Warn().Msgf("Retry %v/3", i+1)
		}
		ctx, cancel := context.WithTimeout(ctx, c.HTTPRequestTimeout)
		defer cancel()
		ev, err = c.doGet(ctx, route, ifModifiedSince)

		if err == nil || errIsClientSide(err) {
			return ev, err
		}
	}

	return ev, err
}

func (c *Client) doPost(ctx context.Context, route string, doc interface{}, multiPartFiles map[string][]byte) (jsonapi.Payloader, error) {
	endpoint := *c.Base
	endpoint.Path = path.Join(endpoint.Path, route)

	pipe := new(bytes.Buffer)
	gz := gzip.NewWriter(pipe)
	var err error
	var writer *multipart.Writer
	if len(multiPartFiles) > 0 {
		writer = multipart.NewWriter(gz)

		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="evidencebody"; filename="evidencebody"`)
		h.Set("Content-Type", "application/json")
		part, err := writer.CreatePart(h)
		if err != nil {
			return nil, FormatError
		}
		err = json.NewEncoder(part).Encode(doc)
		if err != nil {
			return nil, FormatError
		}

		// encode multipart files
		i := 0
		for k, v := range multiPartFiles {
			iow, err := writer.CreateFormFile(strconv.Itoa(i), k)
			if err != nil {
				return nil, err
			}
			_, err = io.Copy(iow, bytes.NewReader(v))
			if err != nil {
				return nil, err
			}
			i++
		}

		writer.Close()
	} else {
		err = json.NewEncoder(gz).Encode(doc)
		if err != nil {
			return nil, FormatError
		}
	}
	gz.Flush()

	log.Debug().Msgf("POST %s", endpoint.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), pipe)
	if err != nil {
		return nil, FormatError
	}
	if len(multiPartFiles) > 0 {
		req.Header.Add("Content-Type", writer.FormDataContentType())
	} else {
		req.Header.Add("Content-Type", "application/json")
	}
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

	log.Debug().Msgf("GET %s", endpoint.String())
	return c.doRequest(req)
}

func (c *Client) doRequest(req *http.Request) (jsonapi.Payloader, error) {
	if c.Auth != "" {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.Auth))
	}

	// this should tell all relaying servers to send error pages as json
	// API server uses json by default anyway
	req.Header.Add("Accept", "application/json")
	req.Header.Add("X-immune-agent-ver", c.AgentVersion)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		log.Debug().Err(err).Msg("HTTP response")
		return nil, NetworkError
	}
	defer resp.Body.Close()

	code := resp.StatusCode
	log.Debug().Msgf("HTTP status: %d", code)

	var readBody bool
	var retErr error
	debugging := log.Logger.GetLevel() == zerolog.TraceLevel

	switch {
	// server tells us to use cached response and sends no body
	case code == http.StatusNotModified:
		retErr = nil
		readBody = false

	// request is processed
	case code == http.StatusAccepted:
		fallthrough

	// default is to read a body for good status codes
	case code < 400:
		retErr = nil
		readBody = true

	case code == http.StatusUnauthorized:
		retErr = AuthError
		readBody = debugging

	case code == http.StatusPaymentRequired:
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
		respBytes, err := io.ReadAll(resp.Body)
		log.Debug().Msgf("HTTP body: %s", string(respBytes)) // always try to print anything we got
		if err != nil {
			log.Debug().Err(err).Msg("reading server response")
			return nil, NetworkError
		}

		if ctype, ok := resp.Header["Content-Type"]; ok {
			ok = false
			for _, val := range ctype {
				ok = (val == "application/vnd.api+json") || (val == "application/json")
				if ok {
					break
				}
			}
			if !ok {
				if retErr == nil {
					retErr = FormatError
				}
				log.Debug().Msgf("Wrong HTTP content type: %v", ctype)
				return nil, retErr
			}
		}

		var one jsonapi.OnePayload
		if err = json.Unmarshal(respBytes, &one); err != nil {
			var many jsonapi.ManyPayload
			if err = json.Unmarshal(respBytes, &many); err != nil {
				log.Debug().Err(err).Msg("parsing server response")
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
