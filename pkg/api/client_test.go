package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/jsonapi"
	"github.com/stretchr/testify/assert"
)

var baseURL, _ = url.Parse("https://test.ser/ver")

type RoundTripFunc func(req *http.Request) *http.Response

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func NewTestClient(fn RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(fn),
	}
}

func TestClient_Configuration(t *testing.T) {
	targetURL, err := url.Parse(baseURL.String() + "/configuration")
	assert.NoError(t, err)

	var cfg Configuration
	cfg.Root.Public.Type = tpm2.AlgECC
	cfg.Root.Public.ECCParameters = &tpm2.ECCParams{}
	tmp, err := jsonapi.Marshal(&cfg)
	assert.NoError(t, err)
	jsonCfg, err := json.Marshal(tmp)
	assert.NoError(t, err)

	client200 := NewTestClient(func(req *http.Request) *http.Response {
		assert.Empty(t, req.Header.Get("If-modified-since"))
		assert.Equal(t, req.URL.String(), targetURL.String())
		return &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewBuffer(jsonCfg)),
			Header:     make(http.Header),
		}
	})

	// round time to nearest time value represented by RFC1123
	modifiedSince, err := time.Parse(time.RFC1123, time.Now().Format(time.RFC1123))
	assert.NoError(t, err)

	client304 := NewTestClient(func(req *http.Request) *http.Response {
		modSinceHeader := req.Header.Get("If-modified-since")
		assert.NotNil(t, modSinceHeader)
		tm, err := time.Parse(time.RFC1123, modSinceHeader)
		assert.NoError(t, err)
		tm.Equal(modifiedSince)

		assert.Equal(t, req.URL.String(), targetURL.String())
		return &http.Response{
			StatusCode: 304,
			// Send response to be tested
			Body: ioutil.NopCloser(bytes.NewBuffer(nil)),
			// Must be set to non-nil value or it panics
			Header: make(http.Header),
		}
	})

	type fields struct {
		HTTP *http.Client
		Base *url.URL
		Auth string
	}
	type args struct {
		ctx        context.Context
		lastUpdate *time.Time
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Configuration
		wantErr bool
	}{
		{
			name: "configuration get",
			fields: fields{
				HTTP: client200,
				Base: baseURL,
			},
			args: args{
				ctx: context.Background(),
			},
			want: &cfg,
		},
		{
			name: "configuration get if-modified-since",
			fields: fields{
				HTTP: client304,
				Base: baseURL,
			},
			args: args{
				ctx:        context.Background(),
				lastUpdate: &modifiedSince,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				HTTP: tt.fields.HTTP,
				Base: tt.fields.Base,
				Auth: tt.fields.Auth,
			}
			got, err := c.Configuration(tt.args.ctx, tt.args.lastUpdate)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Configuration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Client.Configuration() = %v, want %v", got, tt.want)
			}
		})
	}
}
