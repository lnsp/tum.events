package kv

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInMemoryStoreAtomicInt(t *testing.T) {
	kv := NewInMemoryStore()

	got, err := kv.AtomicInc("default")

	assert.NoError(t, err)
	assert.Equal(t, int64(1), got)
}

func TestInMemoryStoreAtomicIntTwice(t *testing.T) {
	kv := NewInMemoryStore()

	kv.AtomicInc("default")
	got, err := kv.AtomicInc("default")

	assert.NoError(t, err)
	assert.Equal(t, int64(2), got)
}

func TestInMemoryStorePutAndFetch(t *testing.T) {
	kv := NewInMemoryStore()

	err := kv.Put("default", []byte("value"))
	assert.NoError(t, err)

	got, err := kv.Fetch("default")
	assert.NoError(t, err)

	assert.Equal(t, []byte("value"), got)
}

func TestInMemoryStoreList(t *testing.T) {
	kv := NewInMemoryStore()

	kv.Put("aaa", []byte("out-of-range"))
	kv.Put("key0", []byte("in-range"))
	kv.Put("key1", []byte("in-range"))
	kv.Put("zzz", []byte("out-of-range"))

	keys, hash, err := kv.List("key")
	assert.NoError(t, err)
	assert.Equal(t, []string{"key0", "key1"}, keys)
	assert.Equal(t, []byte{0x7d, 0xfc, 0x67, 0xe2, 0x6c, 0xb6, 0xee, 0x43, 0xc5, 0xb5, 0x0d, 0x30, 0x33, 0x5f, 0xa0, 0x43, 0x43, 0x4f, 0xb6, 0x84}, hash)
}

var defaultCredentials = Credentials{
	Token:   "token",
	Project: "project",
}

type roundTripper struct {
	fn func(*http.Request) (*http.Response, error)
}

func (rt roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return rt.fn(r) }

func newMockHttpClient(f func(*http.Request) (*http.Response, error)) *http.Client {
	return &http.Client{
		Transport: roundTripper{f},
	}
}

func TestRemoteStoreAtomicInt(t *testing.T) {
	kv := &remoteStore{
		&defaultCredentials,
		newMockHttpClient(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "https://kv.valar.dev/project/key?op=inc&mode=atomic", r.URL.String())

			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader([]byte{0x02})),
			}, nil
		}),
	}

	value, err := kv.AtomicInc("key")

	assert.NoError(t, err)
	assert.Equal(t, int64(2), value)
}

func TestRemoteStoreFetch(t *testing.T) {
	kv := &remoteStore{
		&defaultCredentials,
		newMockHttpClient(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "https://kv.valar.dev/project/key", r.URL.String())

			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader([]byte{0x01, 0x02, 0x03, 0x04})),
			}, nil
		}),
	}

	value, err := kv.Fetch("key")

	assert.NoError(t, err)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, value)
}

func TestRemoteStorePut(t *testing.T) {
	kv := &remoteStore{
		&defaultCredentials,
		newMockHttpClient(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "https://kv.valar.dev/project/key", r.URL.String())

			body, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			assert.Equal(t, body, []byte{0x01, 0x02, 0x03, 0x04})

			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader([]byte{'O', 'K'})),
			}, nil
		}),
	}

	err := kv.Put("key", []byte{0x1, 0x2, 0x3, 0x4})
	assert.NoError(t, err)
}

func TestRemoteStoreList(t *testing.T) {
	kv := &remoteStore{
		&defaultCredentials,
		newMockHttpClient(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "https://kv.valar.dev/project/key?mode=list", r.URL.String())

			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader([]byte(`["key0", "key1"]`))),
			}, nil
		}),
	}

	keys, hash, err := kv.List("key")
	assert.NoError(t, err)
	assert.Equal(t, []string{"key0", "key1"}, keys)
	assert.Equal(t, []byte{0x7d, 0xfc, 0x67, 0xe2, 0x6c, 0xb6, 0xee, 0x43, 0xc5, 0xb5, 0x0d, 0x30, 0x33, 0x5f, 0xa0, 0x43, 0x43, 0x4f, 0xb6, 0x84}, hash)
}

func TestRemoteStoreDelete(t *testing.T) {
	kv := &remoteStore{
		&defaultCredentials,
		newMockHttpClient(func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, "DELETE", r.Method)
			assert.Equal(t, "https://kv.valar.dev/project/key", r.URL.String())

			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader([]byte(`OK`))),
			}, nil
		}),
	}

	err := kv.Delete("key")
	assert.NoError(t, err)
}
