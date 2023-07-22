package blob

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Store interface {
	PublicURL(bucket, name string) (string, error)
	Put(ctx context.Context, bucket, name, mimeType string, reader io.Reader) error
	Delete(ctx context.Context, bucket, name string) error
}

type r2Storage struct {
	publicURL string
	client    *s3.Client
}

var _ Store = (*r2Storage)(nil)

func WithR2Backend(endpoint, accessKeyID, secretAccessKey, publicURL string) (Store, error) {
	endpointResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL: endpoint,
		}, nil
	})
	awsConfig, err := config.LoadDefaultConfig(context.TODO(),
		config.WithEndpointResolverWithOptions(endpointResolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")))
	if err != nil {
		return nil, err
	}
	return &r2Storage{
		publicURL: publicURL,
		client:    s3.NewFromConfig(awsConfig),
	}, nil
}

func (r2 *r2Storage) Delete(ctx context.Context, bucket, name string) error {
	if _, err := r2.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(name),
	}); err != nil {
		return err
	}
	return nil
}

func (r2 *r2Storage) PublicURL(bucket, name string) (string, error) {
	return fmt.Sprintf("%s/%s", r2.publicURL, name), nil
}

func (r2 *r2Storage) Put(ctx context.Context, bucket, name, mediaType string, reader io.Reader) error {
	if _, err := r2.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(name),
		ContentType: aws.String(mediaType),
		Body:        reader,
	}); err != nil {
		return err
	}
	return nil
}

type inMemoryStorage struct {
	publicURL string
	mu        sync.RWMutex
	blobs     map[string][]byte
}

var _ Store = (*inMemoryStorage)(nil)

func (memory *inMemoryStorage) PublicURL(bucket, name string) (string, error) {
	return fmt.Sprintf("%s/%s/%s", memory.publicURL, bucket, name), nil
}

func (memory *inMemoryStorage) ServeHTTP(w http.ResponseWriter, r *http.Request) []byte {
	bucket, name := path.Dir(r.URL.Path), path.Base(r.URL.Path)
	key := bucket + "\x00" + name
	memory.mu.RLock()
	blob := memory.blobs[key]
	memory.mu.RUnlock()
	return blob
}

func (memory *inMemoryStorage) Put(ctx context.Context, bucket, name string, mediaType string, reader io.Reader) error {
	blob, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	key := bucket + "\x00" + name
	memory.mu.Lock()
	memory.blobs[key] = blob
	memory.mu.Unlock()
	return nil
}

func (memory *inMemoryStorage) Delete(ctx context.Context, bucket, name string) error {
	key := bucket + "\x00" + name
	memory.mu.Lock()
	delete(memory.blobs, key)
	memory.mu.Unlock()
	return nil
}
