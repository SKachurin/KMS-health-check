package kmsclient

import "context"

type Client interface {
	Health(ctx context.Context) error
	Wrap(ctx context.Context, userID int, dekB64, hB64, answerFP string) (wB64 string, err error)
	Unwrap(ctx context.Context, userID int, hB64, answerFP, wB64 string) (dekB64 string, ok bool, err error)
}
