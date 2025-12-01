package kmsclient

import (
    "context"
    "encoding/base64"
    "strconv"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/credentials"
    "github.com/aws/aws-sdk-go-v2/service/kms"
)

type awsKMS struct {
    c     *kms.Client
    keyID string
}

func NewAWS(ctx context.Context, region, keyID, accessKey, secretKey, endpoint string) (Client, error) {
    optFns := []func(*config.LoadOptions) error{
        config.WithRegion(region),
        config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
    }
    if endpoint != "" {
        // optional custom endpoint (we’ll still sign for region)
        optFns = append(optFns, config.WithEndpointResolverWithOptions(
            aws.EndpointResolverWithOptionsFunc(func(service, r string, _ ...interface{}) (aws.Endpoint, error) {
                if service == kms.ServiceID {
                    return aws.Endpoint{URL: "https://" + endpoint, HostnameImmutable: true, SigningRegion: region}, nil
                }
                return aws.Endpoint{}, &aws.EndpointNotFoundError{}
            }),
        ))
    }

    cfg, err := config.LoadDefaultConfig(ctx, optFns...)
    if err != nil { return nil, err }
    return &awsKMS{c: kms.NewFromConfig(cfg), keyID: keyID}, nil
}

func (a *awsKMS) Health(ctx context.Context) error {
    _, err := a.c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &a.keyID})
    return err
}

func (a *awsKMS) Wrap(ctx context.Context, userID int, dekB64, _hB64, answerFP string) (string, error) {
    dek, err := base64.StdEncoding.DecodeString(dekB64)
    if err != nil { return "", err }
    out, err := a.c.Encrypt(ctx, &kms.EncryptInput{
        KeyId:     &a.keyID,
        Plaintext: dek,
        EncryptionContext: map[string]string{
            "user_id":   strconv.Itoa(userID),
            "answer_fp": answerFP,
        },
    })
    if err != nil { return "", err }
    return base64.StdEncoding.EncodeToString(out.CiphertextBlob), nil
}

func (a *awsKMS) Unwrap(ctx context.Context, userID int, _hB64, answerFP, wB64 string) (string, bool, error) {
    blob, err := base64.StdEncoding.DecodeString(wB64)
    if err != nil { return "", false, err }
    out, err := a.c.Decrypt(ctx, &kms.DecryptInput{
        CiphertextBlob: blob,
        EncryptionContext: map[string]string{
            "user_id":   strconv.Itoa(userID),
            "answer_fp": answerFP,
        },
    })
    if err != nil { return "", false, err }
    return base64.StdEncoding.EncodeToString(out.Plaintext), true, nil
}