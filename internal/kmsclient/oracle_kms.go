package kmsclient

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

type oracleKMS struct {
	crypto keymanagement.KmsCryptoClient
	keyID  string
}

func NewOracle(
    ctx context.Context,
    cryptoEndpoint string,
    keyID string,
    tenancyOCID string,
    userOCID string,
    region string,
    fingerprint string,
    privateKey string,
) (Client, error) {
    _ = ctx

    provider := common.NewRawConfigurationProvider(
        tenancyOCID,
        userOCID,
        region,
        fingerprint,
        privateKey,
        nil,
    )

    client, err := keymanagement.NewKmsCryptoClientWithConfigurationProvider(
        provider,
        cryptoEndpoint,
    )
    if err != nil {
        return nil, err
    }

    return &oracleKMS{
        crypto: client,
        keyID:  keyID,
    }, nil
}

func (o *oracleKMS) associatedData(userID int, answerFP string) map[string]string {
	return map[string]string{
		"user_id":   strconv.Itoa(userID),
		"answer_fp": answerFP,
	}
}

func (o *oracleKMS) Health(ctx context.Context) error {
	dekB64 := base64.StdEncoding.EncodeToString([]byte("oracle-health"))
	wB64, err := o.Wrap(ctx, 0, dekB64, "", "healthcheck")
	if err != nil {
		return err
	}

	out, ok, err := o.Unwrap(ctx, 0, "", "healthcheck", wB64)
	if err != nil {
		return err
	}
	if !ok || out != dekB64 {
		return errors.New("oracle health mismatch")
	}
	return nil
}

func (o *oracleKMS) Wrap(ctx context.Context, userID int, dekB64, _hB64, answerFP string) (string, error) {
	// Validate caller input is real base64, same as other providers.
	if _, err := base64.StdEncoding.DecodeString(dekB64); err != nil {
		return "", err
	}

	req := keymanagement.EncryptRequest{
		EncryptDataDetails: keymanagement.EncryptDataDetails{
			KeyId:               common.String(o.keyID),
			Plaintext:           common.String(dekB64),
			AssociatedData:      o.associatedData(userID, answerFP),
			EncryptionAlgorithm: keymanagement.EncryptDataDetailsEncryptionAlgorithmAes256Gcm,
		},
	}

	resp, err := o.crypto.Encrypt(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Ciphertext == nil || *resp.Ciphertext == "" {
		return "", errors.New("oracle encrypt returned empty ciphertext")
	}

	// OCI returns ciphertext as base64 string already.
	return *resp.Ciphertext, nil
}

func (o *oracleKMS) Unwrap(ctx context.Context, userID int, _hB64, answerFP, wB64 string) (string, bool, error) {
	req := keymanagement.DecryptRequest{
		DecryptDataDetails: keymanagement.DecryptDataDetails{
			KeyId:               common.String(o.keyID),
			Ciphertext:          common.String(wB64),
			AssociatedData:      o.associatedData(userID, answerFP),
			EncryptionAlgorithm: keymanagement.DecryptDataDetailsEncryptionAlgorithmAes256Gcm,
		},
	}

	resp, err := o.crypto.Decrypt(ctx, req)
	if err != nil {
		return "", false, err
	}
	if resp.Plaintext == nil || *resp.Plaintext == "" {
		return "", false, errors.New("oracle decrypt returned empty plaintext")
	}

	// OCI returns plaintext as base64 string.
	if _, err := base64.StdEncoding.DecodeString(*resp.Plaintext); err != nil {
		return "", false, err
	}

	return *resp.Plaintext, true, nil
}