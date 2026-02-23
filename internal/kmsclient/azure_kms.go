package kmsclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

type azureKMS struct {
	vaultURL string
	keyName  string
	keys     *azkeys.Client
}

func NewAzure(ctx context.Context, vaultURL, keyName, tenantID, clientID, clientSecret string) (Client, error) {
	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		return nil, err
	}

	keysClient, err := azkeys.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, err
	}

	return &azureKMS{
		vaultURL: vaultURL,
		keyName:  keyName,
		keys:     keysClient,
	}, nil
}

func (a *azureKMS) Health(ctx context.Context) error {
	_, err := a.keys.GetKey(ctx, a.keyName, "", nil) // "" = latest
	return err
}

// Format: "u:<id>|fp:<answer_fp>|" + raw DEK bytes
func (a *azureKMS) Wrap(ctx context.Context, userID int, dekB64, _hB64, answerFP string) (string, error) {
	dek, err := base64.StdEncoding.DecodeString(dekB64)
	if err != nil {
		return "", err
	}

	header := []byte(fmt.Sprintf("u:%d|fp:%s|", userID, answerFP))
	plain := append(header, dek...)

	alg := azkeys.EncryptionAlgorithmRSAOAEP256
	out, err := a.keys.Encrypt(ctx, a.keyName, "", azkeys.KeyOperationParameters{
		Algorithm: &alg,
		Value:     plain,
	}, nil)
	if err != nil {
		return "", err
	}
	if out.Result == nil {
		return "", errors.New("azure encrypt returned empty result")
	}
	return base64.StdEncoding.EncodeToString(out.Result), nil
}

func (a *azureKMS) Unwrap(ctx context.Context, userID int, _hB64, answerFP, wB64 string) (string, bool, error) {
	blob, err := base64.StdEncoding.DecodeString(wB64)
	if err != nil {
		return "", false, err
	}

	alg := azkeys.EncryptionAlgorithmRSAOAEP256
	out, err := a.keys.Decrypt(ctx, a.keyName, "", azkeys.KeyOperationParameters{
		Algorithm: &alg,
		Value:     blob,
	}, nil)
	if err != nil {
		return "", false, err
	}
	if out.Result == nil {
		return "", false, errors.New("azure decrypt returned empty result")
	}
	plain := out.Result

	// Parse header: u:<id>|fp:<fp>|<dek...>
	if !bytes.HasPrefix(plain, []byte("u:")) {
		return "", false, errors.New("bad wrapped payload header")
	}

	fpIdx := bytes.Index(plain, []byte("|fp:"))
	if fpIdx < 0 {
		return "", false, errors.New("bad wrapped payload header")
	}
	endIdxRel := bytes.IndexByte(plain[fpIdx+1:], '|')
	if endIdxRel < 0 {
		return "", false, errors.New("bad wrapped payload header")
	}
	headerEnd := fpIdx + 1 + endIdxRel + 1
	header := plain[:headerEnd]

	uEnd := bytes.IndexByte(header, '|')
	uStr := string(bytes.TrimPrefix(header[:uEnd], []byte("u:")))
	u, err := strconv.Atoi(uStr)
	if err != nil || u != userID {
		return "", false, errors.New("user_id mismatch")
	}

	fpPart := header[uEnd+1 : len(header)-1]
	if !bytes.HasPrefix(fpPart, []byte("fp:")) {
		return "", false, errors.New("bad wrapped payload header")
	}
	fp := string(bytes.TrimPrefix(fpPart, []byte("fp:")))
	if fp != answerFP {
		return "", false, errors.New("answer_fp mismatch")
	}

	dek := plain[headerEnd:]
	return base64.StdEncoding.EncodeToString(dek), true, nil
}