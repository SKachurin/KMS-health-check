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
	kvcrypto "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys/crypto"
)

type azureKMS struct {
	vaultURL string
	keyName  string
	keys   *azkeys.Client
	crypto *kvcrypto.Client
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

	// Bind crypto client to latest key version by resolving KID once.
	get, err := keysClient.GetKey(ctx, keyName, "", nil)
	if err != nil {
		return nil, err
	}
	if get.Key == nil || get.Key.KID == nil || *get.Key.KID == "" {
		return nil, errors.New("azure key has no KID")
	}

	cryptoClient, err := kvcrypto.NewClient(*get.Key.KID, cred, nil)
	if err != nil {
		return nil, err
	}

	return &azureKMS{
		vaultURL: vaultURL,
		keyName:  keyName,
		keys:     keysClient,
		crypto:   cryptoClient,
	}, nil
}

func (a *azureKMS) Health(ctx context.Context) error {
	_, err := a.keys.GetKey(ctx, a.keyName, "", nil)
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
	out, err := a.crypto.Encrypt(ctx, alg, plain, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(out.Result), nil
}

func (a *azureKMS) Unwrap(ctx context.Context, userID int, _hB64, answerFP, wB64 string) (string, bool, error) {
	blob, err := base64.StdEncoding.DecodeString(wB64)
	if err != nil {
		return "", false, err
	}

	alg := azkeys.EncryptionAlgorithmRSAOAEP256
	out, err := a.crypto.Decrypt(ctx, alg, blob, nil)
	if err != nil {
		return "", false, err
	}
	plain := out.Result

	// Parse header in bytes (plain contains binary DEK)
	// Expected: u:<id>|fp:<fp>|<dek...>
	if !bytes.HasPrefix(plain, []byte("u:")) {
		return "", false, errors.New("bad wrapped payload header")
	}

	// find "|fp:" and the final "|" after fp
	fpIdx := bytes.Index(plain, []byte("|fp:"))
	if fpIdx < 0 {
		return "", false, errors.New("bad wrapped payload header")
	}
	endIdxRel := bytes.IndexByte(plain[fpIdx+1:], '|') // from after first '|' in "|fp:"
	if endIdxRel < 0 {
		return "", false, errors.New("bad wrapped payload header")
	}
	headerEnd := fpIdx + 1 + endIdxRel + 1

	header := plain[:headerEnd]

	// u:<id>|
	uEnd := bytes.IndexByte(header, '|')
	uStr := string(bytes.TrimPrefix(header[:uEnd], []byte("u:")))
	u, err := strconv.Atoi(uStr)
	if err != nil || u != userID {
		return "", false, errors.New("user_id mismatch")
	}

	// fp:<fp>|
	fpPart := header[uEnd+1 : len(header)-1] // without last '|'
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