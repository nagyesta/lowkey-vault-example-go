package src

import (
	"context"
	"crypto/tls"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"log"
	"net/http"
	"testing"
	"time"
)

func TestSecret(t *testing.T) {
	//given
	httpClient := PrepareClient()
	secretDatabase := "database"
	secretUsername := "username"
	secretPassword := "password"
	database := "db"
	username := "admin"
	password := "s3cr3t"
	client := azsecrets.NewClient("https://localhost:8443",
		&FakeCredential{},
		&azsecrets.ClientOptions{ClientOptions: struct {
			Cloud            cloud.Configuration
			Logging          policy.LogOptions
			Retry            policy.RetryOptions
			Telemetry        policy.TelemetryOptions
			Transport        policy.Transporter
			PerCallPolicies  []policy.Policy
			PerRetryPolicies []policy.Policy
		}{Transport: &httpClient}})
	SetSecret(client, secretDatabase, database)
	SetSecret(client, secretUsername, username)
	SetSecret(client, secretPassword, password)

	//when
	gotDatabase := Secret(client, secretDatabase)
	gotUsername := Secret(client, secretUsername)
	gotPassword := Secret(client, secretPassword)

	//then
	if gotDatabase != database {
		t.Errorf("got %q, wanted %q", gotDatabase, database)
	}
	if gotUsername != username {
		t.Errorf("got %q, wanted %q", gotUsername, username)
	}
	if gotPassword != password {
		t.Errorf("got %q, wanted %q", gotPassword, password)
	}
}

func TestKey(t *testing.T) {
	//given
	httpClient := PrepareClient()
	secretMessage := "a secret message"
	keyName := "rsa-key"
	client := azkeys.NewClient("https://localhost:8443",
		&FakeCredential{},
		&policy.ClientOptions{Transport: &httpClient})
	CreateKey(client, keyName)

	//when
	gotEncrypted := Encrypt(client, keyName, secretMessage)
	gotDecrypted := Decrypt(client, keyName, gotEncrypted)

	//then
	if gotDecrypted != secretMessage {
		t.Errorf("got %q, wanted %q", gotDecrypted, secretMessage)
	}
}

func SetSecret(client *azsecrets.Client, name string, value string) {
	_, err := client.SetSecret(context.TODO(), name, azsecrets.SetSecretParameters{Value: &value}, nil)
	if err != nil {
		log.Fatalf("failed to create a secret: %v", err)
	}
}

func CreateKey(client *azkeys.Client, name string) {
	rsaKeyParams := azkeys.CreateKeyParameters{
		Kty:     to.Ptr(azkeys.JSONWebKeyTypeRSA),
		KeySize: to.Ptr(int32(2048)),
		KeyOps:  KeyOperations(),
	}
	_, err := client.CreateKey(context.TODO(), name, rsaKeyParams, nil)
	if err != nil {
		log.Fatalf("failed to create a key: %v", err)
	}
}

/*
	Ignore SSL error caused by the self-signed certificate.
*/
func PrepareClient() http.Client {
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return http.Client{Transport: customTransport}
}

func KeyOperations() []*azkeys.JSONWebKeyOperation {
	return []*azkeys.JSONWebKeyOperation{
		to.Ptr(azkeys.JSONWebKeyOperationDecrypt),
		to.Ptr(azkeys.JSONWebKeyOperationEncrypt),
		to.Ptr(azkeys.JSONWebKeyOperationUnwrapKey),
		to.Ptr(azkeys.JSONWebKeyOperationWrapKey),
	}
}

/*
	Fake token used for bypassing the fake authentication of Lowkey Vault
*/
type FakeCredential struct{}

//goland:noinspection GoUnusedParameter
func (f *FakeCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "faketoken", ExpiresOn: time.Now().Add(time.Hour).UTC()}, nil
}
