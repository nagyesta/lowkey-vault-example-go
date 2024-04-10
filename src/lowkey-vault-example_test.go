package src

import (
	"context"
	"crypto/elliptic"
	"crypto/tls"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/tracing"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
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
	client, _ := azsecrets.NewClient("https://localhost:8443",
		&FakeCredential{},
		&azsecrets.ClientOptions{ClientOptions: struct {
			APIVersion                      string
			Cloud                           cloud.Configuration
			InsecureAllowCredentialWithHTTP bool
			Logging                         policy.LogOptions
			Retry                           policy.RetryOptions
			Telemetry                       policy.TelemetryOptions
			TracingProvider                 tracing.Provider
			Transport                       policy.Transporter
			PerCallPolicies                 []policy.Policy
			PerRetryPolicies                []policy.Policy
		}{Transport: &httpClient}, DisableChallengeResourceVerification: true})
	SetSecret(client, secretDatabase, database)
	SetSecret(client, secretUsername, username)
	SetSecret(client, secretPassword, password)

	//when
	gotDatabase, err := Secret(client, secretDatabase)
	if err != nil {
		log.Panicf("failed to get the secret %s", err.Error())
	}
	gotUsername, err := Secret(client, secretUsername)
	if err != nil {
		log.Panicf("failed to get the secret %s", err.Error())
	}
	gotPassword, err := Secret(client, secretPassword)
	if err != nil {
		log.Panicf("failed to get the secret %s", err.Error())
	}

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
	client, _ := azkeys.NewClient("https://localhost:8443",
		&FakeCredential{},
		&azkeys.ClientOptions{ClientOptions: struct {
			APIVersion                      string
			Cloud                           cloud.Configuration
			InsecureAllowCredentialWithHTTP bool
			Logging                         policy.LogOptions
			Retry                           policy.RetryOptions
			Telemetry                       policy.TelemetryOptions
			TracingProvider                 tracing.Provider
			Transport                       policy.Transporter
			PerCallPolicies                 []policy.Policy
			PerRetryPolicies                []policy.Policy
		}{Transport: &httpClient}, DisableChallengeResourceVerification: true})
	CreateKey(client, keyName)

	//when
	gotEncrypted, err := Encrypt(client, keyName, secretMessage)
	if err != nil {
		log.Panicf("failed to encrypt: %v", err)
	}
	gotDecrypted, err := Decrypt(client, keyName, gotEncrypted)
	if err != nil {
		log.Panicf("failed to decrypt: %v", err)
	}

	//then
	if gotDecrypted != secretMessage {
		t.Errorf("got %q, wanted %q", gotDecrypted, secretMessage)
	}
}

func TestCertificate(t *testing.T) {
	//given
	httpClient := PrepareClient()
	certificateName := "certificate"
	subject := "CN=example.com"
	secretClient, _ := azsecrets.NewClient("https://localhost:8443",
		&FakeCredential{},
		&azsecrets.ClientOptions{ClientOptions: struct {
			APIVersion                      string
			Cloud                           cloud.Configuration
			InsecureAllowCredentialWithHTTP bool
			Logging                         policy.LogOptions
			Retry                           policy.RetryOptions
			Telemetry                       policy.TelemetryOptions
			TracingProvider                 tracing.Provider
			Transport                       policy.Transporter
			PerCallPolicies                 []policy.Policy
			PerRetryPolicies                []policy.Policy
		}{Transport: &httpClient}, DisableChallengeResourceVerification: true})
	certificateClient, _ := azcertificates.NewClient("https://localhost:8443",
		&FakeCredential{},
		&azcertificates.ClientOptions{ClientOptions: struct {
			APIVersion                      string
			Cloud                           cloud.Configuration
			InsecureAllowCredentialWithHTTP bool
			Logging                         policy.LogOptions
			Retry                           policy.RetryOptions
			Telemetry                       policy.TelemetryOptions
			TracingProvider                 tracing.Provider
			Transport                       policy.Transporter
			PerCallPolicies                 []policy.Policy
			PerRetryPolicies                []policy.Policy
		}{Transport: &httpClient}, DisableChallengeResourceVerification: true})
	CreateCertificate(certificateClient, certificateName, subject)

	//when
	gotCertificate, err := Certificate(secretClient, certificateName)
	if err != nil {
		log.Panicf("failed to get certificate: %v", err)
	}
	gotKey, err := PrivateKey(secretClient, certificateName)
	if err != nil {
		log.Panicf("failed to get private key: %v", err)
	}

	//then
	if gotCertificate.Subject.String() != subject {
		t.Errorf("got %q, wanted %q", gotCertificate.Subject.CommonName, subject)
	}
	//check key curve of the obtained key
	if gotKey.Curve != elliptic.P256() {
		t.Errorf("got %q, wanted %q", gotKey.Curve, elliptic.P256())
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
		Kty:     to.Ptr(azkeys.KeyTypeRSA),
		KeySize: to.Ptr(int32(2048)),
		KeyOps:  KeyOperations(),
	}
	_, err := client.CreateKey(context.TODO(), name, rsaKeyParams, nil)
	if err != nil {
		log.Fatalf("failed to create a key: %v", err)
	}
}

func CreateCertificate(client *azcertificates.Client, name string, subject string) {
	_, err := client.CreateCertificate(context.TODO(), name, azcertificates.CreateCertificateParameters{
		CertificatePolicy: &azcertificates.CertificatePolicy{
			IssuerParameters: &azcertificates.IssuerParameters{
				Name: to.Ptr("Self"),
			},
			KeyProperties: &azcertificates.KeyProperties{
				Curve:    to.Ptr(azcertificates.CurveNameP256),
				KeyType:  to.Ptr(azcertificates.KeyTypeEC),
				ReuseKey: to.Ptr(true),
			},
			SecretProperties: &azcertificates.SecretProperties{
				ContentType: to.Ptr("application/x-pkcs12"),
			},
			X509CertificateProperties: &azcertificates.X509CertificateProperties{
				Subject: &subject,
				SubjectAlternativeNames: &azcertificates.SubjectAlternativeNames{
					DNSNames: []*string{to.Ptr("localhost")},
				},
				ValidityInMonths: to.Ptr(int32(12)),
			},
		},
	}, nil)
	if err != nil {
		log.Fatalf("failed to create a certificate: %v", err)
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

func KeyOperations() []*azkeys.KeyOperation {
	return []*azkeys.KeyOperation{
		to.Ptr(azkeys.KeyOperationDecrypt),
		to.Ptr(azkeys.KeyOperationEncrypt),
		to.Ptr(azkeys.KeyOperationUnwrapKey),
		to.Ptr(azkeys.KeyOperationWrapKey),
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
