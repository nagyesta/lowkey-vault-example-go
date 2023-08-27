package src

import (
	"crypto/elliptic"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/tracing"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"log"
	"testing"
)

func TestMISecret(t *testing.T) {
	//given
	httpClient := PrepareClient()
	secretDatabase := "database"
	secretUsername := "username"
	secretPassword := "password"
	database := "db"
	username := "admin"
	password := "s3cr3t"
	cred, _ := azidentity.NewDefaultAzureCredential(nil) // Will use Managed Identity via the Assumed Identity container
	client, _ := azsecrets.NewClient("https://localhost:8443",
		cred,
		&azsecrets.ClientOptions{ClientOptions: struct {
			APIVersion       string
			Cloud            cloud.Configuration
			Logging          policy.LogOptions
			Retry            policy.RetryOptions
			Telemetry        policy.TelemetryOptions
			TracingProvider  tracing.Provider
			Transport        policy.Transporter
			PerCallPolicies  []policy.Policy
			PerRetryPolicies []policy.Policy
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

func TestMIKey(t *testing.T) {
	//given
	httpClient := PrepareClient()
	secretMessage := "a secret message"
	keyName := "rsa-key"
	cred, _ := azidentity.NewDefaultAzureCredential(nil) // Will use Managed Identity via the Assumed Identity container
	client, _ := azkeys.NewClient("https://localhost:8443",
		cred,
		&azkeys.ClientOptions{ClientOptions: struct {
			APIVersion       string
			Cloud            cloud.Configuration
			Logging          policy.LogOptions
			Retry            policy.RetryOptions
			Telemetry        policy.TelemetryOptions
			TracingProvider  tracing.Provider
			Transport        policy.Transporter
			PerCallPolicies  []policy.Policy
			PerRetryPolicies []policy.Policy
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

func TestMICertificate(t *testing.T) {
	//given
	httpClient := PrepareClient()
	certificateName := "certificate"
	subject := "CN=example.com"
	cred, _ := azidentity.NewDefaultAzureCredential(nil) // Will use Managed Identity via the Assumed Identity container
	secretClient, _ := azsecrets.NewClient("https://localhost:8443",
		cred,
		&azsecrets.ClientOptions{ClientOptions: struct {
			APIVersion       string
			Cloud            cloud.Configuration
			Logging          policy.LogOptions
			Retry            policy.RetryOptions
			Telemetry        policy.TelemetryOptions
			TracingProvider  tracing.Provider
			Transport        policy.Transporter
			PerCallPolicies  []policy.Policy
			PerRetryPolicies []policy.Policy
		}{Transport: &httpClient}, DisableChallengeResourceVerification: true})
	certificateClient, _ := azcertificates.NewClient("https://localhost:8443",
		cred,
		&azcertificates.ClientOptions{ClientOptions: struct {
			APIVersion       string
			Cloud            cloud.Configuration
			Logging          policy.LogOptions
			Retry            policy.RetryOptions
			Telemetry        policy.TelemetryOptions
			TracingProvider  tracing.Provider
			Transport        policy.Transporter
			PerCallPolicies  []policy.Policy
			PerRetryPolicies []policy.Policy
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
