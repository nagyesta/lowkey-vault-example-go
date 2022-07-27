package src

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

// Secret - Simulated production code that can fetch the value of a given secret using the provided secret client.
//
// client - The Azure secret client instance we need to use for fetching the secret value.
//
// name - The name of the secret as stored in Azure Key Vault.
func Secret(client *azsecrets.Client, name string) string {
	resp, err := client.GetSecret(context.TODO(), name, "", nil)
	if err != nil {
		log.Fatalf("failed to get the secret: %v", err)
	}

	return *resp.Value
}

// Encrypt - Simulates a production ready method performing encryption using the provided client on the parameters.
//
// client - The Azure key client used for encryption.
//
// name - The name of the key as it is stored in Azure Key Vault.
//
// message - The clear text message we want to encrypt.
func Encrypt(client *azkeys.Client, name string, message string) []byte {
	version := GetLatestVersionOfKey(client, name)
	parameters := azkeys.KeyOperationsParameters{
		Value:     []byte(message),
		Algorithm: to.Ptr(azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256)}
	resp, err := client.Encrypt(context.TODO(), name, version, parameters, nil)
	if err != nil {
		log.Fatalf("failed to encrypt using key: %v", err)
	}
	return resp.Result
}

// Decrypt - Simulates a production ready method performing decryption using the provided client on the parameters.
//
// client - The Azure key client used for decryption.
//
// name - The name of the key as it is stored in Azure Key Vault.
//
// encrypted - The encrypted message we want to decrypt.
func Decrypt(client *azkeys.Client, name string, encrypted []byte) string {
	version := GetLatestVersionOfKey(client, name)
	parameters := azkeys.KeyOperationsParameters{
		Value:     encrypted,
		Algorithm: to.Ptr(azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256)}
	resp, err := client.Decrypt(context.TODO(), name, version, parameters, nil)
	if err != nil {
		log.Fatalf("failed to decrypt using key: %v", err)
	}
	return string(resp.Result)
}

// GetLatestVersionOfKey - Returns the latest version of the key matching the provided name.
//
// client - The Azure key client used for decryption.
//
// name - The name of the key as it is stored in Azure Key Vault.
func GetLatestVersionOfKey(client *azkeys.Client, name string) string {
	key, err := client.GetKey(context.TODO(), name, "", nil)
	if err != nil {
		log.Fatalf("failed to get key: %v", err)
	}
	return key.Key.KID.Version()
}
