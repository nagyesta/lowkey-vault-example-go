package src

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

func secret(client *azsecrets.Client, name string) string {
	resp, err := client.GetSecret(context.TODO(), name, "", nil)
	if err != nil {
		log.Fatalf("failed to get the secret: %v", err)
	}

	return *resp.Value
}

func encrypt(client *azkeys.Client, name string, message string) []byte {
	version := getLatestVersionOfKey(client, name)
	parameters := azkeys.KeyOperationsParameters{
		Value:     []byte(message),
		Algorithm: to.Ptr(azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256)}
	resp, err := client.Encrypt(context.TODO(), name, version, parameters, nil)
	if err != nil {
		log.Fatalf("failed to encrypt using key: %v", err)
	}
	return resp.Result
}

func decrypt(client *azkeys.Client, name string, encrypted []byte) string {
	version := getLatestVersionOfKey(client, name)
	parameters := azkeys.KeyOperationsParameters{
		Value:     encrypted,
		Algorithm: to.Ptr(azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256)}
	resp, err := client.Decrypt(context.TODO(), name, version, parameters, nil)
	if err != nil {
		log.Fatalf("failed to decrypt using key: %v", err)
	}
	return string(resp.Result)
}

func getLatestVersionOfKey(client *azkeys.Client, name string) string {
	key, err := client.GetKey(context.TODO(), name, "", nil)
	if err != nil {
		log.Fatalf("failed to get key: %v", err)
	}
	return key.Key.KID.Version()
}
