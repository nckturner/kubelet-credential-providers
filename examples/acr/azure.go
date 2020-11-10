// +build !providerless

/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"errors"
	"io"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/containerregistry/mgmt/2019-05-01/containerregistry"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"

	"k8s.io/klog/v2"
	"k8s.io/legacy-cloud-providers/azure/auth"
	"sigs.k8s.io/yaml"
)

const (
	maxReadLength = 10 * 1 << 20 // 10MB
)

var (
	acrRE = regexp.MustCompile(`.*\.azurecr\.io|.*\.azurecr\.cn|.*\.azurecr\.de|.*\.azurecr\.us`)
)

type acrPlugin struct {
	config                *auth.AzureAuthConfig
	environment           *azure.Environment
	registryClient        RegistriesClient
	servicePrincipalToken *adal.ServicePrincipalToken
}

// RegistriesClient is a testable interface for the ACR client List operation.
type RegistriesClient interface {
	List(ctx context.Context) ([]containerregistry.Registry, error)
}

func newAzRegistriesClient(subscriptionID, endpoint string, token *adal.ServicePrincipalToken) *azRegistriesClient {
	registryClient := containerregistry.NewRegistriesClient(subscriptionID)
	registryClient.BaseURI = endpoint
	registryClient.Authorizer = autorest.NewBearerAuthorizer(token)

	return &azRegistriesClient{
		client: registryClient,
	}
}

// azRegistriesClient implements RegistriesClient.
type azRegistriesClient struct {
	client containerregistry.RegistriesClient
}

func (az *azRegistriesClient) List(ctx context.Context) ([]containerregistry.Registry, error) {
	iterator, err := az.client.ListComplete(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]containerregistry.Registry, 0)
	for ; iterator.NotDone(); err = iterator.Next() {
		if err != nil {
			return nil, err
		}

		result = append(result, iterator.Value())
	}

	return result, nil
}

// ParseConfig returns a parsed configuration for an Azure cloudprovider config file
func parseConfig(configReader io.Reader) (*auth.AzureAuthConfig, error) {
	var config auth.AzureAuthConfig

	if configReader == nil {
		return &config, nil
	}

	limitedReader := &io.LimitedReader{R: configReader, N: maxReadLength}
	configContents, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}
	if limitedReader.N <= 0 {
		return nil, errors.New("the read limit is reached")
	}
	err = yaml.Unmarshal(configContents, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func (a *acrPlugin) loadConfig(rdr io.Reader) error {
	var err error
	a.config, err = parseConfig(rdr)
	if err != nil {
		klog.Errorf("Failed to load azure credential file: %v", err)
	}

	a.environment, err = auth.ParseAzureEnvironment(a.config.Cloud, a.config.ResourceManagerEndpoint, a.config.IdentitySystem)
	if err != nil {
		return err
	}

	return nil
}

// parseACRLoginServerFromImage takes image as parameter and returns login server of it.
// Parameter `image` is expected in following format: foo.azurecr.io/bar/imageName:version
// If the provided image is not an acr image, this function will return an empty string.
func (a *acrPlugin) parseACRLoginServerFromImage(image string) string {
	match := acrRE.FindAllString(image, -1)
	if len(match) == 1 {
		return match[0]
	}

	// handle the custom cloud case
	if a != nil && a.environment != nil {
		cloudAcrSuffix := a.environment.ContainerRegistryDNSSuffix
		cloudAcrSuffixLength := len(cloudAcrSuffix)
		if cloudAcrSuffixLength > 0 {
			customAcrSuffixIndex := strings.Index(image, cloudAcrSuffix)
			if customAcrSuffixIndex != -1 {
				endIndex := customAcrSuffixIndex + cloudAcrSuffixLength
				return image[0:endIndex]
			}
		}
	}

	return ""
}

func (a *acrPlugin) getACRDockerEntryFromARMToken(loginServer string) (string, error) {
	// Run EnsureFresh to make sure the token is valid and does not expire
	if err := a.servicePrincipalToken.EnsureFresh(); err != nil {
		return "", err
	}
	armAccessToken := a.servicePrincipalToken.OAuthToken()

	directive, err := receiveChallengeFromLoginServer(loginServer)
	if err != nil {
		return "", err
	}

	registryRefreshToken, err := performTokenExchange(
		loginServer, directive, a.config.TenantID, armAccessToken)
	if err != nil {
		return "", err
	}

	return registryRefreshToken, nil
}
