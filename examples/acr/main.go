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

// TODO: this is just a reference implementation, this plugin should be moved
// to sigs.k8s.io/cloud-provider-azure
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/credentialprovider/apis/credentials/v1alpha1"
	plugin "k8s.io/kubernetes/pkg/credentialprovider/plugin/framework"
	"k8s.io/legacy-cloud-providers/azure/auth"
)

const (
	azureConfigFileKey = "AZURE_CONTAINER_REGISTRY_CONFIG"
)

var (
	containerRegistryUrls = []string{"*.azurecr.io", "*.azurecr.cn", "*.azurecr.de", "*.azurecr.us"}
)

func (a *acrPlugin) GetCredentials(ctx context.Context, image string, args []string) (*v1alpha1.CredentialProviderResponse, error) {
	configFile := os.Getenv(azureConfigFileKey)
	if configFile == "" {
		return nil, fmt.Errorf("azure config file argument %s not provided", azureConfigFileKey)

	}

	f, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("error reading azure config file: %v", err)
	}
	defer f.Close()

	err = a.loadConfig(f)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %v", err)
	}

	a.servicePrincipalToken, err = auth.GetServicePrincipalToken(a.config, a.environment)
	if err != nil {
		return nil, fmt.Errorf("error creating service principal token: %v", err)
	}

	a.registryClient = newAzRegistriesClient(a.config.SubscriptionID, a.environment.ResourceManagerEndpoint, a.servicePrincipalToken)

	response := &v1alpha1.CredentialProviderResponse{
		CacheKeyType:  v1alpha1.GlobalPluginCacheKeyType,
		CacheDuration: &metav1.Duration{Duration: 1 * time.Minute},
		Auth: map[string]v1alpha1.AuthConfig{
			"*.azurecr.*": {
				Username: "",
				Password: "",
			},
		},
	}

	if !a.config.UseManagedIdentityExtension {
		for _, imageMatch := range containerRegistryUrls {
			authConfig := v1alpha1.AuthConfig{
				Username: a.config.AADClientID,
				Password: a.config.AADClientSecret,
			}

			response.Auth[imageMatch] = authConfig
		}

		return response, nil
	}

	loginServer := a.parseACRLoginServerFromImage(image)
	if loginServer == "" {
		return nil, errors.New("could not parse login server from image")
	}

	token, err := a.getACRDockerEntryFromARMToken(loginServer)
	if err != nil {
		// only return anonymous auth credentials if error getting token
		return response, nil
	}

	response.Auth[loginServer] = v1alpha1.AuthConfig{
		Username: dockerTokenLoginUsernameGUID,
		Password: token,
	}

	return response, nil

}

func main() {
	p := plugin.NewCredentialProvider(&acrPlugin{})
	if err := p.Run(context.TODO()); err != nil {
		klog.Errorf("Error running credential provider plugin: %v", err)
		os.Exit(1)
	}
}
