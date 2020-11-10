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
// to k8s.io/cloud-provider-gcp
package main

import (
	"context"
	"os"

	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/credentialprovider/apis/credentials/v1alpha1"
	plugin "k8s.io/kubernetes/pkg/credentialprovider/plugin/framework"
)

// TODO(cheftako): implement reference implementation or move to k8s.io/cloud-provier-gcp
type gcrPlugin struct {
}

func (g *gcrPlugin) GetCredentials(ctx context.Context, image string, args []string) (*v1alpha1.CredentialProviderResponse, error) {
	return nil, nil
}

func main() {
	p := plugin.NewCredentialProvider(&gcrPlugin{})
	if err := p.Run(context.TODO()); err != nil {
		klog.Errorf("Error running credential provider plugin: %v", err)
		os.Exit(1)
	}
}
