// Copyright © 2019 Banzai Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package azure

import (
	"testing"

	"github.com/banzaicloud/pipeline/config"
	intNetwork "github.com/banzaicloud/pipeline/internal/network"
	pkgSecret "github.com/banzaicloud/pipeline/pkg/secret"
	"github.com/banzaicloud/pipeline/secret"
)

var (
	logger = config.Logger()

	sir = secret.SecretItemResponse{
		Values: map[string]string{
			pkgSecret.AzureClientID:       "",
			pkgSecret.AzureClientSecret:   "",
			pkgSecret.AzureTenantID:       "",
			pkgSecret.AzureSubscriptionID: "",
		},
	}
	svc, _     = NewNetworkService("SebaTestWEU", &sir, logger)
	networkSvc = svc.(*azureNetworkService)
)

func TestCreateNetwork(t *testing.T) {
	tags := map[string]string{
		"test-tag": "test-value",
		"owner":    "pipeline",
	}

	cidrs := []string{"10.240.0.0/16", "10.250.0.0/16"}
	_, err := networkSvc.CreateNetwork("vnet-test1", "westeurope", cidrs, tags)
	if err != nil {
		t.Error(err)
	}
}

func TestDeleteNetwork(t *testing.T) {
	err := networkSvc.DeleteNetwork("vnet-test1")
	if err != nil {
		t.Error(err)
	}
}

func TestCreateSubnet(t *testing.T) {
	_, err := networkSvc.CreateSubnet("vnet-test1", "subnet-test1", []string{"10.240.0.0/20"})
	if err != nil {
		t.Error(err)
	}
}

func TestDeleteSubnet(t *testing.T) {
	err := networkSvc.DeleteSubnet("vnet-test1", "subnet-test1")
	if err != nil {
		t.Error(err)
	}
}

func TestAzureNetworkService_CreateNetworkSecurityGroup(t *testing.T) {
	tags := map[string]string{
		"test-tag": "test-value",
		"owner":    "pipeline",
	}

	apiServerInboundRule := intNetwork.AzureNetworkSecurityRule{
		Name:                 "AllowPKEApiServerInbound",
		Source:               "*",
		SourcePortRange:      "*",
		Destination:          "*",
		DestinationPortRange: "6443",
		Protocol:             "Tcp",
		Description:          "Allow inbound access to API server",
		Access:               "Allow",
		Direction:            "Inbound",
		Priority:             1001,
	}

	allowSSHRule := intNetwork.AzureNetworkSecurityRule{
		Name:                 "AllowSSHInbound",
		Source:               "*",
		SourcePortRange:      "*",
		Destination:          "*",
		DestinationPortRange: "22",
		Protocol:             "Tcp",
		Description:          "Allow SSH to nodes",
		Access:               "Allow",
		Direction:            "Inbound",
		Priority:             1000,
	}

	rules := []intNetwork.AzureNetworkSecurityRule{
		apiServerInboundRule,
		allowSSHRule,
	}

	_, err := networkSvc.CreateNetworkSecurityGroup("PKEMasterNSG", "westeurope", rules, tags)

	if err != nil {
		t.Error(err)
	}

	_, err = networkSvc.CreateNetworkSecurityGroup("PKEWorkersNSG", "westeurope", []intNetwork.AzureNetworkSecurityRule{allowSSHRule}, tags)

	if err != nil {
		t.Error(err)
	}
}

func TestAzureNetworkService_DeleteNetworkSecurityGroup(t *testing.T) {
	err := networkSvc.DeleteNetworkSecurityGroup("PKEMasterNSG")
	if err != nil {
		t.Error(err)
	}

	err = networkSvc.DeleteNetworkSecurityGroup("PKEWorkersNSG")
	if err != nil {
		t.Error(err)
	}
}
