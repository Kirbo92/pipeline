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
	"fmt"
	"testing"
	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2018-10-01/compute"
)

var (
	computeSvc, _ = NewComputeService("SebaTestWEU", &sir, logger)
)

func TestComputeService_CreateVirtualMachineScaleSets(t *testing.T) {
	tags := map[string]string{
		"test-tag": "test-value",
		"owner":    "pipeline",
	}
	vmssName := "PKEMasterScaleSet"

	osProfile := NewVirtualMachineScaleSetOSProfile(
		"pke-master",
		"pkeroot",
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDnxr54ukpCOwyd5hmAsj5Gx+2FnnIHNOUEJkEY76B6efYvJzbpMCpg1qH4SZHheiNIqBooa5yKGI2Di7PHIZWPMwpudqJgeeWe5p+eVFTFjO2uS8UxdNg3fUlmOrg4Af7yu8RS2QAAT6gRPspxfYt45vI/zkjW70w6FuY9Irj0XyuiD3MlDPhp+GSyalzVslyMKn9VjwJ1FcJs7kM2sZ8dTSdvxsfFi/ryzzD5JrHCeotk07YRxokN2oEcJeg/25FTDgkNEzR4FgLyMNW9q/gI8zvJ0MTRor/xsz3g0+p5KSOSWRiewhfDxfFFGHBVXnI7avSKC5F6j31CwrkpcTkh st0ad3r@gmail.com",
		)

	ipConfig1 := NewVirtualMachineScaleSetIPConfiguration(
		fmt.Sprintf("%s-pip-1", vmssName),
		true,
		"/subscriptions/ba96ef31-4a42-40f5-8740-03f7e3c439eb/resourceGroups/SebaTestWEU/providers/Microsoft.Network/virtualNetworks/vnet-test1/subnets/subnet-test1",
		)

	networkConfig1 := NewVirtualMachineScaleSetNetworkConfiguration(
		fmt.Sprintf("%s-nic-1", vmssName),
		true,
		true,
		"/subscriptions/ba96ef31-4a42-40f5-8740-03f7e3c439eb/resourceGroups/SebaTestWEU/providers/Microsoft.Network/networkSecurityGroups/PKEMasterNSG",
		[]compute.VirtualMachineScaleSetIPConfiguration{ *ipConfig1 },
		)

	networkProfile := &compute.VirtualMachineScaleSetNetworkProfile{
		NetworkInterfaceConfigurations: &[]compute.VirtualMachineScaleSetNetworkConfiguration{ *networkConfig1 },
	}
	_, err := computeSvc.CreateVirtualMachineScaleSet(
		"westeurope",
		"PKEMasterScaleSet",
		"Standard_B2s",
		3,
		[]string{"1", "2", "3"},
		tags,
		&Centos7CI,
		&OSDiskStandardSSDLRS,
		osProfile,
		networkProfile)

	if err != nil {
		t.Error(err)
	}
}

func TestComputeService_DeleteVirtualMachineScaleSet(t *testing.T) {
	err := computeSvc.DeleteVirtualMachineScaleSet("PKEMasterScaleSet")
	if err != nil {
		t.Error(err)
	}
}
