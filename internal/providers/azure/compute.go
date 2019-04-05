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
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2018-10-01/compute"
	"github.com/Azure/go-autorest/autorest/azure"
	pkgAzure "github.com/banzaicloud/pipeline/pkg/providers/azure"
	"github.com/banzaicloud/pipeline/secret"
	"github.com/goph/emperror"
	"github.com/sirupsen/logrus"
)


var (
	Centos75 = compute.ImageReference{
		Publisher: stringRef("OpenLogic"),
		Offer: stringRef("CentOS"),
		Sku: stringRef("7.5"),
		Version: stringRef("latest"),
	}

	// Centos 7-CI supports cloud init (preview)
	// https://docs.microsoft.com/en-us/azure/virtual-machines/linux/using-cloud-init?toc=%2Fazure%2Fvirtual-machines%2Flinux%2Ftoc.json
	Centos7CI = compute.ImageReference{
		Publisher: stringRef("OpenLogic"),
		Offer: stringRef("CentOS"),
		Sku: stringRef("7-CI"),
		Version: stringRef("latest"),
	}

	DefaulsOSDiskSizeGB int32 = 32

	// 32 GB StandardSSD_LRS disk for OS
	OSDiskStandardSSDLRS = compute.VirtualMachineScaleSetOSDisk{
		ManagedDisk: &compute.VirtualMachineScaleSetManagedDiskParameters{
			StorageAccountType: compute.StorageAccountTypesStandardSSDLRS,
		},
		CreateOption: compute.DiskCreateOptionTypesFromImage,
		Caching:      compute.CachingTypesReadWrite,
		DiskSizeGB:   &DefaulsOSDiskSizeGB,
		OsType:       compute.Linux,
	}
)

type computeService struct {
	vmssClient        compute.VirtualMachineScaleSetsClient
	logger            logrus.FieldLogger
	resourceGroupName string
}

// NewComputeService returns a new Azure virtual machine service
func NewComputeService(resourceGroupName string, sir *secret.SecretItemResponse, logger logrus.FieldLogger) (*computeService, error) {
	cc, err := pkgAzure.NewCloudConnection(&azure.PublicCloud, pkgAzure.NewCredentials(sir.Values))
	if err != nil {
		return nil, emperror.Wrap(err, "failed to create cloud connection")
	}

	return &computeService{
		vmssClient:        cc.GetVirtualMachineScaleSetsClient().VirtualMachineScaleSetsClient,
		logger:            logger.WithField("resourceGroup", resourceGroupName),
		resourceGroupName: resourceGroupName,
	}, nil
}

func (cs *computeService) CreateVirtualMachineScaleSet(location, vmssName, instanceType string, capacity int64, zones []string, tags map[string]string, image *compute.ImageReference, osDisk *compute.VirtualMachineScaleSetOSDisk, osProfile *compute.VirtualMachineScaleSetOSProfile, networkProfile *compute.VirtualMachineScaleSetNetworkProfile) (*compute.VirtualMachineScaleSet, error) {
	logger := cs.logger.WithFields(logrus.Fields{"virtualMachineScaleSetName": vmssName, "location": location})

	logger.Info("create virtual machine scaleset")

	vmssTags := resourceTags(tags)

	vmssParams := compute.VirtualMachineScaleSet{
		Name:     &vmssName,
		Location: &location,
		Zones:    &zones,
		Identity: &compute.VirtualMachineScaleSetIdentity{ Type: compute.ResourceIdentityTypeSystemAssigned },
		Tags:     vmssTags,
		Sku: &compute.Sku{
			Name:     &instanceType,
			Capacity: &capacity,
		},
		VirtualMachineScaleSetProperties: &compute.VirtualMachineScaleSetProperties{
			VirtualMachineProfile: &compute.VirtualMachineScaleSetVMProfile{
				OsProfile: osProfile,
				StorageProfile: &compute.VirtualMachineScaleSetStorageProfile{
					ImageReference: image,
					OsDisk: osDisk,
				},
				NetworkProfile: networkProfile,
			},
			UpgradePolicy: &compute.UpgradePolicy{ Mode: compute.Manual },
		},
	}

	logger.Debug("sending request to create virtual machine scaleset")

	createOrUpdateFuture, err := cs.vmssClient.CreateOrUpdate(context.TODO(), cs.resourceGroupName, vmssName, vmssParams)
	if err != nil {
		return nil, emperror.WrapWith(err, "sending request to create or update virtual machine scale set failed", "resourceGroup", cs.resourceGroupName, "virtualMachineScaleSetName", vmssName, "location", location)
	}

	logger.Debug("waiting for the completion of create or update virtual machine scaleset")

	err = createOrUpdateFuture.WaitForCompletionRef(context.TODO(), cs.vmssClient.Client)
	if err != nil {
		return nil, emperror.WrapWith(err, "waiting for the completion of create or update virtual machine scaleset failed", "resourceGroup", cs.resourceGroupName, "virtualMachineScaleSetName", vmssName, "location", location)
	}

	logger.Debug("getting virtual machine scaleset details")

	vmss, err := createOrUpdateFuture.Result(cs.vmssClient)
	if err != nil {
		return nil, emperror.WrapWith(err, "getting virtual machine scaleset details failed", "resourceGroup", cs.resourceGroupName, "virtualMachineScaleSetName", vmssName, "location", location)
	}

	return &vmss, nil
}

func (cs *computeService) DeleteVirtualMachineScaleSet(vmssName string) error {
	logger := cs.logger.WithFields(logrus.Fields{"virtualMachineScaleSetName": vmssName})

	logger.Info("delete virtual machine scaleset")

	logger.Debug("sending request to delete virtual machine scaleset")

	deleteFuture, err := cs.vmssClient.Delete(context.TODO(), cs.resourceGroupName, vmssName)
	if err != nil {
		return emperror.WrapWith(err, "sending request to delete virtual machine scaleset failed", "resourceGroup", cs.resourceGroupName, "virtualMachineScaleSetName", vmssName)
	}

	logger.Debug("waiting for the completion of delete virtual machine scaleset operation")

	err = deleteFuture.WaitForCompletionRef(context.TODO(), cs.vmssClient.Client)
	if err != nil {
		return emperror.WrapWith(err, "waiting for the completion of delete virtual machine scaleset operation failed", "resourceGroup", cs.resourceGroupName, "virtualMachineScaleSetName", vmssName)
	}

	return nil
}

// NewVirtualMachineScaleSetOSProfile creates a new OS profile
// computerNamePrefix name prefix of VM instances
// adminUserName admin user of VM instances
// sshPublicKeyData ssh public key
func NewVirtualMachineScaleSetOSProfile(computerNamePrefix, adminUserName, sshPublicKeyData string) *compute.VirtualMachineScaleSetOSProfile {

	if adminUserName == "" {
		adminUserName = "azureuser"
	}
	sshAuthKeysPath := fmt.Sprintf("/home/%s/.ssh/authorized_keys", adminUserName)

	disablePasswordAuthentication := true

	return &compute.VirtualMachineScaleSetOSProfile{
		ComputerNamePrefix: &computerNamePrefix,
		AdminUsername:      &adminUserName,
		LinuxConfiguration: &compute.LinuxConfiguration{
			DisablePasswordAuthentication: &disablePasswordAuthentication,
			SSH: &compute.SSHConfiguration{
				PublicKeys: &[]compute.SSHPublicKey{
					{
						Path:    &sshAuthKeysPath,
						KeyData: &sshPublicKeyData,
					},
				},
			},
		},
	}
}

// NewVirtualMachineScaleSetIPConfiguration creates a IP configuration for a virtual machine scaleset network profile
// ipConfigName -name of the ip configuration
// primary - specifies if its the primary ip configuration in case the virtual machine scaleset has multiple network interfaces
func NewVirtualMachineScaleSetIPConfiguration(ipConfigName string, primary bool, subnetID string) *compute.VirtualMachineScaleSetIPConfiguration {
	return &compute.VirtualMachineScaleSetIPConfiguration{
		Name: &ipConfigName,
		VirtualMachineScaleSetIPConfigurationProperties: &compute.VirtualMachineScaleSetIPConfigurationProperties{
			Primary: &primary,
			Subnet: &compute.APIEntityReference{
				ID: &subnetID,
			},
		},
	}
}

// NewVirtualMachineScaleSetNetworkConfiguration creates a new network interface configuration for a virtual machine scaleset
// nicName - name of the network configuration
// primary - specifies whether this config is the primary network config in case the machine scaleset has multiple network configurations
func NewVirtualMachineScaleSetNetworkConfiguration(nicName string, primary, enableIPForwarding bool, securityGroupID string, ipConfigurations []compute.VirtualMachineScaleSetIPConfiguration) *compute.VirtualMachineScaleSetNetworkConfiguration {
	return &compute.VirtualMachineScaleSetNetworkConfiguration{
		Name: &nicName,
		VirtualMachineScaleSetNetworkConfigurationProperties: &compute.VirtualMachineScaleSetNetworkConfigurationProperties{
			Primary: &primary,
			NetworkSecurityGroup: &compute.SubResource{
				ID: &securityGroupID,
			},
			IPConfigurations: &ipConfigurations,
			EnableIPForwarding: &enableIPForwarding,
		},
	}
}

func stringRef(s string) *string {
	return &s
}


