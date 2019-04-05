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

	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2018-01-01/network"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/banzaicloud/pipeline/secret"
	"github.com/goph/emperror"

	intNetwork "github.com/banzaicloud/pipeline/internal/network"
	pkgAzure "github.com/banzaicloud/pipeline/pkg/providers/azure"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type azureNetwork struct {
	cidrs []string
	id    string
	name  string
}

func (a azureNetwork) CIDRs() []string {
	return a.cidrs
}

func (a azureNetwork) ID() string {
	return a.id
}

func (a azureNetwork) Name() string {
	return a.name
}

type azureSubnet struct {
	cidrs    []string
	id       string
	location string
	name     string
}

func (a azureSubnet) CIDRs() []string {
	return a.cidrs
}

func (a azureSubnet) ID() string {
	return a.id
}

func (a azureSubnet) Location() string {
	return a.location
}

func (a azureSubnet) Name() string {
	return a.name
}

type azureRouteTable struct {
	id   string
	name string
}

func (a azureRouteTable) ID() string {
	return a.id
}

func (a azureRouteTable) Name() string {
	return a.name
}

type azureNetworkService struct {
	client               network.VirtualNetworksClient
	subnetClient         network.SubnetsClient
	securityGroupsClient network.SecurityGroupsClient
	loadBalancersClient  network.LoadBalancersClient
	logger               logrus.FieldLogger
	resourceGroupName    string
}

// NewNetworkService returns a new Azure network Service
func NewNetworkService(resourceGroupName string, sir *secret.SecretItemResponse, logger logrus.FieldLogger) (intNetwork.Service, error) {
	cc, err := pkgAzure.NewCloudConnection(&azure.PublicCloud, pkgAzure.NewCredentials(sir.Values))
	if err != nil {
		return nil, emperror.Wrap(err, "failed to create cloud connection")
	}
	return &azureNetworkService{
		client:               cc.GetVirtualNetworksClient().VirtualNetworksClient,
		subnetClient:         cc.GetSubnetsClient().SubnetsClient,
		securityGroupsClient: cc.GetSecurityGroupsClient().SecurityGroupsClient,
		loadBalancersClient:  cc.GetLoabBalancersClient().LoadBalancersClient,
		logger:               logger.WithField("resourceGroup", resourceGroupName),
		resourceGroupName:    resourceGroupName,
	}, nil
}

func (ns *azureNetworkService) ListNetworks() ([]intNetwork.Network, error) {
	rp, err := ns.client.List(context.TODO(), ns.resourceGroupName)
	if err != nil {
		return nil, emperror.Wrap(err, "request to list virtual networks failed")
	}
	var res []intNetwork.Network
	for rp.NotDone() {
		for _, vn := range rp.Values() {
			res = append(res, &azureNetwork{
				cidrs: *vn.AddressSpace.AddressPrefixes,
				id:    *vn.Name, // this is what we want as ID
				name:  *vn.Name,
			})
		}
		err = rp.NextWithContext(context.TODO())
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (ns *azureNetworkService) CreateNetwork(networkName string, location string, cidrs []string, tags map[string]string) (intNetwork.Network, error) {
	logger := ns.logger.WithFields(logrus.Fields{"networkName": networkName, "location": location})

	logger.Info("create virtual network")

	vnTags := resourceTags(tags)

	vnParams := network.VirtualNetwork{
		Location: &location,
		VirtualNetworkPropertiesFormat: &network.VirtualNetworkPropertiesFormat{
			AddressSpace: &network.AddressSpace{
				AddressPrefixes: &cidrs,
			},
		},
		Tags: vnTags,
	}

	logger.Debug("sending request to create or update virtual network")

	createOrUpdateFuture, err := ns.client.CreateOrUpdate(context.TODO(), ns.resourceGroupName, networkName, vnParams)
	if err != nil {
		return nil, emperror.WrapWith(err, "sending request to create or update virtual network failed", "resourceGroup", ns.resourceGroupName, "networkName", networkName)
	}

	logger.Debug("waiting for the completion of create or update virtual network operation")

	err = createOrUpdateFuture.WaitForCompletionRef(context.TODO(), ns.client.Client)
	if err != nil  {
		return nil, emperror.WrapWith(err, "waiting for the completion of create or update virtual network operation failed", "resourceGroup", ns.resourceGroupName, "networkName", networkName)
	}

	logger.Debug("getting virtual network details")

	vn, err := createOrUpdateFuture.Result(ns.client)
	if err != nil {
		return nil, emperror.WrapWith(err, "getting virtual network details failed", "resourceGroup", ns.resourceGroupName, "networkName", networkName)
	}

	return  azureNetwork{
		id: *vn.ID,
		name: *vn.Name,
		cidrs: *vn.AddressSpace.AddressPrefixes,
	}, nil
}

func (ns *azureNetworkService) DeleteNetwork(networkName string) error {
	logger := ns.logger.WithField("networkName", networkName)

	logger.Info("deleting virtual network")

	logger.Debug("sending request to delete virtual network")

	deleteFuture, err := ns.client.Delete(context.TODO(), ns.resourceGroupName, networkName)
	if err != nil {
		return emperror.WrapWith(err, "sending request to delete virtual network failed", "resourceGroup", ns.resourceGroupName, "networkName", networkName)
	}

	logger.Debug("waiting for the completion of virtual network deletion")

	err = deleteFuture.WaitForCompletionRef(context.TODO(), ns.client.Client)
	if err != nil {
		return emperror.WrapWith(err, "waiting for the completion of virtual network deletion failed", "resourceGroup", ns.resourceGroupName, "networkName", networkName)
	}

	return nil
}

func (ns *azureNetworkService) ListRouteTables(networkID string) ([]intNetwork.RouteTable, error) {
	return nil, errors.New("not implemented")
}

func (ns *azureNetworkService) ListSubnets(networkID string) ([]intNetwork.Subnet, error) {
	vn, err := ns.client.Get(context.TODO(), ns.resourceGroupName, networkID, "")
	if err != nil {
		return nil, emperror.Wrap(err, "request to get virtual network failed")
	}
	if vn.Subnets == nil {
		return nil, nil
	}
	res := make([]intNetwork.Subnet, 0, len(*vn.Subnets))
	for _, s := range *vn.Subnets {
		res = append(res, &azureSubnet{
			cidrs:    []string{*s.AddressPrefix},
			id:       *s.ID,
			name:     *s.Name,
			location: *vn.Location,
		})
	}
	return res, nil
}

func (ns *azureNetworkService) CreateSubnet(networkName, subnetName string, cidrs []string) (intNetwork.Subnet, error) {
	logger := ns.logger.WithFields(logrus.Fields{"networkName": networkName, "subnetName": subnetName})

	logger.Info("create subnet")

	subnetParams := network.Subnet{
		SubnetPropertiesFormat: &network.SubnetPropertiesFormat{
			AddressPrefix: &cidrs[0],
		},
	}

	logger.Debug("sending request to create or update subnet")

	createOrUpdateFuture, err := ns.subnetClient.CreateOrUpdate(context.TODO(), ns.resourceGroupName, networkName, subnetName, subnetParams)
	if err != nil {
		return nil, emperror.WrapWith(err, "request to create or update subnet failed", "resourceGroup", ns.resourceGroupName, "networkName", networkName, "subnetName", subnetName)
	}

	logger.Debug("waiting for the completion of create or update subnet operation")

	err = createOrUpdateFuture.WaitForCompletionRef(context.TODO(), ns.subnetClient.Client)

	if err != nil && err != context.Canceled {
		return nil, emperror.WrapWith(err, "waiting for the completion of create or update subnet operation failed", "resourceGroup", ns.resourceGroupName, "networkName", networkName, "subnetName", subnetName)
	}

	logger.Debug("getting subnet details")

	subnet, err := createOrUpdateFuture.Result(ns.subnetClient)
	if err != nil {
		return nil, emperror.WrapWith(err, "getting subnet details failed", "resourceGroup", ns.resourceGroupName, "networkName", networkName, "subnetName", subnetName)
	}

	return azureSubnet{
		id:       *subnet.ID,
		name:     *subnet.Name,
		cidrs:    []string{*subnet.SubnetPropertiesFormat.AddressPrefix},
	}, nil
}

func (ns *azureNetworkService) DeleteSubnet(networkName, subnetName string) error {
	logger := ns.logger.WithFields(logrus.Fields{"networkName": networkName, "subnetName": subnetName})

	logger.Info("delete subnet")

	logger.Debug("sending request to delete subnet")

	deleteFuture, err := ns.subnetClient.Delete(context.TODO(), ns.resourceGroupName, networkName, subnetName)
	if err != nil {
		return emperror.WrapWith(err, "sending request to delete subnet failed", "resourceGroup", ns.resourceGroupName, "networkName", networkName, "subnetName", subnetName)
	}

	logger.Debug("waiting for the completion of subnet deletion")

	err = deleteFuture.WaitForCompletionRef(context.TODO(), ns.subnetClient.Client)
	if err != nil {
		return emperror.WrapWith(err, "waiting for the completion of subnet deletion failed", "resourceGroup", ns.resourceGroupName, "networkName", networkName, "subnetName", subnetName)
	}

	return nil
}


func (ns *azureNetworkService) CreateNetworkSecurityGroup(securityGroupName, location string, rules []intNetwork.AzureNetworkSecurityRule, tags map[string]string) (*network.SecurityGroup, error) {
	logger := ns.logger.WithField("securityGroupName", securityGroupName)

	logger.Info("create network security group")

	nsgTags := resourceTags(tags)

	var securityRules []network.SecurityRule
	for _, rule := range rules {
		rule := rule
		securityRules = append(securityRules, network.SecurityRule{
			Name: &rule.Name,
			SecurityRulePropertiesFormat: &network.SecurityRulePropertiesFormat{
				SourceAddressPrefix:      &rule.Source,
				SourcePortRange:          &rule.SourcePortRange,
				DestinationAddressPrefix: &rule.Destination,
				DestinationPortRange:     &rule.DestinationPortRange,
				Protocol:                 network.SecurityRuleProtocol(rule.Protocol),
				Direction:                network.SecurityRuleDirection(rule.Direction),
				Access:                   network.SecurityRuleAccess(rule.Access),
				Priority:                 &rule.Priority,
				Description:              &rule.Description,
			},
		})
	}

	nsgParams := network.SecurityGroup{
		SecurityGroupPropertiesFormat: &network.SecurityGroupPropertiesFormat{
			SecurityRules: &securityRules,
		},
		Location: &location,
		Tags:     nsgTags,
	}

	logger.Debug("sending request to create network security group")

	createOrUpdateFuture, err := ns.securityGroupsClient.CreateOrUpdate(context.TODO(), ns.resourceGroupName, securityGroupName, nsgParams)
	if err != nil {
		return nil, emperror.WrapWith(err, "sending request to create or update network security group", "resourceGroup", ns.resourceGroupName, "securitryGroupName", securityGroupName)
	}

	logger.Debug("waiting for the completion of create or update network security group")

	err = createOrUpdateFuture.WaitForCompletionRef(context.TODO(), ns.subnetClient.Client)

	if err != nil {
		return nil, emperror.WrapWith(err, "waiting for the completion of create or update network security group failed", "resourceGroup", ns.resourceGroupName, "securitryGroupName", securityGroupName)
	}

	logger.Debug("getting network security group details")

	nsg, err := createOrUpdateFuture.Result(ns.securityGroupsClient)
	if err != nil {
		return nil, emperror.WrapWith(err, "getting subnet details failed", "resourceGroup", ns.resourceGroupName, "securitryGroupName", securityGroupName)
	}


	return &nsg, nil
}

func (ns *azureNetworkService) DeleteNetworkSecurityGroup(securityGroupName string) error {
	logger := ns.logger.WithField("securityGroupName", securityGroupName)

	logger.Info("delete network security group")

	logger.Debug("sending request to delete network security group")

	deleteFuture, err := ns.securityGroupsClient.Delete(context.TODO(), ns.resourceGroupName, securityGroupName)
	if err != nil {
		return emperror.WrapWith(err, "sending request to delete network security group failed", "resourceGroup", ns.resourceGroupName, "securityGroupName", securityGroupName)
	}

	logger.Debug("waiting for the completion of network security group deletion")

	err = deleteFuture.WaitForCompletionRef(context.TODO(), ns.subnetClient.Client)
	if err != nil {
		return emperror.WrapWith(err, "waiting for the completion of network security group deletion failed", "resourceGroup", ns.resourceGroupName, "securityGroupName", securityGroupName)
	}

	return nil
}


func (ns *azureNetworkService) CreateStandardLoadBalancer(lbName, location string, tags map[string]string, zones []string) {

	lbTags := resourceTags(tags)

	lbParams := network.LoadBalancer{
		Sku:      &network.LoadBalancerSku{Name: network.LoadBalancerSkuNameStandard},
		Location: &location,
		Tags:     lbTags,
		LoadBalancerPropertiesFormat: &network.LoadBalancerPropertiesFormat{

		},
	}
	_, _ = ns.loadBalancersClient.CreateOrUpdate(context.TODO(), ns.resourceGroupName, lbName, lbParams)
}

// resourceTags converts map[string]string to map[string]*string
func resourceTags(tags map[string]string) map[string]*string {
	azTags := make(map[string]*string, len(tags))
	for k, v := range tags {
		v := v
		azTags[k] = &v
	}

	return azTags
}


