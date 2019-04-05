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

package network

// Network is an interface that cloud specific VPC network implementations must implement
type Network interface {
	CIDRs() []string
	ID() string
	Name() string
}

// Subnet is an interface that cloud specific VPC subnetwork implementations must implement
type Subnet interface {
	CIDRs() []string
	ID() string
	Location() string
	Name() string
}

// RouteTable is an interface that cloud specific VPC route table implementations must implement
type RouteTable interface {
	ID() string
	Name() string
}

// AzureNetworkSecurityRule describes rule of a security group
type AzureNetworkSecurityRule struct {
	Name                 string
	Source               string
	SourcePortRange      string
	Destination          string
	DestinationPortRange string
	Protocol             string // Tcp | Udp
	Direction            string // Inbound | Outbound
	Access               string // Allow | Deny
	Priority             int32  // The priority of the rule. The value can be between 100 and 4096. The priority number must be unique for each rule in the collection. The lower the priority number, the higher the priority of the rule.
	Description          string
}

// Service defines the interface of provider specific network service implementations
type Service interface {
	ListNetworks() ([]Network, error)
	CreateNetwork(networkName string, location string, cidrs []string, tags map[string]string) (Network, error)
	DeleteNetwork(networkName string) error

	ListRouteTables(networkID string) ([]RouteTable, error)
	ListSubnets(networkID string) ([]Subnet, error)
	CreateSubnet(networkName, name string, cidrs []string) (Subnet, error)
	DeleteSubnet(networkName, subnetName string) error
}
