/*
Copyright 2021.

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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StaticPasswordSpec allows us to define login credentials. Do not expect us to use this.
type StaticPasswordSpec struct {
	Email string `json:"email,omitempty"`
}

// StorageSpec defines how/if we persist the configuration to a database on store in K8s.
type StorageSpec struct {
	Type string `json:"type,omitempty"`
}

// WebSpec defines override for cert to dex server.
type WebSpec struct {
	Http    string `json:"http,omitempty"`
	Https   string `json:"https,omitempty"`
	TlsCert string `json:"tlsCert,omitempty"`
	TlsKey  string `json:"tlsKey,omitempty"`
}

// GrpcSpec defines override options on how we run grpc server. Addr should not need to change. The certs are required.
type GrpcSpec struct {
	Addr        string `json:"addr,omitempty"`
	TlsCert     string `json:"tlsCert,omitempty"`
	TlsKey      string `json:"tlsKey,omitempty"`
	TlsClientCA string `json:"tlsClientCA,omitempty"`
}

// ExpirySpec defines how we expire
type ExpirySpec struct {
	DeviceRequests string `json:"deviceRequests,omitempty"`
}

// LoggerSpec defines loggingoptions. Optional
type LoggerSpec struct {
	Level  string `json:"level,omitempty"`
	Format string `json:"format,omitempty"`
}

// Oauth2Spec defines dex behavior flags
type Oauth2Spec struct {
	ResponseTypes         []string `json:"responseTypes,omitempty"`
	SkipApprovalScreen    bool     `json:"skipApprovalScreen,omitempty"`
	AlwaysShowLoginScreen bool     `json:"alwaysShowLoginScreen,omitempty"`
	PasswordConnector     string   `json:"passwordConnector,omitempty"`
}

// ConfigSpec describes the client id and secret. The RedirectURI should be returned?
type ConfigSpec struct {
	ClientID        string                 `json:"clientID,omitempty"`
	ClientSecretRef corev1.ObjectReference `json:"clientSecretRef,omitempty"`
	// TODO: confirm if we set this, or allow this to be passed in?
	RedirectURI string `json:"redirectURI,omitempty"`
	Org         string `json:"org,omitempty"`
}

// ConnectorSpec defines the OIDC connector config details
type ConnectorSpec struct {
	Name string `json:"name,omitempty"`
	// +kubebuilder:validation:Enum=github;ldap
	Type   ConnectorType `json:"type,omitempty"`
	Id     string        `json:"id,omitempty"`
	Config ConfigSpec    `json:"config,omitempty"`
}

type ConnectorType string

const (
	// ConnectorTypeGitHub enables Dex to use the GitHub OAuth2 flow to identify the end user through their GitHub account
	ConnectorTypeGitHub ConnectorType = "github"

	// ConnectorTypeLDAP enables Dex to allow email/password based authentication, backed by an LDAP directory
	ConnectorTypeLDAP ConnectorType = "ldap"
)

// DexServerSpec defines the desired state of DexServer
type DexServerSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// Foo is an example field of DexServer. Edit dexserver_types.go to remove/update
	Foo string `json:"foo,omitempty"`
	// TODO: Issuer references the dex instance web URI. Should this be returned as status?
	Issuer           string               `json:"issuer,omitempty"`
	EnablePasswordDB bool                 `json:"enablepassworddb,omitempty"`
	StaticPasswords  []StaticPasswordSpec `json:"staticpasswords,omitempty"`
	Storage          StorageSpec          `json:"storage,omitempty"`
	Web              WebSpec              `json:"web,omitempty"`
	Grpc             GrpcSpec             `json:"grpc,omitempty"`
	Expiry           ExpirySpec           `json:"expiry,omitempty"`
	Logger           LoggerSpec           `json:"logger,omitempty"`
	Oauth2           Oauth2Spec           `json:"oauth2,omitempty"`
	Connectors       []ConnectorSpec      `json:"connectors,omitempty"`
}

// DexServerStatus defines the observed state of DexServer
type DexServerStatus struct {
	// +optional
	State string `json:"state,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// DexServer is the Schema for the dexservers API
type DexServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DexServerSpec   `json:"spec,omitempty"`
	Status DexServerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// DexServerList contains a list of DexServer
type DexServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DexServer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DexServer{}, &DexServerList{})
}
