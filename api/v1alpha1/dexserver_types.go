// Copyright Red Hat

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Org holds org-team filters (GitHub), in which teams are optional.
type Org struct {
	// Organization name in github (not slug, full name). Only users in this github
	// organization can authenticate.
	Name string `json:"name"`

	// Names of teams in a github organization. A user will be able to
	// authenticate if they are members of at least one of these teams. Users
	// in the organization can authenticate if this field is omitted from the
	// config file.
	Teams []string `json:"teams,omitempty"`
}

// GitHubConfigSpec describes the configuration specific to the GitHub connector
type GitHubConfigSpec struct {
	ClientID        string                 `json:"clientID,omitempty"`
	ClientSecretRef corev1.SecretReference `json:"clientSecretRef,omitempty"`
	RedirectURI     string                 `json:"redirectURI,omitempty"`
	Org             string                 `json:"org,omitempty"`
	Orgs            []Org                  `json:"orgs,omitempty"`
	HostName        string                 `json:"hostName,omitempty"`
	RootCA          string                 `json:"rootCA,omitempty"`
	TeamNameField   string                 `json:"teamNameField,omitempty"`
	LoadAllGroups   bool                   `json:"loadAllGroups,omitempty"`
	UseLoginAsID    bool                   `json:"useLoginAsID,omitempty"`
}

// MicrosoftConfigSpec describes the configuration specific to the Microsoft connector
type MicrosoftConfigSpec struct {
	ClientID        string                 `json:"clientID,omitempty"`
	ClientSecretRef corev1.SecretReference `json:"clientSecretRef,omitempty"`
	RedirectURI     string                 `json:"redirectURI,omitempty"`
	// groups claim in dex is only supported when tenant is specified in Microsoft connector config.
	Tenant string `json:"tenant,omitempty"`
	// When the groups claim is present in a request to dex and tenant is configured,
	// dex will query Microsoft API to obtain a list of groups the user is a member of.
	// onlySecurityGroups configuration option restricts the list to include only security groups.
	// By default all groups (security, Office 365, mailing lists) are included.
	OnlySecurityGroups bool     `json:"onlySecurityGroups,omitempty"`
	Groups             []string `json:"groups,omitempty"`
}

// LDAP UserMatcher holds information about user and group matching
type UserMatcher struct {
	UserAttr  string `json:"userAttr"`
	GroupAttr string `json:"groupAttr"`
}

// LDAP User entry search configuration
type UserSearchSpec struct {
	// BaseDN to start the search from. For example "cn=users,dc=example,dc=com"
	BaseDN string `json:"baseDN,omitempty"`

	// Optional filter to apply when searching the directory. For example "(objectClass=person)"
	Filter string `json:"filter,omitempty"`

	// Attribute to match against the inputted username. This will be translated and combined
	// with the other filter as "(<attr>=<username>)".
	Username string `json:"username,omitempty"`

	// Can either be:
	// * "sub" - search the whole sub tree
	// * "one" - only search one level
	Scope string `json:"scope,omitempty"`

	// A mapping of attributes on the user entry to claims.
	IDAttr    string `json:"idAttr,omitempty"`    // Defaults to "uid"
	EmailAttr string `json:"emailAttr,omitempty"` // Defaults to "mail"
	NameAttr  string `json:"nameAttr,omitempty"`  // No default.
}

// LDAP Group search configuration
type GroupSearchSpec struct {
	// BaseDN to start the search from. For example "cn=groups,dc=example,dc=com"
	BaseDN string `json:"baseDN,omitempty"`

	// Optional filter to apply when searching the directory. For example "(objectClass=posixGroup)"
	Filter string `json:"filter,omitempty"`

	Scope string `json:"scope,omitempty"` // Defaults to "sub"

	// Array of the field pairs used to match a user to a group.
	// See the "UserMatcher" struct for the exact field names
	//
	// Each pair adds an additional requirement to the filter that an attribute in the group
	// match the user's attribute value. For example that the "members" attribute of
	// a group matches the "uid" of the user. The exact filter being added is:
	//
	//   (userMatchers[n].<groupAttr>=userMatchers[n].<userAttr value>)
	//
	UserMatchers []UserMatcher `json:"userMatchers,omitempty"`

	// The attribute of the group that represents its name.
	NameAttr string `json:"nameAttr,omitempty"`
}

// LDAPConfigSpec describes the configuration specific to the LDAP connector
type LDAPConfigSpec struct {
	// The host and optional port of the LDAP server. If port isn't supplied, it will be guessed based on the TLS configuration. 389 or 636.
	Host string `json:"host,omitempty"`
	// Required if LDAP host does not use TLS
	InsecureNoSSL bool `json:"insecureNoSSL,omitempty"`
	// Connect to the insecure port then issue a StartTLS command to negotiate a
	// secure connection. If unsupplied secure connections will use the LDAPS
	// protocol.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
	// Connect to the insecure port and then issue a StartTLS command to negotiate a secure connection.
	// If unspecified, connections will use the ldaps:// protocol
	StartTLS bool `json:"startTLS,omitempty"`
	// Reference to the secret containing a trusted Root CA file - file name and format: "ca.crt"
	// Note: If the server uses self-signed certificates, include files with names "tls.crt" and "tls.key" (representing client certificate and key) in the same secret
	RootCARef corev1.SecretReference `json:"rootCARef,omitempty"`
	// A raw certificate file can also be provided inline as a base64 encoded PEM file.
	RootCAData []byte `json:"rootCAData,omitempty"`
	// The DN for an application service account. The connector uses the bindDN and bindPW as credentials to
	// search for users and groups. Not required if the LDAP server provides access for anonymous auth.
	BindDN string `json:"bindDN,omitempty"`
	// Secret reference to the password for an application service account. The connector uses the bindDN and bindPW
	// as credentials to search for users and groups. Not required if the LDAP server provides access
	// for anonymous auth.
	BindPWRef corev1.SecretReference `json:"bindPWRef,omitempty"`
	// The attribute to display in the provided password prompt. If unset, will display "Username"
	UsernamePrompt string `json:"usernamePrompt,omitempty"`
	// User entry search configuration.
	UserSearch UserSearchSpec `json:"userSearch,omitempty"`
	// Group search configuration.
	GroupSearch GroupSearchSpec `json:"groupSearch,omitempty"`
}

// ConnectorSpec defines the OIDC connector config details
type ConnectorSpec struct {
	Name string `json:"name,omitempty"`
	// +kubebuilder:validation:Enum=github;ldap;microsoft
	Type ConnectorType `json:"type,omitempty"`
	// Unique Id for the connector
	Id        string              `json:"id,omitempty"`
	GitHub    GitHubConfigSpec    `json:"github,omitempty"`
	LDAP      LDAPConfigSpec      `json:"ldap,omitempty"`
	Microsoft MicrosoftConfigSpec `json:"microsoft,omitempty"`
}

type ConnectorType string

const (
	// ConnectorTypeGitHub enables Dex to use the GitHub OAuth2 flow to identify the end user through their GitHub account
	ConnectorTypeGitHub ConnectorType = "github"

	// ConnectorTypeLDAP enables Dex to allow email/password based authentication, backed by an LDAP directory
	ConnectorTypeLDAP ConnectorType = "ldap"

	// ConnectorTypeMicrosoft enables Dex to use the Microsoft OAuth2 flow to identify the end user through their Microsoft account
	ConnectorTypeMicrosoft ConnectorType = "microsoft"
)

// DexServerSpec defines the desired state of DexServer
type DexServerSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// TODO: Issuer references the dex instance web URI. Should this be returned as status?
	Issuer     string          `json:"issuer,omitempty"`
	Connectors []ConnectorSpec `json:"connectors,omitempty"`
	// Optional bring-your-own-certificate. Otherwise, the default certificate is used for dex server Ingress.
	IngressCertificateRef corev1.LocalObjectReference `json:"ingressCertificateRef,omitempty"`
}

const (
	DexServerConditionTypeApplied string = "Applied"
)

// DexServerStatus defines the observed state of DexServer
type DexServerStatus struct {
	// +optional
	State string `json:"state,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
	// +optional
	RelatedObjects []RelatedObjectReference `json:"relatedObjects,omitempty"`
	// Conditions contains the different condition statuses for this DexServer.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

type RelatedObjectReference struct {
	// the Kind of the referenced resource
	Kind string `json:"kind,omitempty"`
	// The name of the referenced object
	Name string `json:"name,omitempty"`
	// The namespace of the referenced object
	Namespace string `json:"namespace,omitempty"`
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
