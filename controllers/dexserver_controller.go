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

package controllers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/ghodss/yaml"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	clusteradmapply "open-cluster-management.io/clusteradm/pkg/helpers/apply"
	"open-cluster-management.io/clusteradm/pkg/helpers/asset"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/identitatem/dex-operator/api/v1alpha1"
	authv1alpha1 "github.com/identitatem/dex-operator/api/v1alpha1"
	deploy "github.com/identitatem/dex-operator/deploy"
)

const (
	SECRET_MTLS_NAME      = "grpc-mtls"
	SECRET_WEB_TLS_SUFFIX = "-tls-secret"
	SERVICE_ACCOUNT_NAME  = "dex-operator-dexsso"
	GRPC_SERVICE_NAME     = "grpc"
	DEX_IMAGE_ENV_NAME    = "RELATED_IMAGE_DEX"
)

// DexServerReconciler reconciles a DexServer object
type DexServerReconciler struct {
	client.Client
	KubeClient         kubernetes.Interface
	DynamicClient      dynamic.Interface
	APIExtensionClient apiextensionsclient.Interface
	Scheme             *runtime.Scheme
}

//+kubebuilder:rbac:groups=auth.identitatem.io,resources=dexservers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=auth.identitatem.io,resources=dexservers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=auth.identitatem.io,resources=dexservers/finalizers,verbs=update
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;delete
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;patch;delete
//+kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=route.openshift.io,resources=routes/custom-host,verbs=create;patch
//+kubebuilder:rbac:groups="rbac.authorization.k8s.io",resources={clusterroles},verbs=get;list;watch;create;update;patch;delete;escalate;bind
//+kubebuilder:rbac:groups="rbac.authorization.k8s.io",resources={clusterrolebindings},verbs=get;list;create;watch;update;patch;delete
//+kubebuilder:rbac:groups="apiextensions.k8s.io",resources={customresourcedefinitions},verbs=get;list;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses/status,verbs=get;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the DexServer object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *DexServerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)
	log.V(1).Info("Reconciling...")

	// Fetch the DexServer instance
	dexServer := &authv1alpha1.DexServer{}
	if err := r.Client.Get(
		ctx,
		req.NamespacedName,
		dexServer,
	); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Prepare Mutual TLS for gRPC connection
	if err := r.configureMTLSSecret(dexServer, ctx); err != nil {
		log.Error(err, "failed to configure mTLS Secret")
		return ctrl.Result{}, err
	}

	if err := r.syncConfigMap(dexServer, ctx); err != nil {
		log.Error(err, "failed to sync ConfigMap")
		return ctrl.Result{}, err
	}

	if err := r.syncService(dexServer, ctx); err != nil {
		log.Error(err, "failed to sync http Service")
		return ctrl.Result{}, err
	}

	if err := r.syncServiceGrpc(dexServer, ctx); err != nil {
		log.Error(err, "failed to sync grpc Service")
		return ctrl.Result{}, err
	}

	if err := r.syncServiceAccount(dexServer, ctx); err != nil {
		log.Error(err, "failed to sync ServiceAccount")
		return ctrl.Result{}, err
	}

	if err := r.syncClusterRoleBinding(dexServer, ctx); err != nil {
		log.Error(err, "failed to sync ClusterRoleBinding")
		return ctrl.Result{}, err
	}

	if err := r.syncDeployment(dexServer, ctx); err != nil {
		log.Error(err, "failed to sync Deployment")
		return ctrl.Result{}, err
	}

	if err := r.syncIngress(dexServer, ctx); err != nil {
		log.Error(err, "failed to sync Ingress")
		return ctrl.Result{}, err
	}

	// // TODO(cdoan): check CA or CERT renew?
	return ctrl.Result{}, nil
}

func getConnectorSecretFromRef(connector v1alpha1.ConnectorSpec, m *authv1alpha1.DexServer, r *DexServerReconciler, ctx context.Context) (string, error) {
	var secretNamespace, secretName string

	switch connector.Type {
	case authv1alpha1.ConnectorTypeGitHub:
		secretName = connector.GitHub.ClientSecretRef.Name
		if secretNamespace = connector.GitHub.ClientSecretRef.Namespace; secretNamespace == "" {
			secretNamespace = m.Namespace
		}
		resource := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, resource); err != nil && errors.IsNotFound(err) {
			return "", err
		}
		return string(resource.Data["clientSecret"]), nil
	case authv1alpha1.ConnectorTypeMicrosoft:
		secretName = connector.Microsoft.ClientSecretRef.Name
		if secretNamespace = connector.Microsoft.ClientSecretRef.Namespace; secretNamespace == "" {
			secretNamespace = m.Namespace
		}
		resource := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, resource); err != nil && errors.IsNotFound(err) {
			return "", err
		}
		return string(resource.Data["clientSecret"]), nil
	case authv1alpha1.ConnectorTypeLDAP:
		secretName = connector.LDAP.BindPWRef.Name
		if secretNamespace = connector.LDAP.BindPWRef.Namespace; secretNamespace == "" {
			secretNamespace = m.Namespace
		}
		resource := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, resource); err != nil && errors.IsNotFound(err) {
			return "", err
		}
		return string(resource.Data["bindPW"]), nil
	default:
		return "", fmt.Errorf("could not retrieve secret")
	}

}

// Define the secret for grpc Mutual TLS. This secret is volume mounted on the dex instance pod. The client cert should be loaded by the gRPC client code.
func (r *DexServerReconciler) defineMTLSSecret(m *authv1alpha1.DexServer, caPEM, caPrivKeyPEM, certPEM, certPrivKeyPEM, clientPEM, clientPrivKeyPEM *bytes.Buffer) *corev1.Secret {
	labels := map[string]string{
		"app": m.Name,
	}
	secretSpec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SECRET_MTLS_NAME,
			Namespace: m.Namespace,
			Labels:    labels,
		},
		Data: map[string][]byte{
			"ca.crt":     caPEM.Bytes(),
			"ca.key":     caPrivKeyPEM.Bytes(),
			"tls.crt":    append(certPEM.Bytes(), certPEM.Bytes()...),
			"tls.key":    certPrivKeyPEM.Bytes(),
			"client.crt": append(clientPEM.Bytes(), clientPEM.Bytes()...),
			"client.key": clientPrivKeyPEM.Bytes(),
		},
	}
	ctrl.SetControllerReference(m, secretSpec, r.Scheme)
	return secretSpec
}

func isNotDefinedMTLSSecret(m *authv1alpha1.DexServer, r *DexServerReconciler, ctx context.Context) bool {
	resource := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: fmt.Sprintf(SECRET_MTLS_NAME), Namespace: m.Namespace}, resource); err != nil && errors.IsNotFound(err) {
		return true
	}
	return false
}

func (r *DexServerReconciler) configureMTLSSecret(dexServer *authv1alpha1.DexServer, ctx context.Context) error {
	log := ctrllog.FromContext(ctx)
	log.Info("configureMTLSSecret")
	if isNotDefinedMTLSSecret(dexServer, r, ctx) {
		caPEM, caPrivKeyPEM, certPEM, certPrivKeyPEM, clientPEM, clientPrivKeyPEM, err := generateMTLSCerts(dexServer.Namespace)
		if err != nil {
			log.Error(err, "failed to generate mTLS certs")
			return err
		}
		spec := r.defineMTLSSecret(dexServer, caPEM, caPrivKeyPEM, certPEM, certPrivKeyPEM, clientPEM, clientPrivKeyPEM)
		log.Info("Creating a new MTLS Secret", "Secret.Namespace", spec.Namespace, "Secret.Name", spec.Name)
		if err := r.Create(ctx, spec); err != nil {
			log.Error(err, "failed to create MTLS Secret", "Secret.Name", spec.Name)
			return err
		}
	}
	return nil
}

func (r *DexServerReconciler) syncServiceAccount(dexServer *authv1alpha1.DexServer, ctx context.Context) error {
	log := ctrllog.FromContext(ctx)
	log.Info("syncServiceAccount", "ServiceAccount.Name", SERVICE_ACCOUNT_NAME)

	values := struct {
		ServiceAccountName string
		DexServer          *authv1alpha1.DexServer
	}{
		ServiceAccountName: SERVICE_ACCOUNT_NAME,
		DexServer:          dexServer,
	}

	files := []string{
		"dex-server/service_account.yaml",
	}

	applier, readerDeploy := r.getApplierAndReader(dexServer)
	_, err := applier.ApplyDirectly(readerDeploy, values, false, "", files...)
	if err != nil {
		return err
	}

	return nil
}

func (r *DexServerReconciler) syncClusterRoleBinding(dexServer *authv1alpha1.DexServer, ctx context.Context) error {
	log := ctrllog.FromContext(ctx)
	clusterRoleBindingName := SERVICE_ACCOUNT_NAME + "-" + dexServer.Namespace
	log.Info("syncClusterRoleBinding", "ClusterRoleBinding.Name", clusterRoleBindingName)

	values := struct {
		ClusterRoleName        string
		ServiceAccountName     string
		ClusterRoleBindingName string
		DexServer              *authv1alpha1.DexServer
	}{
		ClusterRoleName:        SERVICE_ACCOUNT_NAME,
		ServiceAccountName:     SERVICE_ACCOUNT_NAME,
		ClusterRoleBindingName: clusterRoleBindingName,
		DexServer:              dexServer,
	}

	files := []string{
		"dex-server/cluster_role_binding.yaml",
	}

	applier, readerDeploy := r.getApplierAndReader(dexServer)
	_, err := applier.ApplyDirectly(readerDeploy, values, false, "", files...)
	if err != nil {
		return err
	}

	return nil
}

func getDexImagePullSpec() (string, error) {
	imageName := os.Getenv(DEX_IMAGE_ENV_NAME)
	if len(imageName) == 0 {
		return "", fmt.Errorf("required environment variable %v is empty or not set", DEX_IMAGE_ENV_NAME)
	}
	return imageName, nil
}

// Defines the dex instance (dex server).
func (r *DexServerReconciler) syncDeployment(dexServer *authv1alpha1.DexServer, ctx context.Context) error {
	dexImage, err := getDexImagePullSpec()
	if err != nil {
		return err
	}
	log := ctrllog.FromContext(ctx)
	log.Info("syncDeployment", "DexImage", dexImage)

	var additionalVolumeMounts []corev1.VolumeMount
	var additionalVolumes []corev1.Volume
	var additionalVolumeMountsYaml, additionalVolumesYaml []byte
	// Update Volume Mounts based on rootCA secret refs for LDAP connectors (Trusted Root CA and optionally client cert and key files)
	// Iterate over connectors defined in the DexServer to create the dex configuration for connectors
	for _, connector := range dexServer.Spec.Connectors {
		if connector.Type == authv1alpha1.ConnectorTypeLDAP && connector.LDAP.RootCARef.Name != "" {
			newVolume := corev1.Volume{
				Name: "ldapcerts-" + connector.Id,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: connector.LDAP.RootCARef.Name,
					},
				},
			}

			newVolumeMount := corev1.VolumeMount{
				Name:      "ldapcerts-" + connector.Id,
				MountPath: "/etc/dex/ldapcerts/" + connector.Id,
			}

			additionalVolumeMounts = append(additionalVolumeMounts, newVolumeMount)
			additionalVolumes = append(additionalVolumes, newVolume)
		}
	}
	if len(additionalVolumeMounts) > 0 {
		// Get yaml representation of additional volumeMounts and volumes
		additionalVolumeMountsYaml, err = yaml.Marshal(&additionalVolumeMounts)
		if err != nil {
			log.Error(err, "failed to marshal yaml for additional volume mounts")
		}
		additionalVolumesYaml, err = yaml.Marshal(&additionalVolumes)
		if err != nil {
			log.Error(err, "failed to marshal yaml for additional volumes")
		}
	}

	// Add the dex ConfigMap sha256 checksum to the Deployment to trigger rolling restarts when the ConfigMap changes
	dexConfigMap := &corev1.ConfigMap{}
	var dexConfigMapHash string
	if err := r.Get(ctx, types.NamespacedName{Name: dexServer.Name, Namespace: dexServer.Namespace}, dexConfigMap); err != nil {
		// If ConfigMap is not yet found, the annotation will be omitted, and will be added once the ConfigMap is created
		if !errors.IsNotFound(err) {
			log.Error(err, "error getting dex server configmap")
			return err
		}
	} else {
		jsonData, err := json.Marshal(dexConfigMap)
		if err != nil {
			log.Error(err, "failed to marshal configmap JSON")
			return err
		}
		h := sha256.New()
		h.Write([]byte(jsonData))
		dexConfigMapHash = fmt.Sprintf("%x", h.Sum(nil))
		// log.Info("computed hash", "dexConfigMapHash", dexConfigMapHash)
	}

	values := struct {
		DexImage               string
		DexConfigMapHash       string
		ServiceAccountName     string
		TlsSecretName          string
		MtlsSecretName         string
		DexServer              *authv1alpha1.DexServer
		AdditionalVolumeMounts string
		AdditionalVolumes      string
	}{
		DexImage:           dexImage,
		DexConfigMapHash:   dexConfigMapHash,
		ServiceAccountName: SERVICE_ACCOUNT_NAME,
		// this secret is generated using service serving certificate via service annotation
		// service.beta.openshift.io/serving-cert-secret-name: dexServer.Name-tls-secret
		TlsSecretName: fmt.Sprintf(dexServer.Name + SECRET_WEB_TLS_SUFFIX),
		// This secret is generated by this controller, here we load the server side cert and ca
		// service.beta.openshift.io/serving-cert-secret-name: dexServer.Name-mtls-secret
		MtlsSecretName:         SECRET_MTLS_NAME,
		DexServer:              dexServer,
		AdditionalVolumeMounts: string(additionalVolumeMountsYaml),
		AdditionalVolumes:      string(additionalVolumesYaml),
	}

	files := []string{
		"dex-server/deployment.yaml",
	}

	applier, readerDeploy := r.getApplierAndReader(dexServer)
	_, err = applier.ApplyDeployments(readerDeploy, values, false, "", files...)
	if err != nil {
		return err
	}

	return nil
}

func (r *DexServerReconciler) syncService(dexServer *authv1alpha1.DexServer, ctx context.Context) error {
	log := ctrllog.FromContext(ctx)
	log.Info("syncService", "DexServer.Name", dexServer.Name, "DexServer.Namespace", dexServer.Namespace)

	values := struct {
		ServingCertSecretName string
		DexServer             *authv1alpha1.DexServer
	}{
		ServingCertSecretName: fmt.Sprintf(dexServer.Name + SECRET_WEB_TLS_SUFFIX),
		DexServer:             dexServer,
	}

	files := []string{
		"dex-server/service_http.yaml",
	}

	applier, readerDeploy := r.getApplierAndReader(dexServer)
	_, err := applier.ApplyDirectly(readerDeploy, values, false, "", files...)
	if err != nil {
		return err
	}

	return nil
}

func (r *DexServerReconciler) getApplierAndReader(dexServer *authv1alpha1.DexServer) (clusteradmapply.Applier, asset.ScenarioReader) {
	applierBuilder := &clusteradmapply.ApplierBuilder{}
	applier := applierBuilder.
		WithClient(r.KubeClient, r.APIExtensionClient, r.DynamicClient).
		WithOwner(dexServer, true, true, r.Scheme).
		Build()

	readerDeploy := deploy.GetScenarioResourcesReader()
	return applier, readerDeploy
}

func (r *DexServerReconciler) syncServiceGrpc(dexServer *authv1alpha1.DexServer, ctx context.Context) error {
	log := ctrllog.FromContext(ctx)
	log.Info("syncServiceGrpc", "DexServer.Name", dexServer.Name, "DexServer.Namespace", dexServer.Namespace)

	values := struct {
		GrpcServiceName string
		DexServer       *authv1alpha1.DexServer
	}{
		GrpcServiceName: GRPC_SERVICE_NAME,
		DexServer:       dexServer,
	}

	files := []string{
		"dex-server/service_grpc.yaml",
	}

	applier, readerDeploy := r.getApplierAndReader(dexServer)
	_, err := applier.ApplyDirectly(readerDeploy, values, false, "", files...)
	if err != nil {
		return err
	}

	return nil
}

type DexConnectorConfigSpec struct {
	// Common fields between GitHub and Microsoft OAuth2 configuration
	ClientID     string `yaml:"clientID,omitempty"`
	ClientSecret string `yaml:"clientSecret,omitempty"`
	RedirectURI  string `yaml:"redirectURI,omitempty"`

	// Github configuration
	Org           string             `yaml:"org,omitempty"`
	Orgs          []authv1alpha1.Org `yaml:"orgs,omitempty"`
	HostName      string             `yaml:"hostName,omitempty"`
	TeamNameField string             `yaml:"teamNameField,omitempty"`
	LoadAllGroups bool               `yaml:"loadAllGroups,omitempty"`
	UseLoginAsID  bool               `yaml:"useLoginAsID,omitempty"`

	// Microsoft configuration
	Tenant             string   `yaml:"tenant,omitempty"`
	OnlySecurityGroups bool     `yaml:"onlySecurityGroups,omitempty"`
	Groups             []string `yaml:"groups,omitempty"`

	// LDAP configuration
	Host               string                       `yaml:"host,omitempty"`
	InsecureNoSSL      bool                         `yaml:"insecureNoSSL,omitempty"`
	InsecureSkipVerify bool                         `yaml:"insecureSkipVerify,omitempty"`
	StartTLS           bool                         `yaml:"startTLS,omitempty"`
	ClientCA           string                       `yaml:"clientCA,omitempty"`
	ClientKey          string                       `yaml:"clientKey,omitempty"`
	RootCAData         []byte                       `yaml:"rootCAData,omitempty"`
	BindDN             string                       `yaml:"bindDN,omitempty"`
	BindPW             string                       `yaml:"bindPW,omitempty"`
	UsernamePrompt     string                       `yaml:"usernamePrompt,omitempty"`
	UserSearch         authv1alpha1.UserSearchSpec  `yaml:"userSearch,omitempty"`
	GroupSearch        authv1alpha1.GroupSearchSpec `yaml:"groupSearch,omitempty"`

	// Common field between GitHub and LDAP configs
	RootCA string `json:"rootCA,omitempty"`
}

type DexConnectorSpec struct {
	// +kubebuilder:validation:Enum=github;ldap
	Type   string                 `yaml:"type,omitempty"`
	Id     string                 `yaml:"id,omitempty"`
	Name   string                 `yaml:"name,omitempty"`
	Config DexConnectorConfigSpec `yaml:"config,omitempty"`
}

func (r *DexServerReconciler) syncConfigMap(dexServer *authv1alpha1.DexServer, ctx context.Context) error {
	log := ctrllog.FromContext(ctx)
	log.Info("syncConfigMap")

	connectors := []DexConnectorSpec{}

	// Iterate over connectors defined in the DexServer to create the dex configuration for connectors

	for _, connector := range dexServer.Spec.Connectors {
		var newConnector DexConnectorSpec
		switch connector.Type {
		case authv1alpha1.ConnectorTypeGitHub:
			// Get Github ClientSecret from SecretRef
			clientSecret, err := getConnectorSecretFromRef(connector, dexServer, r, ctx)

			if err != nil {
				log.Error(err, "Error getting client secret")
				return nil
			}

			newConnector = DexConnectorSpec{
				Type: string(authv1alpha1.ConnectorTypeGitHub),
				Id:   connector.Id,
				Name: connector.Name,
				Config: DexConnectorConfigSpec{
					ClientID:     connector.GitHub.ClientID,
					ClientSecret: clientSecret,
					RedirectURI:  connector.GitHub.RedirectURI,
					Org:          connector.GitHub.Org,
					Orgs:         connector.GitHub.Orgs,
				},
			}
		case authv1alpha1.ConnectorTypeMicrosoft:
			// Get Microsoft ClientSecret from SecretRef
			clientSecret, err := getConnectorSecretFromRef(connector, dexServer, r, ctx)

			if err != nil {
				log.Error(err, "Error getting client secret")
				return nil
			}

			newConnector = DexConnectorSpec{
				Type: string(authv1alpha1.ConnectorTypeMicrosoft),
				Id:   connector.Id,
				Name: connector.Name,
				Config: DexConnectorConfigSpec{
					ClientID:     connector.Microsoft.ClientID,
					ClientSecret: clientSecret,
					RedirectURI:  connector.Microsoft.RedirectURI,
					Tenant:       connector.Microsoft.Tenant,
				},
			}
		case authv1alpha1.ConnectorTypeLDAP:
			// Get LDAP BindPW from SecretRef
			bindPW, err := getConnectorSecretFromRef(connector, dexServer, r, ctx)

			if err != nil {
				log.Error(err, "Error getting bind pw")
				return nil
			}

			// If there is a secret reference to the trusted Root CA
			var rootCAPath, clientCAPath, clientKeyPath string
			if connector.LDAP.RootCARef.Name != "" {
				// Check if the Root CA (ca.crt) and client cert and key files (tls.cert, tls.key) are present
				secretName := connector.LDAP.RootCARef.Name
				var secretNamespace string
				if secretNamespace = connector.LDAP.RootCARef.Namespace; secretNamespace == "" {
					secretNamespace = dexServer.Namespace
				}
				resource := &corev1.Secret{}
				if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, resource); err != nil && errors.IsNotFound(err) {
					// Error getting secret
					log.Error(err, "Error getting root CA")
					return nil
				}
				if string(resource.Data["ca.crt"]) != "" {
					rootCAPath = "/etc/dex/ldapcerts/" + connector.Id + "/ca.crt"
				}
				if string(resource.Data["tls.crt"]) != "" {
					clientCAPath = "/etc/dex/ldapcerts/" + connector.Id + "/tls.crt"
				}
				if string(resource.Data["tls.key"]) != "" {
					clientKeyPath = "/etc/dex/ldapcerts/" + connector.Id + "/tls.key"
				}
			}

			newConnector = DexConnectorSpec{
				Type: string(authv1alpha1.ConnectorTypeLDAP),
				Id:   connector.Id,
				Name: connector.Name,
				Config: DexConnectorConfigSpec{
					Host:               connector.LDAP.Host,
					InsecureNoSSL:      connector.LDAP.InsecureNoSSL,
					InsecureSkipVerify: connector.LDAP.InsecureSkipVerify,
					StartTLS:           connector.LDAP.StartTLS,
					RootCA:             rootCAPath,
					ClientCA:           clientCAPath,
					ClientKey:          clientKeyPath,
					BindDN:             connector.LDAP.BindDN,
					BindPW:             bindPW,
					UsernamePrompt:     connector.LDAP.UsernamePrompt,
				},
			}

			if connector.LDAP.UserSearch.BaseDN != "" {
				newConnector.Config.UserSearch.BaseDN = connector.LDAP.UserSearch.BaseDN
				newConnector.Config.UserSearch.Filter = connector.LDAP.UserSearch.Filter
				newConnector.Config.UserSearch.Username = connector.LDAP.UserSearch.Username
				newConnector.Config.UserSearch.Scope = connector.LDAP.UserSearch.Scope
				newConnector.Config.UserSearch.IDAttr = connector.LDAP.UserSearch.IDAttr
				newConnector.Config.UserSearch.EmailAttr = connector.LDAP.UserSearch.EmailAttr
				newConnector.Config.UserSearch.NameAttr = connector.LDAP.UserSearch.NameAttr
				newConnector.Config.UserSearch = v1alpha1.UserSearchSpec{
					BaseDN:    connector.LDAP.UserSearch.BaseDN,
					Filter:    connector.LDAP.UserSearch.Filter,
					Username:  connector.LDAP.UserSearch.Username,
					Scope:     connector.LDAP.UserSearch.Scope,
					IDAttr:    connector.LDAP.UserSearch.IDAttr,
					EmailAttr: connector.LDAP.UserSearch.EmailAttr,
					NameAttr:  connector.LDAP.UserSearch.NameAttr,
				}
			}

			if connector.LDAP.GroupSearch.BaseDN != "" {
				newConnector.Config.GroupSearch = v1alpha1.GroupSearchSpec{
					BaseDN:       connector.LDAP.GroupSearch.BaseDN,
					Filter:       connector.LDAP.GroupSearch.Filter,
					Scope:        connector.LDAP.GroupSearch.Scope,
					UserMatchers: connector.LDAP.GroupSearch.UserMatchers,
					NameAttr:     connector.LDAP.GroupSearch.NameAttr,
				}
			}

		default:
			return nil
		}

		// Add connector to list
		connectors = append(connectors, newConnector)
	}

	connectorYamlSpec := struct {
		Connectors []DexConnectorSpec `json:"connectors,omitempty"`
	}{
		Connectors: connectors,
	}

	// Get yaml representation of configYamlData
	connectorYaml, err := yaml.Marshal(&connectorYamlSpec)

	if err != nil {
		log.Error(err, "failed to marshal dex config.yaml")
		return err
	}

	values := struct {
		Issuer         string
		ConnectorsYaml string
		DexServer      *authv1alpha1.DexServer
	}{
		Issuer:         dexServer.Spec.Issuer,
		ConnectorsYaml: string(connectorYaml),
		DexServer:      dexServer,
	}

	files := []string{
		"dex-server/config_map.yaml",
	}

	applier, readerDeploy := r.getApplierAndReader(dexServer)
	_, err = applier.ApplyDirectly(readerDeploy, values, false, "", files...)
	if err != nil {
		return err
	}

	return nil
}

func (r *DexServerReconciler) syncIngress(dexServer *authv1alpha1.DexServer, ctx context.Context) error {
	log := ctrllog.FromContext(ctx)
	u, _ := url.Parse(dexServer.Spec.Issuer)
	routeHost := u.Host
	log.Info("syncIngress", "Host", routeHost)

	ingressCertificateRefName := dexServer.Spec.IngressCertificateRef.Name

	values := struct {
		Host                   string
		DexServer              *authv1alpha1.DexServer
		IngressCertificateName string
	}{
		Host:                   routeHost,
		DexServer:              dexServer,
		IngressCertificateName: ingressCertificateRefName,
	}

	files := []string{
		"dex-server/ingress.yaml",
	}

	applier, readerDeploy := r.getApplierAndReader(dexServer)
	// TODO: ApplyCustomResources is a hack... no support currently for applying a route or ingress and this seems to work
	_, err := applier.ApplyCustomResources(readerDeploy, values, false, "", files...)

	if err != nil {
		return err
	}

	return nil

}

// Rolling restarts are accomplished with an annotation on the pod template. Ignore this and resulting updates
// to allow rolling restarts to complete successfully.
func ignoreDeploymentRestartPredicate() predicate.Predicate {
	// hold the generation of any deployment restarts in progress, by namespace and name
	restartsInProgress := map[string]int64{}
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			if len(e.ObjectOld.GetOwnerReferences()) == 0 {
				return false
			} else if e.ObjectOld.GetOwnerReferences()[0].Kind != "DexServer" {
				return false
			}
			namespacedName := fmt.Sprintf("%s:%s", e.ObjectNew.GetNamespace(), e.ObjectNew.GetName())
			log := ctrl.Log.WithName("controllers").WithName("dexserver").WithName("ignoreDeploymentRestartPredicate").WithValues("namespace", e.ObjectNew.GetNamespace(), "name", e.ObjectNew.GetName())
			if restartInProgressGeneration, found := restartsInProgress[namespacedName]; found {
				log.V(1).Info("restart in progress for deployment", "generation", restartInProgressGeneration)
				if restartInProgressGeneration == e.ObjectNew.GetGeneration() {
					log.V(1).Info("updates are due to restart in progress... ignore")
					return false
				} else {
					log.V(1).Info("new generation detected", "generation", e.ObjectNew.GetGeneration())
					delete(restartsInProgress, namespacedName)
				}
			}
			log.V(1).Info("deployment updated", "generation", e.ObjectNew.GetGeneration())
			oldDeployment := e.ObjectOld.(*appsv1.Deployment)
			newDeployment := e.ObjectNew.(*appsv1.Deployment)

			newPodSpecAnnotations := newDeployment.Spec.Template.ObjectMeta.Annotations
			if newDeploymentRestartedAt, found := newPodSpecAnnotations["kubectl.kubernetes.io/restartedAt"]; found {
				oldPodSpecAnnotations := oldDeployment.Spec.Template.ObjectMeta.Annotations
				if len(oldPodSpecAnnotations) == 0 ||
					(newDeploymentRestartedAt != oldPodSpecAnnotations["kubectl.kubernetes.io/restartedAt"]) {
					// this is a new restart. don't process it. hold on to it so we can ignore future updates to the deployment from this same restart
					restartsInProgress[namespacedName] = e.ObjectNew.GetGeneration()
					log.V(1).Info("new restart detected", "generation", e.ObjectNew.GetGeneration())
					return false
				}
			}
			log.V(1).Info("deployment update not filtered out")
			return true
		},
	}
}

func (r *DexServerReconciler) installClusterRole() error {
	values := struct {
		ClusterRoleName string
	}{
		ClusterRoleName: SERVICE_ACCOUNT_NAME,
	}

	files := []string{
		"dex-server/cluster_role.yaml",
	}

	applierBuilder := &clusteradmapply.ApplierBuilder{}
	applier := applierBuilder.
		WithClient(r.KubeClient, r.APIExtensionClient, r.DynamicClient).
		Build()

	readerDeploy := deploy.GetScenarioResourcesReader()
	_, err := applier.ApplyDirectly(readerDeploy, values, false, "", files...)
	if err != nil {
		return err
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *DexServerReconciler) SetupWithManager(mgr ctrl.Manager) error {

	// Set up the Cluster Role
	if err := r.installClusterRole(); err != nil {
		return err
	}

	deploymentOwnsOpts := []builder.OwnsOption{
		builder.WithPredicates(ignoreDeploymentRestartPredicate()), // ignore deployment rolling restarts
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&authv1alpha1.DexServer{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&corev1.Secret{}).
		Owns(&appsv1.Deployment{}, deploymentOwnsOpts...).
		Owns(&networkingv1.Ingress{}).
		Complete(r)
}

// func (r *DexServerReconciler) startdexServer(ctx context.Context, ds *v1alpha1.DexServer, c client.Client) (*v1alpha1.DexServer, error) {
// 	switch {
// 	case len(ds.Spec.Connectors) != 0:
// 		log.Info("Found connector!")
// 	}
// 	return updateStatus(ctx, ds, c)
// }
