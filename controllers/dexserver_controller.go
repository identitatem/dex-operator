// Copyright Red Hat

package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	deployUtil "github.com/openshift/cluster-resource-override-admission-operator/pkg/deploy"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/equality"
	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	authv1alpha1 "github.com/identitatem/dex-operator/api/v1alpha1"
	deploy "github.com/identitatem/dex-operator/deploy"
)

const (
	SECRET_MTLS_NAME            = "grpc-mtls"
	SECRET_WEB_TLS_SUFFIX       = "-tls-secret"
	SERVICE_ACCOUNT_NAME        = "dex-operator-dexsso"
	GRPC_SERVICE_NAME           = "grpc"
	DEX_IMAGE_ENV_NAME          = "RELATED_IMAGE_DEX"
	MTLS_CERT_EXPIRY_ANNOTATION = "auth.identitatem.io/expiry"
	IDP_CREDENTIAL_LABEL        = "auth.identitatem.io/idp-credential"
	DEXSERVER_FINALIZER         = "auth.identitatem.io/cleanup"
	GITHUB_CLIENT_SECRET_ENV    = "GITHUB_CLIENT_SECRET"
	MICROSOFT_CLIENT_SECRET_ENV = "MICROSOFT_CLIENT_SECRET"
	LDAP_BIND_PW_ENV            = "LDAP_BIND_PW"
)

type ConnectorSecret struct {
	EnvVarName string
	SecretKey  string
}

var envVariableForConnector = map[authv1alpha1.ConnectorType]ConnectorSecret{
	"github": {
		EnvVarName: "GITHUB_CLIENT_SECRET",
		SecretKey:  "clientSecret",
	},
	"ldap": {
		EnvVarName: "LDAP_BIND_PW",
		SecretKey:  "bindPW",
	},
	"microsoft": {
		EnvVarName: "MICROSOFT_CLIENT_SECRET",
		SecretKey:  "clientSecret",
	},
}

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
		log.Error(err, "failed to fetch DexServer instance")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// If a deletionTimestamp exists this means the dex server is being deleted, we need to also delete the associated ClusterRoleBinding
	if dexServer.DeletionTimestamp != nil {
		if err := r.processDexServerDeletion(dexServer, ctx); err != nil {
			return reconcile.Result{}, err
		}
		controllerutil.RemoveFinalizer(dexServer, DEXSERVER_FINALIZER)
		if err := r.Client.Update(context.TODO(), dexServer); err != nil {
			log.Error(err, "failed to update DexServer after removing the finalizer")
			return ctrl.Result{}, err
		}
		return reconcile.Result{}, nil
	}

	// Add a finalizer to the DexServer to handle deletion of the ClusterRoleBinding, it will be removed once the ClusterRoleBinding is deleted
	if !controllerutil.ContainsFinalizer(dexServer, DEXSERVER_FINALIZER) {
		controllerutil.AddFinalizer(dexServer, DEXSERVER_FINALIZER)
		// Update DexServer after adding finalizer
		if err := r.Client.Update(context.TODO(), dexServer); err != nil {
			log.Error(err, "failed to update DexServer after adding the finalizer")
			return ctrl.Result{}, err
		}
	}

	// Prepare Mutual TLS for gRPC connection
	if err := r.manageMTLSSecret(dexServer, ctx); err != nil {
		log.Error(err, "failed to manage mtls secret")
		cond := metav1.Condition{
			Type:   authv1alpha1.DexServerConditionTypeApplied,
			Status: metav1.ConditionFalse,
			Reason: "ConfigMTLSSecretFailed",
			Message: fmt.Sprintf("failed to configure MTLS secret. error: %s",
				err.Error()),
		}
		if err := updateDexServerStatusConditions(r.Client, dexServer, cond); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	if err := r.syncConfigMap(dexServer, ctx); err != nil {
		log.Error(err, "failed to sync ConfigMap")
		cond := metav1.Condition{
			Type:   authv1alpha1.DexServerConditionTypeApplied,
			Status: metav1.ConditionFalse,
			Reason: "ConfigMapFailed",
			Message: fmt.Sprintf("failed to sync ConfigMap. error: %s",
				err.Error()),
		}
		if err := updateDexServerStatusConditions(r.Client, dexServer, cond); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	if err := r.syncService(dexServer, ctx); err != nil {
		log.Error(err, "failed to sync http service")
		cond := metav1.Condition{
			Type:   authv1alpha1.DexServerConditionTypeApplied,
			Status: metav1.ConditionFalse,
			Reason: "ConfigHTTPServiceFailed",
			Message: fmt.Sprintf("failed to sync http service. error: %s",
				err.Error()),
		}
		if err := updateDexServerStatusConditions(r.Client, dexServer, cond); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	if err := r.syncServiceGrpc(dexServer, ctx); err != nil {
		log.Error(err, "failed to sync grpc Service")
		cond := metav1.Condition{
			Type:   authv1alpha1.DexServerConditionTypeApplied,
			Status: metav1.ConditionFalse,
			Reason: "ConfigGRPCServiceFailed",
			Message: fmt.Sprintf("failed to sync grpc service. error: %s",
				err.Error()),
		}
		if err := updateDexServerStatusConditions(r.Client, dexServer, cond); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, err
	}

	if err := r.syncServiceAccount(dexServer, ctx); err != nil {
		log.Error(err, "failed to sync ServiceAccount")
		cond := metav1.Condition{
			Type:   authv1alpha1.DexServerConditionTypeApplied,
			Status: metav1.ConditionFalse,
			Reason: "ConfigServiceAccountFailed",
			Message: fmt.Sprintf("failed to sync ServiceAccount. error: %s",
				err.Error()),
		}
		if err := updateDexServerStatusConditions(r.Client, dexServer, cond); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	if err := r.syncClusterRoleBinding(dexServer, ctx); err != nil {
		log.Error(err, "failed to sync ClusterRoleBinding")
		cond := metav1.Condition{
			Type:   authv1alpha1.DexServerConditionTypeApplied,
			Status: metav1.ConditionFalse,
			Reason: "ConfigClusterRoleBindingFailed",
			Message: fmt.Sprintf("failed to sync ClusterRoleBinding. error: %s",
				err.Error()),
		}
		if err := updateDexServerStatusConditions(r.Client, dexServer, cond); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	if err := r.syncDeployment(dexServer, ctx); err != nil {
		log.Error(err, "failed to sync Deployment")
		cond := metav1.Condition{
			Type:   authv1alpha1.DexServerConditionTypeApplied,
			Status: metav1.ConditionFalse,
			Reason: "ConfigDeploymentFailed",
			Message: fmt.Sprintf("failed to sync Deployment. error: %s",
				err.Error()),
		}
		if err := updateDexServerStatusConditions(r.Client, dexServer, cond); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	if err := r.syncIngress(dexServer, ctx); err != nil {
		log.Error(err, "failed to sync Ingress")
		cond := metav1.Condition{
			Type:   authv1alpha1.DexServerConditionTypeApplied,
			Status: metav1.ConditionFalse,
			Reason: "ConfigIngressFailed",
			Message: fmt.Sprintf("failed to sync Ingress. error: %s",
				err.Error()),
		}
		if err := updateDexServerStatusConditions(r.Client, dexServer, cond); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	cond := metav1.Condition{
		Type:    authv1alpha1.DexServerConditionTypeApplied,
		Status:  metav1.ConditionTrue,
		Reason:  "Applied",
		Message: "DexServer is applied",
	}
	if err := updateDexServerStatusConditions(r.Client, dexServer, cond); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("Checking for dexServer deployment status")
	cond, err := r.getDexServerDeploymentCondition(dexServer)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := updateDexServerStatusConditions(r.Client, dexServer, cond); err != nil {
		return ctrl.Result{}, err
	}

	// Reconcile hourly to ensure grpc mtls certs are regenerated before expiry
	return ctrl.Result{Requeue: true, RequeueAfter: 1 * time.Hour}, nil
}

// Get status (availability) of DexServer deployment
func (r *DexServerReconciler) getDexServerDeploymentCondition(dexServer *authv1alpha1.DexServer) (metav1.Condition, error) {
	// Failure condition
	condition := metav1.Condition{
		Type:    authv1alpha1.DexServerDeploymentAvailable,
		Status:  metav1.ConditionFalse,
		Reason:  "NotAvailable",
		Message: "DexServer deployment is currently unavailable",
	}
	dexServerDeployment := &appsv1.Deployment{}
	err := r.Client.Get(context.TODO(), client.ObjectKey{Name: dexServer.Name, Namespace: dexServer.Namespace}, dexServerDeployment)
	if err != nil {
		return condition, err
	} else {
		// Deployment exists, check its status
		isAvailable, err := deployUtil.GetDeploymentStatus(dexServerDeployment)

		if isAvailable {
			condition = metav1.Condition{
				Type:    authv1alpha1.DexServerDeploymentAvailable,
				Status:  metav1.ConditionTrue,
				Reason:  "Available",
				Message: "DexServer deployment is available",
			}
		} else if err != nil {
			condition.Message += ", " + err.Error()
			return condition, nil
		}

		return condition, nil
	}
}

// Handle cleanup during DexServer deletion
func (r *DexServerReconciler) processDexServerDeletion(dexServer *authv1alpha1.DexServer, ctx context.Context) error {
	log := ctrllog.FromContext(ctx)
	clusterRoleBindingName := SERVICE_ACCOUNT_NAME + "-" + dexServer.Namespace
	log.Info("processDexServerDeletion", "Clean up ClusterRoleBinding", clusterRoleBindingName)

	// Delete ClusterRoleBinding
	crb := &rbacv1.ClusterRoleBinding{}
	err := r.Client.Get(context.TODO(), client.ObjectKey{Name: clusterRoleBindingName}, crb)
	switch {
	case err == nil:
		if err := r.Client.Delete(context.TODO(), crb); err != nil {
			log.Error(err, "failed to delete ClusterRoleBinding")
			return err
		}
	case !kubeerrors.IsNotFound(err):
		log.Error(err, "failed to fetch ClusterRoleBinding")
		return err
	}
	return nil
}

// Check if the secret already contains the required label "auth.identitatem.io/idp-credential"
// and if it doesn't then add the label - this label allows us to watch specific secrets for updates
func checkAndAddLabelToSecret(secret *corev1.Secret, r *DexServerReconciler, ctx context.Context) {
	log := ctrllog.FromContext(ctx)

	if secret.Labels == nil {
		secret.Labels = make(map[string]string)
	}
	if _, ok := secret.Labels[IDP_CREDENTIAL_LABEL]; !ok {
		secret.Labels[IDP_CREDENTIAL_LABEL] = ""
		if err := r.Update(ctx, secret); err != nil {
			log.Error(err, "Error updating secret with label")
		}
	}
}

func getConnectorSecretFromRef(connector authv1alpha1.ConnectorSpec, m *authv1alpha1.DexServer, r *DexServerReconciler, ctx context.Context) (string, error) {
	var secretNamespace, secretName string

	switch connector.Type {
	case authv1alpha1.ConnectorTypeGitHub:
		secretName = connector.GitHub.ClientSecretRef.Name
		if secretNamespace = connector.GitHub.ClientSecretRef.Namespace; secretNamespace == "" {
			secretNamespace = m.Namespace
		}
		resource := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, resource); err != nil && kubeerrors.IsNotFound(err) {
			return "", err
		}
		checkAndAddLabelToSecret(resource, r, ctx)
		return string(resource.Data["clientSecret"]), nil
	case authv1alpha1.ConnectorTypeMicrosoft:
		secretName = connector.Microsoft.ClientSecretRef.Name
		if secretNamespace = connector.Microsoft.ClientSecretRef.Namespace; secretNamespace == "" {
			secretNamespace = m.Namespace
		}
		resource := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, resource); err != nil && kubeerrors.IsNotFound(err) {
			return "", err
		}
		checkAndAddLabelToSecret(resource, r, ctx)
		return string(resource.Data["clientSecret"]), nil
	case authv1alpha1.ConnectorTypeLDAP:
		secretName = connector.LDAP.BindPWRef.Name
		if secretNamespace = connector.LDAP.BindPWRef.Namespace; secretNamespace == "" {
			secretNamespace = m.Namespace
		}
		resource := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, resource); err != nil && kubeerrors.IsNotFound(err) {
			return "", err
		}
		checkAndAddLabelToSecret(resource, r, ctx)
		return string(resource.Data["bindPW"]), nil
	default:
		return "", fmt.Errorf("could not retrieve secret")
	}

}

// Define the secret for grpc Mutual TLS. This secret is volume mounted on the dex instance pod. The client cert should be loaded by the gRPC client code.
func (r *DexServerReconciler) defineMTLSSecret(m *authv1alpha1.DexServer, mtlsCerts *MTLSCerts) *corev1.Secret {
	labels := map[string]string{
		"app": m.Name,
	}
	annotations := map[string]string{
		MTLS_CERT_EXPIRY_ANNOTATION: mtlsCerts.expiry.UTC().Format(time.RFC3339),
	}
	secretSpec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        SECRET_MTLS_NAME,
			Namespace:   m.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Data: map[string][]byte{
			"ca.crt":     mtlsCerts.caPEM.Bytes(),
			"ca.key":     mtlsCerts.caPrivKeyPEM.Bytes(),
			"tls.crt":    append(mtlsCerts.certPEM.Bytes(), mtlsCerts.certPEM.Bytes()...),
			"tls.key":    mtlsCerts.certPrivKeyPEM.Bytes(),
			"client.crt": append(mtlsCerts.clientPEM.Bytes(), mtlsCerts.clientPEM.Bytes()...),
			"client.key": mtlsCerts.clientPrivKeyPEM.Bytes(),
		},
	}
	ctrl.SetControllerReference(m, secretSpec, r.Scheme)
	return secretSpec
}

func (r *DexServerReconciler) getMTLSSecret(m *authv1alpha1.DexServer, ctx context.Context) (*corev1.Secret, error) {
	resource := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: fmt.Sprintf(SECRET_MTLS_NAME), Namespace: m.Namespace}, resource); err != nil {
		return nil, err
	}
	return resource, nil
}

func (r *DexServerReconciler) manageMTLSSecret(dexServer *authv1alpha1.DexServer, ctx context.Context) error {
	log := ctrllog.FromContext(ctx)
	log.V(1).Info("manageMTLSSecret")
	secretExists := false
	regenerate := false
	secret, err := r.getMTLSSecret(dexServer, ctx)
	if err != nil {
		if !kubeerrors.IsNotFound(err) {
			return errors.Wrap(err, "error getting mtls secret")
		}
	} else {
		secretExists = true
		// check if cert is expiring soon...
		expiry := secret.Annotations[MTLS_CERT_EXPIRY_ANNOTATION]
		if expiry == "" {
			// expiration annotation is missing... something is amiss... let's regenerate
			regenerate = true
		} else {
			expiryTime, err := time.Parse(time.RFC3339, expiry)
			if err != nil {
				//something unexpected found in the expiry annotation ... something is amiss ... let's regenerate
				log.Error(err, "cert expiry could not be parsed")
				regenerate = true
			}
			if inCertRenewalWindow(expiryTime) {
				log.V(1).Info("mtls cert is nearing expiration... regenerate")
				regenerate = true
			}

		}
	}
	if !secretExists || regenerate {
		mTLSCerts, err := generateMTLSCerts(dexServer.Namespace)
		if err != nil {
			return errors.Wrap(err, "error generating mtls certs")
		}
		spec := r.defineMTLSSecret(dexServer, mTLSCerts)
		if !secretExists {
			log.Info("Creating a new MTLS Secret", "Secret.Namespace", spec.Namespace, "Secret.Name", spec.Name)
			if err := r.Create(ctx, spec); err != nil {
				return errors.Wrap(err, "error creating mtls secret")
			}
		} else {
			log.Info("Updating MTLS Secret", "Secret.Namespace", spec.Namespace, "Secret.Name", spec.Name)
			if err := r.Update(ctx, spec); err != nil {
				return errors.Wrap(err, "error updating mtls secret")
			}
		}

	} else {
		log.V(1).Info("mtls cert found and does not require renewal")
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
	var additionalEnvVariables []corev1.EnvVar
	var additionalEnvVariablesYaml []byte
	var rootCAHash string

	// Update Volume Mounts based on rootCA secret refs for LDAP connectors (Trusted Root CA and optionally client cert and key files)
	// Iterate over connectors defined in the DexServer to create the dex configuration for connectors
	for _, connector := range dexServer.Spec.Connectors {
		switch connector.Type {
		case authv1alpha1.ConnectorTypeGitHub:
			// To ensure uniqueness of names for secrets copied into the dex server namespace, the secret name is prefixed with the original namespace
			secretName := connector.GitHub.ClientSecretRef.Namespace + "-" + connector.GitHub.ClientSecretRef.Name
			newEnvVariable, err := r.getEnvironmentVariableForSecret(ctx, dexServer, secretName, connector)
			if err != nil {
				return err
			}
			if newEnvVariable != (corev1.EnvVar{}) {
				additionalEnvVariables = append(additionalEnvVariables, newEnvVariable)
			}
		case authv1alpha1.ConnectorTypeMicrosoft:
			// To ensure uniqueness of names for secrets copied into the dex server namespace, the secret name is prefixed with the original namespace
			secretName := connector.Microsoft.ClientSecretRef.Namespace + "-" + connector.Microsoft.ClientSecretRef.Name
			newEnvVariable, err := r.getEnvironmentVariableForSecret(ctx, dexServer, secretName, connector)
			if err != nil {
				return err
			}
			if newEnvVariable != (corev1.EnvVar{}) {
				additionalEnvVariables = append(additionalEnvVariables, newEnvVariable)
			}
		case authv1alpha1.ConnectorTypeLDAP:
			// To ensure uniqueness of names for secrets copied into the dex server namespace, the secret name is prefixed with the original namespace
			secretName := connector.LDAP.BindPWRef.Namespace + "-" + connector.LDAP.BindPWRef.Name
			newEnvVariable, err := r.getEnvironmentVariableForSecret(ctx, dexServer, secretName, connector)
			if err != nil {
				return err
			}
			if newEnvVariable != (corev1.EnvVar{}) {
				additionalEnvVariables = append(additionalEnvVariables, newEnvVariable)
			}

			if connector.LDAP.RootCARef.Name != "" {
				// To ensure uniqueness of names for secrets copied into the dex server namespace, the secret name is prefixed with the original namespace
				secretName := connector.LDAP.RootCARef.Namespace + "-" + connector.LDAP.RootCARef.Name
				rootCASecret := &corev1.Secret{}

				// Add the root CA secret's sha256 checksum to the Deployment to trigger rolling restarts when the secret changes
				if err := r.Client.Get(context.TODO(), client.ObjectKey{Name: secretName, Namespace: dexServer.Namespace}, rootCASecret); err != nil {
					// If the secret is not yet found, the annotation will be omitted, and will be added once the secret is created
					if !kubeerrors.IsNotFound(err) {
						log.Error(err, "error getting secret containing LDAP root CA")
						return err
					}
				} else {
					jsonData, err := json.Marshal(rootCASecret)
					if err != nil {
						log.Error(err, "failed to marshal LDAP root CA JSON")
						return err
					}
					h := sha256.New()
					h.Write([]byte(jsonData))
					rootCAHash = rootCAHash + fmt.Sprintf("%x", h.Sum(nil)) // If there are multiple LDAP connectors with root CA, the hashes will be concatenated

					newVolume := corev1.Volume{
						Name: "ldapcerts-" + connector.Id,
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: secretName,
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
		default:
			return nil
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

	if len(additionalEnvVariables) > 0 {
		// Get yaml representation of additional environment variables
		additionalEnvVariablesYaml, err = yaml.Marshal(&additionalEnvVariables)
		if err != nil {
			log.Error(err, "failed to marshal yaml for additional environment variables")
		}
	}

	// Add the dex ConfigMap sha256 checksum to the Deployment to trigger rolling restarts when the ConfigMap changes
	dexConfigMap := &corev1.ConfigMap{}
	var dexConfigMapHash string
	if err := r.Get(ctx, types.NamespacedName{Name: dexServer.Name, Namespace: dexServer.Namespace}, dexConfigMap); err != nil {
		// If ConfigMap is not yet found, the annotation will be omitted, and will be added once the ConfigMap is created
		if !kubeerrors.IsNotFound(err) {
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
	var mtlsSecretExpiry string
	if mtlsSecret, err := r.getMTLSSecret(dexServer, ctx); err != nil {
		// If mtls secret is not yet found, the annotation will be omitted, and will be added once the secret is created
		if !kubeerrors.IsNotFound(err) {
			return errors.Wrap(err, "error getting dex server grpc mtls secret")
		}
	} else {
		mtlsSecretExpiry = mtlsSecret.Annotations[MTLS_CERT_EXPIRY_ANNOTATION]
	}

	values := struct {
		DexImage               string
		DexConfigMapHash       string
		RootCAHash             string
		ServiceAccountName     string
		TlsSecretName          string
		MtlsSecretName         string
		MtlsSecretExpiry       string
		DexServer              *authv1alpha1.DexServer
		AdditionalEnvVariables string
		AdditionalVolumeMounts string
		AdditionalVolumes      string
	}{
		DexImage:           dexImage,
		DexConfigMapHash:   dexConfigMapHash,
		RootCAHash:         rootCAHash,
		ServiceAccountName: SERVICE_ACCOUNT_NAME,
		// this secret is generated using service serving certificate via service annotation
		// service.beta.openshift.io/serving-cert-secret-name: dexServer.Name-tls-secret
		TlsSecretName: fmt.Sprintf(dexServer.Name + SECRET_WEB_TLS_SUFFIX),
		// This secret is generated by this controller, here we load the server side cert and ca
		// service.beta.openshift.io/serving-cert-secret-name: dexServer.Name-mtls-secret
		MtlsSecretName:         SECRET_MTLS_NAME,
		MtlsSecretExpiry:       mtlsSecretExpiry,
		DexServer:              dexServer,
		AdditionalEnvVariables: string(additionalEnvVariablesYaml),
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

// Set unique alphanumeric Id for connector (this is used as a suffix for the environment variable holding the private credentials for the connector)
func getUniqueAlphanumericIdForConnector(connector authv1alpha1.ConnectorSpec) string {
	idBytes := []byte(connector.Id)
	str := hex.EncodeToString(idBytes)
	return strings.ToUpper(str)
}

// Get environment variable referencing a particular secret
func (r *DexServerReconciler) getEnvironmentVariableForSecret(ctx context.Context, dexServer *authv1alpha1.DexServer, secretName string, connector authv1alpha1.ConnectorSpec) (envVariable corev1.EnvVar, err error) {
	log := ctrllog.FromContext(ctx)
	credentialSecret := &corev1.Secret{}
	var newEnvVariable corev1.EnvVar
	// get an alphanumeric ID for the connector that can be used as a suffix in the env variable name containing the secret for this connector
	connectorAlphanumericId := getUniqueAlphanumericIdForConnector(connector)

	// The environment variable name includes a unique alphanumeric suffix so to distinguish between secrets for multiple connectors of the same type
	envVariableName := envVariableForConnector[connector.Type].EnvVarName + "_" + connectorAlphanumericId

	secretKey := envVariableForConnector[connector.Type].SecretKey

	if err := r.Client.Get(context.TODO(), client.ObjectKey{Name: secretName, Namespace: dexServer.Namespace}, credentialSecret); err != nil {
		// The environment variable will be added once the secret is created
		if !kubeerrors.IsNotFound(err) {
			log.Error(err, "error getting secret containing GitHub client secret")
			return newEnvVariable, err
		}
		return newEnvVariable, nil
	} else {
		// Add an environment variable to reference this secret
		newEnvVariable := corev1.EnvVar{
			Name: envVariableName,
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: secretName,
					},
					Key: secretKey,
				},
			},
		}
		return newEnvVariable, nil
	}
}

// Copy a secret from its original namespace into the Dex Server namespace
func (r *DexServerReconciler) copySecretToDexServerNamespace(dexServer *authv1alpha1.DexServer, secretRef corev1.SecretReference, ctx context.Context) error {
	log := ctrllog.FromContext(ctx)

	// Secret to copy from
	originalSecret := &corev1.Secret{}
	if err := r.Client.Get(context.TODO(),
		client.ObjectKey{Name: secretRef.Name, Namespace: secretRef.Namespace},
		originalSecret); err != nil {
		log.Error(err, "Error retrieving secret", "name", secretRef.Name)
		return err
	}
	// Add label to this secret so that the secret can be watched for updates
	checkAndAddLabelToSecret(originalSecret, r, ctx)

	// Secret to copy into (in the dex server namespace)
	secretInDexServerNS := &corev1.Secret{}

	// To ensure uniqueness of names for secrets copied into the dex server namespace, prefix the secret name with the original namespace
	secretName := originalSecret.Namespace + "-" + originalSecret.Name

	err := r.Client.Get(context.TODO(), client.ObjectKey{Name: secretName, Namespace: dexServer.Namespace}, secretInDexServerNS)

	switch {
	case err == nil:
		// Secret already exists in the dex server ns, update it
		secretInDexServerNS.Data = originalSecret.Data
		if err := r.Client.Update(context.TODO(), secretInDexServerNS); err != nil {
			log.Error(err, "Error updating secret in dexserver namespace", "name", secretRef.Name)
			return err
		}
	case kubeerrors.IsNotFound(err):
		// Create secret in the dex server ns
		secretInDexServerNS = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: dexServer.Namespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: originalSecret.Data,
		}
		if err := r.Client.Create(context.TODO(), secretInDexServerNS); err != nil {
			log.Error(err, "Error creating secret in dexserver namespace", "name", secretRef.Name)
			return err
		}
	default:
		log.Error(err, "Error retrieving secret in dexserver namespace", "name", secretRef.Name)
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
		// get an alphanumeric ID for the connector that can be used as a suffix in the env variable name containing the secret for this connector
		connectorAlphanumericId := getUniqueAlphanumericIdForConnector(connector)

		var newConnector DexConnectorSpec
		switch connector.Type {
		case authv1alpha1.ConnectorTypeGitHub:
			// Check if secret is in the dex server namespace and copy it into the dexserver ns
			// The secret copied into the dexserver ns will be referenced by the env variable in the dexserver deployment
			if secretNamespace := connector.GitHub.ClientSecretRef.Namespace; secretNamespace != dexServer.Namespace {
				err := r.copySecretToDexServerNamespace(dexServer, connector.GitHub.ClientSecretRef, ctx)
				if err != nil {
					return err
				}
			}

			// Environment variable that references the GitHub client secret copied into the dexserver ns
			// The name includes the connector's alphanumeric unique Id as a suffix to distinguish between client secrets for multiple GitHub connectors
			clientSecretEnvVariable := "$" + envVariableForConnector[connector.Type].EnvVarName + "_" + connectorAlphanumericId

			newConnector = DexConnectorSpec{
				Type: string(authv1alpha1.ConnectorTypeGitHub),
				Id:   connector.Id,
				Name: connector.Name,
				Config: DexConnectorConfigSpec{
					ClientID:     connector.GitHub.ClientID,
					ClientSecret: clientSecretEnvVariable,
					RedirectURI:  connector.GitHub.RedirectURI,
					Org:          connector.GitHub.Org,
					Orgs:         connector.GitHub.Orgs,
				},
			}
		case authv1alpha1.ConnectorTypeMicrosoft:
			// Check if secret is in the dex server namespace and copy it into the dexserver ns
			// The secret copied into the dexserver ns will be referenced by the env variable in the dexserver deployment
			if secretNamespace := connector.Microsoft.ClientSecretRef.Namespace; secretNamespace != dexServer.Namespace {
				err := r.copySecretToDexServerNamespace(dexServer, connector.Microsoft.ClientSecretRef, ctx)
				if err != nil {
					return err
				}
			}

			// Environment variable that references the Microsoft OAuth client secret copied into the dexserver ns
			// The name includes the connector's alphanumeric unique Id as a suffix to distinguish between client secrets for multiple Microsoft connectors
			clientSecretEnvVariable := "$" + envVariableForConnector[connector.Type].EnvVarName + "_" + connectorAlphanumericId

			newConnector = DexConnectorSpec{
				Type: string(authv1alpha1.ConnectorTypeMicrosoft),
				Id:   connector.Id,
				Name: connector.Name,
				Config: DexConnectorConfigSpec{
					ClientID:     connector.Microsoft.ClientID,
					ClientSecret: clientSecretEnvVariable,
					RedirectURI:  connector.Microsoft.RedirectURI,
					Tenant:       connector.Microsoft.Tenant,
				},
			}
		case authv1alpha1.ConnectorTypeLDAP:
			// Check if bind password secret is in the dex server namespace and copy it into the dexserver ns
			// The secret copied into the dexserver ns will be referenced by the env variable in the dexserver deployment
			if secretNamespace := connector.LDAP.BindPWRef.Namespace; secretNamespace != dexServer.Namespace {
				err := r.copySecretToDexServerNamespace(dexServer, connector.LDAP.BindPWRef, ctx)
				if err != nil {
					return err
				}
			}

			// Environment variable that references the LDAP Bind Password secret copied into the dexserver ns
			// The name includes the connector's alphanumeric unique Id as a suffix to distinguish between bind passwords for multiple connectors
			bindPWEnvVariable := "$" + envVariableForConnector[connector.Type].EnvVarName + "_" + connectorAlphanumericId

			// If there is a secret reference to the trusted Root CA
			var rootCAPath, clientCAPath, clientKeyPath string
			if connector.LDAP.RootCARef.Name != "" {
				// Check if secret is in the dex server namespace
				if secretNamespace := connector.LDAP.RootCARef.Namespace; secretNamespace != dexServer.Namespace {
					err := r.copySecretToDexServerNamespace(dexServer, connector.LDAP.RootCARef, ctx)
					if err != nil {
						return err
					}
				}
				// To ensure uniqueness of names for secrets copied into the dex server namespace, the secret name is prefixed with the original namespace
				secretName := connector.LDAP.RootCARef.Namespace + "-" + connector.LDAP.RootCARef.Name
				secretNamespace := dexServer.Namespace
				resource := &corev1.Secret{}

				if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, resource); err != nil {
					// Error getting secret
					log.Error(err, "Error getting root CA secret in dex server ns")
					return err
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
					BindPW:             bindPWEnvVariable,
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
				newConnector.Config.UserSearch = authv1alpha1.UserSearchSpec{
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
				newConnector.Config.GroupSearch = authv1alpha1.GroupSearchSpec{
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

// MergeStatusConditions returns a new status condition array with merged status conditions. It is based on newConditions,
// and merges the corresponding existing conditions if exists.
func mergeStatusConditions(conditions []metav1.Condition, newConditions ...metav1.Condition) []metav1.Condition {
	merged := []metav1.Condition{}

	merged = append(merged, conditions...)

	for _, condition := range newConditions {
		// merge two conditions if necessary
		meta.SetStatusCondition(&merged, condition)
	}

	return merged
}

func updateDexServerStatusConditions(c client.Client, dexServer *authv1alpha1.DexServer, newConditions ...metav1.Condition) error {
	dexServer.Status.Conditions = mergeStatusConditions(dexServer.Status.Conditions, newConditions...)
	return c.Status().Update(context.TODO(), dexServer)
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

	dexServerPredicate := predicate.Predicate(predicate.Funcs{
		GenericFunc: func(e event.GenericEvent) bool { return false },
		DeleteFunc:  func(e event.DeleteEvent) bool { return false },
		CreateFunc:  func(e event.CreateEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			dexServerOld := e.ObjectOld.(*authv1alpha1.DexServer)
			dexServerNew := e.ObjectNew.(*authv1alpha1.DexServer)
			// only handle the Finalizer, DeletionStamp and Spec changes
			return !equality.Semantic.DeepEqual(e.ObjectOld.GetFinalizers(), e.ObjectNew.GetFinalizers()) ||
				!equality.Semantic.DeepEqual(e.ObjectOld.GetDeletionTimestamp(), e.ObjectNew.GetDeletionTimestamp()) ||
				!equality.Semantic.DeepEqual(dexServerOld.Spec, dexServerNew.Spec)

		},
	})

	// Watch for updates to the secrets containing credentials for IDP connectors (example: Github client secret, LDAP bind password etc)
	// These secrets are labelled with auth.identitatem.io/idp-credential=""
	secretPredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			if _, ok := e.ObjectNew.GetLabels()[IDP_CREDENTIAL_LABEL]; ok {
				return true
			}
			return false
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&authv1alpha1.DexServer{}, builder.WithPredicates(dexServerPredicate)).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&corev1.Secret{}).
		Owns(&appsv1.Deployment{}, deploymentOwnsOpts...).
		Owns(&networkingv1.Ingress{}).
		Watches(&source.Kind{Type: &corev1.Secret{}}, // Since the IDP credential secrets are not generated by this controller, updates to them will not trigger the reconcile loop. We need map them to a resource (dexserver) that is managed by this controller.
			handler.EnqueueRequestsFromMapFunc(func(a client.Object) []reconcile.Request {
				var dexServerList authv1alpha1.DexServerList
				_ = mgr.GetClient().List(context.TODO(), &dexServerList)

				var requests = []reconcile.Request{}

				for _, dexServer := range dexServerList.Items {
					requests = append(requests, reconcile.Request{
						NamespacedName: types.NamespacedName{
							Name:      dexServer.Name,
							Namespace: dexServer.Namespace,
						},
					})
				}
				return requests // Events from the watched secrets mapped to the DexServer resource
			}),
			builder.WithPredicates(secretPredicate)). // Predicate to ensure we're only watching secrets that have the label "auth.identitatem.io/idp-credential" on them
		Complete(r)
}

// func (r *DexServerReconciler) startdexServer(ctx context.Context, ds *v1alpha1.DexServer, c client.Client) (*v1alpha1.DexServer, error) {
// 	switch {
// 	case len(ds.Spec.Connectors) != 0:
// 		log.Info("Found connector!")
// 	}
// 	return updateStatus(ctx, ds, c)
// }
