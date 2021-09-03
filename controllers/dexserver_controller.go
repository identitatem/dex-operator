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
	"fmt"

	routev1 "github.com/openshift/api/route/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	authv1alpha1 "github.com/identitatem/dex-operator/api/v1alpha1"
)

const (
	SECRET_MTLS_NAME      = "mtls-secret"
	SECRET_MTLS_SUFFIX    = "-mtls"
	SECRET_WEB_TLS_SUFFIX = "-tls-secret"
	SERVICE_ACCOUNT_NAME  = "dex-operator-dexsso"
	GRPC_SERVICE_NAME     = "dex"
	DEX_IMAGE             = "quay.io/dexidp/dex:v2.28.1"
)

var (
	apiGV = authv1alpha1.GroupVersion.String()
	ctls  ClientTLS
)

type ClientTLS struct {
	caPEM            *bytes.Buffer
	clientPEM        *bytes.Buffer
	clientPrivKeyPEM *bytes.Buffer
}

// DexServerReconciler reconciles a DexServer object
type DexServerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
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
//+kubebuilder:rbac:groups="apiextensions.k8s.io",resources={customresourcedefinitions},verbs=get;list;create;update;patch;delete

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
	dexServer := &authv1alpha1.DexServer{}
	if err := r.Get(ctx, req.NamespacedName, dexServer); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	switch {

	case isNotDefinedMTLSSecret(dexServer, r, ctx):
		caPEM, caPrivKeyPEM, certPEM, certPrivKeyPEM, clientPEM, clientPrivKeyPEM, err := createMTLS()
		if err != nil {
			log.Info("failed to generate ca, cert and key")
			return ctrl.Result{}, err
		}
		spec := r.defineSecret(dexServer, caPEM, caPrivKeyPEM, certPEM, certPrivKeyPEM, clientPEM, clientPrivKeyPEM)
		log.Info("Creating a new Secret", "Secret.Namespace", spec.Namespace, "Secret.Name", spec.Name)
		if err := r.Create(ctx, spec); err != nil {
			log.Info("failed to create Secret", "Secret.Name", spec.Name)
			return ctrl.Result{}, err
		}
		ctls.caPEM = caPEM
		ctls.clientPEM = clientPEM
		ctls.clientPrivKeyPEM = clientPrivKeyPEM
		return ctrl.Result{Requeue: true}, nil

	case isNotDefinedConfigmap(dexServer, r, ctx):
		spec := r.defineConfigMap(dexServer, ctx)
		log.Info("Creating a new ConfigMap", "ConfigMap.Namespace", spec.Namespace, "ConfigMap.Name", spec.Name)
		if err := r.Create(ctx, spec); err != nil {
			log.Info("failed to create configmap", "ConfigMap.Name", spec.Name)
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil

	case isNotDefinedService(dexServer, r, ctx):
		spec := r.defineService(dexServer)
		log.Info("Creating a new Service", "Service.Namespace", spec.Namespace, "Service.Name", spec.Name)
		if err := r.Create(ctx, spec); err != nil {
			log.Info("failed to create service", "Service.Name", spec.Name)
			return ctrl.Result{}, err
		}
		specGrpc := r.defineServiceGrpc(dexServer)
		log.Info("Creating a new Service", "Service.Namespace", specGrpc.Namespace, "Service.Name", specGrpc.Name)
		if err := r.Create(ctx, specGrpc); err != nil {
			log.Info("failed to create grpc service", "Service.Name", specGrpc.Name)
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil

	case isNotDefinedServiceAccount(dexServer, r, ctx):
		spec := r.defineServiceAccount(dexServer)
		log.Info("Creating a new ServiceAccount", "ServiceAccount.Namespace", spec.Namespace, "ServiceAccount.Name", spec.Name)
		if err := r.Create(ctx, spec); err != nil {
			log.Info("failed to create ServiceAccount", "ServiceAccount.Name", SERVICE_ACCOUNT_NAME)
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil

	case isNotDefinedDeployment(dexServer, r, ctx):
		spec := r.defineDeployment(dexServer)
		log.Info("Creating a new Deployment", "Deployment.Namespace", spec.Namespace, "Deployment.Name", spec.Name)
		if err := r.Create(ctx, spec); err != nil {
			log.Info("failed to create deployment", "Deployment.Name", spec.Name)
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil

	case isNotDefinedRoute(dexServer, r, ctx):
		spec := r.defineRoute(dexServer)
		log.Info("Creating a new Route", "Route.Namespace", spec.Namespace, "Route.Name", spec.Name)
		if err := r.Create(ctx, spec); err != nil {
			log.Info("failed to create Route", "Route.Name", spec.Name)
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil

	// TODO(cdoan): check CA or CERT renew?
	default:
		log.Info("dexServer started and NOT finished")
	}

	return ctrl.Result{}, nil
}

func isNotDefinedMTLSSecret(m *authv1alpha1.DexServer, r *DexServerReconciler, ctx context.Context) bool {
	resource := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: fmt.Sprintf(m.Name + SECRET_MTLS_SUFFIX), Namespace: m.Namespace}, resource); err != nil && errors.IsNotFound(err) {
		return true
	}
	return false
}

func isNotDefinedRoute(m *authv1alpha1.DexServer, r *DexServerReconciler, ctx context.Context) bool {
	resource := &routev1.Route{}
	if err := r.Get(ctx, types.NamespacedName{Name: m.Name, Namespace: m.Namespace}, resource); err != nil && errors.IsNotFound(err) {
		return true
	}
	return false
}

func isNotDefinedServiceAccount(m *authv1alpha1.DexServer, r *DexServerReconciler, ctx context.Context) bool {
	resource := &corev1.ServiceAccount{}
	// if err := r.Get(ctx, types.NamespacedName{Name: m.Name, Namespace: m.Namespace}, resource); err != nil && errors.IsNotFound(err) {
	if err := r.Get(ctx, types.NamespacedName{Name: SERVICE_ACCOUNT_NAME, Namespace: m.Namespace}, resource); err != nil {
		if errors.IsNotFound(err) {
			return true
		} else {
			return true
		}
	}
	return false
}

func isNotDefinedDeployment(m *authv1alpha1.DexServer, r *DexServerReconciler, ctx context.Context) bool {
	resource := &appsv1.Deployment{}
	if err := r.Get(ctx, types.NamespacedName{Name: m.Name, Namespace: m.Namespace}, resource); err != nil && errors.IsNotFound(err) {
		return true
	}
	return false
}

func isNotDefinedService(m *authv1alpha1.DexServer, r *DexServerReconciler, ctx context.Context) bool {
	resource := &corev1.Service{}
	if err := r.Get(ctx, types.NamespacedName{Name: m.Name, Namespace: m.Namespace}, resource); err != nil && errors.IsNotFound(err) {
		return true
	}
	return false
}

func isNotDefinedConfigmap(m *authv1alpha1.DexServer, r *DexServerReconciler, ctx context.Context) bool {
	resource := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Name: m.Name, Namespace: m.Namespace}, resource); err != nil && errors.IsNotFound(err) {
		// spec := r.defineConfigMap(m)
		// log.Info("Creating a new ConfigMap", "ConfigMap.Namespace", spec.Namespace, "ConfigMap.Name", spec.Name)
		// if err = r.Create(ctx, spec); err != nil {
		// 	log.Debug("failed to create configmap", spec.Name)
		// 	return false
		// }
		// return true
		return true
	}
	return false
}

func getClientSecretFromRef(m *authv1alpha1.DexServer, r *DexServerReconciler, ctx context.Context) string {
	var secretNamespace string
	secretName := m.Spec.Connectors[0].Config.ClientSecretRef.Name
	if secretNamespace = m.Spec.Connectors[0].Config.ClientSecretRef.Namespace; secretNamespace == "" {
		secretNamespace = m.Namespace
	}
	resource := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, resource); err != nil && errors.IsNotFound(err) {
		// TODO(cdoan): handle errors
		return ""
	}
	return string(resource.Data["clientSecret"])
}

// Define the secret for grpc Mutual TLS. This secret is volume mounted on the dex instance pod. The client cert should be loaded by the gRPC client code.
func (r *DexServerReconciler) defineSecret(m *authv1alpha1.DexServer, caPEM, caPrivKeyPEM, certPEM, certPrivKeyPEM, clientPEM, clientPrivKeyPEM *bytes.Buffer) *corev1.Secret {
	labels := map[string]string{
		"app": m.Name,
	}
	secretSpec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf(m.Name + SECRET_MTLS_SUFFIX),
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

func (r *DexServerReconciler) defineServiceAccount(m *authv1alpha1.DexServer) *corev1.ServiceAccount {
	labels := map[string]string{
		"app": m.Name,
	}
	serviceAccountSpec := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SERVICE_ACCOUNT_NAME,
			Namespace: m.Namespace,
			Labels:    labels,
		},
	}
	ctrl.SetControllerReference(m, serviceAccountSpec, r.Scheme)
	return serviceAccountSpec
}

// Defines the dex instance (dex server).
func (r *DexServerReconciler) defineDeployment(m *authv1alpha1.DexServer) *appsv1.Deployment {
	ls := labelsForDexServer(m.Name, m.Namespace)
	// replicas := m.Spec.Size
	var replicas int32 = 1

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.Name,
			Namespace: m.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: ls,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: ls,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Command: []string{
							"/usr/local/bin/dex",
							"serve",
							"/etc/dex/cfg/config.yaml",
						},
						Image:           DEX_IMAGE,
						ImagePullPolicy: corev1.PullAlways,
						Name:            m.Name,
						Env: []corev1.EnvVar{
							{
								// FIX: failed to initialize storage: failed to inspect service account token:
								//      jwt claim "kubernetes.io/serviceaccount/namespace" not found
								Name:  "KUBERNETES_POD_NAMESPACE",
								Value: m.Namespace,
							},
						},
						Ports: []corev1.ContainerPort{
							{
								ContainerPort: 5556,
								Name:          "https",
							}, {
								ContainerPort: 5557,
								Name:          "grpc",
							},
						},
						Resources: getDexResources(m),
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "config", // the dex config.yaml
								MountPath: "/etc/dex/cfg",
							},
							{
								Name:      "tls",
								MountPath: "/etc/dex/tls",
							},
							{
								Name:      "mtls",
								MountPath: "/etc/dex/mtls",
							},
						},
					}},
					Volumes: []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: m.Name,
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "config.yaml",
											Path: "config.yaml",
										},
									},
								},
							},
						},
						{
							Name: "tls",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									// this secret is generated using service serving certificate via service annotation
									// service.beta.openshift.io/serving-cert-secret-name: m.Name-tls-secret
									SecretName: fmt.Sprintf(m.Name + SECRET_WEB_TLS_SUFFIX),
								},
							},
						},
						{
							Name: "mtls",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									// This secret is generated by this controller, here we load the server side cert and ca
									// service.beta.openshift.io/serving-cert-secret-name: m.Name-mtls-secret
									SecretName: fmt.Sprintf(m.Name + SECRET_MTLS_SUFFIX),
								},
							},
						},
					},
				},
			},
		},
	}

	// TODO: dep.Spec.Template.Spec.ServiceAccountName = m.Name
	dep.Spec.Template.Spec.ServiceAccountName = SERVICE_ACCOUNT_NAME

	ctrl.SetControllerReference(m, dep, r.Scheme)
	return dep
}

func (r *DexServerReconciler) defineService(m *authv1alpha1.DexServer) *corev1.Service {
	// ls := labelsForDexConfig(m.Name)
	labels := map[string]string{
		"app": m.Name,
	}
	matchlabels := map[string]string{
		"app": m.Name,
	}
	resource := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.Name,
			Namespace: m.Namespace,
			Labels:    labels,
			Annotations: map[string]string{
				"service.beta.openshift.io/serving-cert-secret-name": fmt.Sprintf(m.Name + SECRET_WEB_TLS_SUFFIX),
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Port:     5556,
					Protocol: "TCP",
					Name:     "http",
				},
			},
			Selector: matchlabels,
		},
	}
	ctrl.SetControllerReference(m, resource, r.Scheme)
	return resource
}

func (r *DexServerReconciler) defineServiceGrpc(m *authv1alpha1.DexServer) *corev1.Service {
	labels := map[string]string{
		"app": m.Name,
	}
	matchlabels := map[string]string{
		"app": m.Name,
	}
	resource := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GRPC_SERVICE_NAME,
			Namespace: m.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Port:     5557,
					Protocol: "TCP",
					Name:     "grpc",
				},
			},
			Selector: matchlabels,
		},
	}
	ctrl.SetControllerReference(m, resource, r.Scheme)
	return resource
}

func (r *DexServerReconciler) defineConfigMap(m *authv1alpha1.DexServer, ctx context.Context) *corev1.ConfigMap {
	// var configMapData = make(map[string]string)
	// configMapData["config.yaml"] = dexconfigdata
	labels := map[string]string{
		"app": m.Name,
	}
	var Name, BaseDomain, clientID string
	Name = "dex"
	BaseDomain = "example.com"
	clientID = "test-client-id-example"
	clientSecret := getClientSecretFromRef(m, r, ctx)
	// if m.Spec.Connectors[0].Config.ClientID != "" {
	// 	clientID = m.Spec.Connectors[0].Config.ClientID
	// } else {
	// 	clientID = "test-data-clientid"
	// }
	// if m.Spec.Connectors[0].Config.ClientSecret != "" {
	// 	clientSecret = m.Spec.Connectors[0].Config.ClientSecret
	// } else {
	// 	clientSecret = "test-data-clientsecret"
	// }
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.Name,
			Namespace: m.Namespace,
			Labels:    labels,
		},
		Data: map[string]string{"config.yaml": `
issuer: https://` + Name + `.apps.` + BaseDomain + `
storage:
  type: kubernetes
  config:
    inCluster: true
web:
  https: 0.0.0.0:5556
  tlsCert: /etc/dex/tls/tls.crt
  tlsKey: /etc/dex/tls/tls.key
grpc:
  addr: 0.0.0.0:5557
  tlsCert: /etc/dex/mtls/tls.crt
  tlsKey: /etc/dex/mtls/tls.key
  tlsClientCA: /etc/dex/mtls/ca.crt
  reflection: true
connectors:
- type: github
  id: github
  name: GitHub
  config:
    clientID: ` + clientID + `
    clientSecret: ` + clientSecret + `
    redirectURI: https://` + Name + `.apps.` + BaseDomain + `
    org: kubernetes
oauth2:
  skipApprovalScreen: true
staticClients:
- id: example-app
  redirectURIs:
  - 'http://127.0.0.1:5555/callback'
  name: 'Example App'
  secret: another-client-secret
enablePasswordDB: true
`},
	}
	ctrl.SetControllerReference(m, cm, r.Scheme)
	return cm
}

// https://stackoverflow.com/questions/47104454/openshift-online-v3-adding-new-route-gives-forbidden-error
func (r *DexServerReconciler) defineRoute(m *authv1alpha1.DexServer) *routev1.Route {
	ls := labelsForDexServer(m.Name, m.Namespace)
	// routeHost := fmt.Sprintf("%s.apps.%s", m.Name, "pool-sno-8x32-n9kps.demo.red-chesterfield.com")
	routeSpec := &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.Name,
			Namespace: m.Namespace,
			Labels:    ls,
		},
		Spec: routev1.RouteSpec{
			// Host: routeHost,
			TLS: &routev1.TLSConfig{
				Termination: routev1.TLSTerminationPassthrough,
			},
			To: routev1.RouteTargetReference{
				Kind: "Service",
				Name: m.Name,
			},
			Port: &routev1.RoutePort{
				TargetPort: intstr.IntOrString{
					Type:   intstr.String,
					StrVal: "http",
				},
			},
			WildcardPolicy: routev1.WildcardPolicyNone,
		},
	}
	ctrl.SetControllerReference(m, routeSpec, r.Scheme)
	return routeSpec
}

// getDexResources will return the ResourceRequirements for the Dex container.
func getDexResources(cr *authv1alpha1.DexServer) corev1.ResourceRequirements {
	resources := corev1.ResourceRequirements{}
	return resources
}

func labelsForDexServer(name string, namespace string) map[string]string {
	return map[string]string{
		"app":                 name,
		"dexconfig_name":      name,
		"dexconfig_namespace": namespace,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *DexServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authv1alpha1.DexServer{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&corev1.Secret{}).
		Owns(&appsv1.Deployment{}).
		Owns(&routev1.Route{}). /* TODO(cdoan): add Ingress */
		Complete(r)
}

// func (r *DexServerReconciler) startdexServer(ctx context.Context, ds *v1alpha1.DexServer, c client.Client) (*v1alpha1.DexServer, error) {
// 	switch {
// 	case len(ds.Spec.Connectors) != 0:
// 		log.Info("Found connector!")
// 	}
// 	return updateStatus(ctx, ds, c)
// }
