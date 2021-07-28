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
	"fmt"
	"time"

	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	routev1 "github.com/openshift/api/route/v1"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	identitatemiov1alpha1 "github.com/cdoan1/dex-operator/api/v1alpha1"
	"github.com/prometheus/common/log"
)

// DexConfigReconciler reconciles a DexConfig object
type DexConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=identitatem.io,resources=dexconfigs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=identitatem.io,resources=dexconfigs/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=identitatem.io,resources=dexconfigs/finalizers,verbs=update
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=route.openshift.io,resources=routes/custom-host,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the DexConfig object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *DexConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)

	// Fetch the DexConfig instance
	dexconfig := &identitatemiov1alpha1.DexConfig{}
	err := r.Get(ctx, req.NamespacedName, dexconfig)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			log.Info("DexConfig resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get DexConfig")
		return ctrl.Result{}, err
	}

	// Check if the deployment already exists, if not create a new one
	found := &appsv1.Deployment{}
	err = r.Get(ctx, types.NamespacedName{Name: dexconfig.Name, Namespace: dexconfig.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		// Define a new deployment
		var dep *appsv1.Deployment

		if dexconfig.Spec.Type == "community" {
			dep = r.deploymentCommunityForDexConfig(dexconfig)
		} else {
			dep = r.deploymentForDexConfig(dexconfig)
		}
		// dep := r.reconcileDexDeployment(dexconfig)

		log.Info("Creating a new Deployment", "Deployment.Namespace", dep.Namespace, "Deployment.Name", dep.Name)

		err = r.Create(ctx, dep)
		if err != nil {
			log.Error(err, "Failed to create new Deployment", "Deployment.Namespace", dep.Namespace, "Deployment.Name", dep.Name)
			return ctrl.Result{}, err
		}
		// Deployment created successfully - return and requeue
		return ctrl.Result{Requeue: true}, nil
	} else if err != nil {
		log.Error(err, "Failed to get Deployment")
		return ctrl.Result{}, err
	}

	// Check if the service already exists, if not create a new one
	foundserv := &corev1.Service{}
	err = r.Get(ctx, types.NamespacedName{Name: dexconfig.Name, Namespace: dexconfig.Namespace}, foundserv)
	if err != nil && errors.IsNotFound(err) {
		var serv *corev1.Service
		if dexconfig.Spec.Type == "community" {
			serv = r.serviceCommunityForDexConfig(dexconfig)
		} else {
			serv = r.serviceForDexConfig(dexconfig)
		}
		log.Info("Creating a new Service", "Service.Namespace", serv.Namespace, "Service.Name", serv.Name)
		err = r.Create(ctx, serv)
		if err != nil {
			log.Error(err, "Failed to create new Service", "Service.Namespace", serv.Namespace, "Service.Name", serv.Name)
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	} else if err != nil {
		log.Error(err, "Failed to get Service")
		return ctrl.Result{}, err
	}

	// if dexconfig.Spec.Type == "community" {
	// Check if the service already exists, if not create a new one
	foundroute := &routev1.Route{}
	err = r.Get(ctx, types.NamespacedName{Name: dexconfig.Name, Namespace: dexconfig.Namespace}, foundroute)
	if err != nil && errors.IsNotFound(err) {
		routeSpec := r.routeCommunityForDexConfig(dexconfig)
		log.Info("Creating a new Route", "Route.Namespace", routeSpec.Namespace, "Route.Name", routeSpec.Name)
		err = r.Create(ctx, routeSpec)
		if err != nil {
			log.Error(err, "Failed to create new Route", "Route.Namespace", routeSpec.Namespace, "Route.Name", routeSpec.Name)
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	} else if err != nil {
		log.Error(err, "Failed to get Route\n")
		return ctrl.Result{}, err
	}
	// }

	// Ensure the deployment size is the same as the spec
	size := dexconfig.Spec.Size
	if *found.Spec.Replicas != size {
		found.Spec.Replicas = &size
		err = r.Update(ctx, found)
		if err != nil {
			log.Error(err, "Failed to update Deployment", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
			return ctrl.Result{}, err
		}
		// Ask to requeue after 1 minute in order to give enough time for the
		// pods be created on the cluster side and the operand be able
		// to do the next update step accurately.
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	// Update the DexConfig status with the pod names
	// List the pods for this dexconfig's deployment
	// podList := &corev1.PodList{}
	// listOpts := []client.ListOption{
	// 	client.InNamespace(dexconfig.Namespace),
	// 	client.MatchingLabels(labelsForDexConfig(dexconfig.Name)),
	// }
	// if err = r.List(ctx, podList, listOpts...); err != nil {
	// 	log.Error(err, "Failed to list pods", "DexConfig.Namespace", dexconfig.Namespace, "DexConfig.Name", dexconfig.Name)
	// 	return ctrl.Result{}, err
	// }
	// podNames := getPodNames(podList.Items)

	// // Update status.Nodes if needed
	// if !reflect.DeepEqual(podNames, dexconfig.Status.Nodes) {
	// 	dexconfig.Status.Nodes = podNames
	// 	err := r.Status().Update(ctx, dexconfig)
	// 	if err != nil {
	// 		log.Error(err, "Failed to update DexConfig status")
	// 		return ctrl.Result{}, err
	// 	}
	// }

	return ctrl.Result{}, nil
}

func (r *DexConfigReconciler) serviceForDexConfig(m *identitatemiov1alpha1.DexConfig) *corev1.Service {

	// ls := labelsForDexConfig(m.Name)
	labels := map[string]string{
		"app": m.Name,
	}
	matchlabels := map[string]string{
		"app": m.Name,
	}

	serv := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.Name,
			Namespace: m.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Port:     5556,
					Protocol: "TCP",
					Name:     "http",
				},
				{
					Port:     5557,
					Protocol: "TCP",
					Name:     "grpc",
				},
			},
			Selector: matchlabels,
		},
	}
	ctrl.SetControllerReference(m, serv, r.Scheme)
	return serv
}

// deploymentForDexConfig returns a dexconfig Deployment object
func (r *DexConfigReconciler) deploymentForDexConfig(m *identitatemiov1alpha1.DexConfig) *appsv1.Deployment {
	ls := labelsForDexConfig(m.Name)
	log.Info("labels:", ls)

	replicas := m.Spec.Size

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
							"/shared/argocd-dex",
							"rundex",
						},
						Image:           "quay.io/dexidp/dex@sha256:01e996b4b60edcc5cc042227c6965dd63ba68764c25d86b481b0d65f6e4da308",
						ImagePullPolicy: corev1.PullAlways,
						Name:            "dex",
						// Env:             proxyEnvVars(),
						Ports: []corev1.ContainerPort{
							{
								ContainerPort: 5556,
								Name:          "http",
							}, {
								ContainerPort: 5557,
								Name:          "grpc",
							},
						},
						Resources: getDexResources(m),
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "static-files",
							MountPath: "/shared",
						}},
					}},
					InitContainers: []corev1.Container{{
						Command: []string{
							"cp",
							"-n",
							"/usr/local/bin/argocd",
							"/shared/argocd-dex",
						},
						// Env:             proxyEnvVars(),
						Image:           "registry.redhat.io/openshift-gitops-1/argocd-rhel8@sha256:df4b11a78ab8f8a3ee758a1a2b549c190ce1467cdd098a1c10468bbf6e76a596",
						ImagePullPolicy: corev1.PullAlways,
						Name:            "copyutil",
						Resources:       getDexResources(m),
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "static-files",
							MountPath: "/shared",
						}},
					}},
				},
			},
		},
	}

	// TODO: for now, hardcode reference the SA created from CSV
	dep.Spec.Template.Spec.ServiceAccountName = "dex-operator-dexsso"

	dep.Spec.Template.Spec.Volumes = []corev1.Volume{{
		Name: "static-files",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}}

	// Set DexConfig instance as the owner and controller
	ctrl.SetControllerReference(m, dep, r.Scheme)
	return dep
}

// community deployment
func (r *DexConfigReconciler) deploymentCommunityForDexConfig(m *identitatemiov1alpha1.DexConfig) *appsv1.Deployment {
	ls := labelsForDexConfig2(m.Name, m.Namespace)
	replicas := m.Spec.Size

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
						Image:           "quay.io/dexidp/dex:v2.28.1",
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
								Name:      "config",
								MountPath: "/etc/dex/cfg",
							},
							{
								Name:      "tls",
								MountPath: "/etc/dex/tls",
							},
						},
					}},
					Volumes: []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										// Right now, since we're manually creating this config,
										// this is hard coded.
										// can change this to dex configmap in this namespace: dex-community
										Name: "dex-community",
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
									// Can change this to dex.tls in this namespace: dex-community
									SecretName: "dex-community.tls",
								},
							},
						},
					},
				},
			},
		},
	}

	// Right now, we're using the the dex-operator service account name
	// TODO: dex instance itself needs its own service account
	//   dep.Spec.Template.Spec.ServiceAccountName = m.Name
	dep.Spec.Template.Spec.ServiceAccountName = "dex-operator-dexsso"

	ctrl.SetControllerReference(m, dep, r.Scheme)
	return dep
}

// community service
// * expect the TLS CERT and KEY to be manually created
// * expect the dex.tls secret to reference those CERT|KEY
// * the ROUTE is hardcoded for now dex-community.apps.${BASE_DOMAIN}
//
func (r *DexConfigReconciler) serviceCommunityForDexConfig(m *identitatemiov1alpha1.DexConfig) *corev1.Service {
	ls := labelsForDexConfig2(m.Name, m.Namespace)
	log.Info("labels:", ls)
	labels := map[string]string{
		"app": m.Name,
	}
	matchlabels := map[string]string{
		"app": m.Name,
	}
	serv := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.Name,
			Namespace: m.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				{
					Port:     5556,
					Protocol: "TCP",
					Name:     "http",
				},
				{
					Port:     5557,
					Protocol: "TCP",
					Name:     "grpc",
				},
			},
			Selector: matchlabels,
		},
	}
	ctrl.SetControllerReference(m, serv, r.Scheme)
	return serv
}

// https://stackoverflow.com/questions/47104454/openshift-online-v3-adding-new-route-gives-forbidden-error
func (r *DexConfigReconciler) routeCommunityForDexConfig(m *identitatemiov1alpha1.DexConfig) *routev1.Route {
	var bd string
	if m.Spec.BaseDomain != "" {
		bd = m.Spec.BaseDomain
	} else {
		// TODO: need to add logic to automatically get the basedomain of the cluster
		log.Error("BaseDomain required to be set for now ...")
		return nil
	}
	ls := labelsForDexConfig2(m.Name, m.Namespace)
	routeHost := fmt.Sprintf("%s.apps.%s", m.Name, bd)
	routeSpec := &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Name:      m.Name,
			Namespace: m.Namespace,
			Labels:    ls,
		},
		Spec: routev1.RouteSpec{
			Host: routeHost,
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
	// override Termination if gitops
	if m.Spec.Type != "community" {
		routeSpec.Spec.TLS.Termination = routev1.TLSTerminationEdge
	}
	ctrl.SetControllerReference(m, routeSpec, r.Scheme)
	return routeSpec
}

// getDexResources will return the ResourceRequirements for the Dex container.
func getDexResources(cr *identitatemiov1alpha1.DexConfig) corev1.ResourceRequirements {
	resources := corev1.ResourceRequirements{}
	return resources
}

// labelsForDexConfig returns the labels for selecting the resources
// belonging to the given dexconfig CR name.
func labelsForDexConfig(name string) map[string]string {
	return map[string]string{
		"app":            name,
		"dexconfig_name": name,
	}
}

func labelsForDexConfig2(name string, namespace string) map[string]string {
	return map[string]string{
		"app":                 name,
		"dexconfig_name":      name,
		"dexconfig_namespace": namespace,
		"owner":               "dex-operator", // oc get routes -l owner=dex-operator
	}
}

// getPodNames returns the pod names of the array of pods passed in
func getPodNames(pods []corev1.Pod) []string {
	var podNames []string
	for _, pod := range pods {
		podNames = append(podNames, pod.Name)
	}
	return podNames
}

// SetupWithManager sets up the controller with the Manager.
func (r *DexConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&identitatemiov1alpha1.DexConfig{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}
