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
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"context"

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

		dep := r.deploymentForDexConfig(dexconfig)
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
								ContainerPort: 55556,
								Name:          "http",
							}, {
								ContainerPort: 55557,
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

// getDexResources will return the ResourceRequirements for the Dex container.
func getDexResources(cr *identitatemiov1alpha1.DexConfig) corev1.ResourceRequirements {
	resources := corev1.ResourceRequirements{}
	return resources
}

// labelsForDexConfig returns the labels for selecting the resources
// belonging to the given dexconfig CR name.
func labelsForDexConfig(name string) map[string]string {
	return map[string]string{"app": "dexconfig", "dexconfig_cr": name}
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
