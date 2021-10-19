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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	authv1alpha1 "github.com/identitatem/dex-operator/api/v1alpha1"
	dexapi "github.com/identitatem/dex-operator/controllers/dex"
)

const (
	DEX_CLIENT_SECRET_LABEL           = "auth.identitatem.io/dex-client-secret"
	DEX_CLIENT_SECRET_HASH_ANNOTATION = "auth.identitatem.io/dex-client-secret-hash"
)

// DexClientReconciler reconciles a DexClient object
type DexClientReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=auth.identitatem.io,resources=dexclients,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=auth.identitatem.io,resources=dexclients/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=auth.identitatem.io,resources=dexclients/finalizers,verbs=update
//+kubebuilder:rbac:groups="rbac.authorization.k8s.io",resources={clusterroles},verbs=get;list;watch;create;update;patch;delete;escalate;bind
//+kubebuilder:rbac:groups="apiextensions.k8s.io",resources={customresourcedefinitions},verbs=get;list;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;patch;delete;update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the DexClient object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *DexClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrllog.FromContext(ctx)
	log.V(1).Info("Reconciling...")

	dexv1Client := &authv1alpha1.DexClient{}
	if err := r.Get(ctx, req.NamespacedName, dexv1Client); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("found dexclient", "DexClient.name", dexv1Client.Name, "DexClient.namespace", dexv1Client.Namespace)

	// If dex server and dex client are created at the same time, we may need to wait a few seconds for dex server reconciler
	// to create the mtls certs
	mTLSSecret, err := r.getMTLSSecret(dexv1Client, ctx)
	if err != nil {
		if errors.IsNotFound(err) {
			cond := metav1.Condition{
				Type:    authv1alpha1.DexClientConditionTypeApplied,
				Status:  metav1.ConditionFalse,
				Reason:  "MTLSSecretNotFound",
				Message: "waiting for dex server mtls certificates",
			}
			if err := r.updateDexClientStatusConditions(dexv1Client, ctx, cond); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{Requeue: true, RequeueAfter: 5 * time.Second}, nil
		} else {
			log.Error(err, "Error getting mTLS certificate to create api client connection to gRPC server", "client", dexv1Client.Name)
			cond := metav1.Condition{
				Type:    authv1alpha1.DexClientConditionTypeApplied,
				Status:  metav1.ConditionFalse,
				Reason:  "MTLSSecretCheckFailed",
				Message: fmt.Sprintf("failed checking MTLS secret. error: %s", err.Error()),
			}
			if err := r.updateDexClientStatusConditions(dexv1Client, ctx, cond); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, err
		}
	}

	// Fetch the mTLS client cert and create the grpc client

	dexApiOptions := &dexapi.Options{
		HostAndPort: fmt.Sprintf("%s.%s.%s%s", GRPC_SERVICE_NAME, dexv1Client.Namespace, "svc.cluster.local", ":5557"),
		CABuffer:    bytes.NewBuffer(mTLSSecret.Data["ca.crt"]),
		CrtBuffer:   bytes.NewBuffer(mTLSSecret.Data["client.crt"]),
		KeyBuffer:   bytes.NewBuffer(mTLSSecret.Data["client.key"]),
	}
	dexApiClient, err := dexapi.NewClientPEM(dexApiOptions)
	if err != nil {
		log.Error(err, "Failed to create api client connection to gRPC server", "client", dexv1Client.Name)
		cond := metav1.Condition{
			Type:    authv1alpha1.DexClientConditionTypeApplied,
			Status:  metav1.ConditionFalse,
			Reason:  "GRPCConnectionFailed",
			Message: fmt.Sprintf("failed creating api client connection to gRPC server. error: %s", err.Error()),
		}
		if err := r.updateDexClientStatusConditions(dexv1Client, ctx, cond); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	defer dexApiClient.CloseConnection()

	hasClientSecretBeenUpdated, err := r.hasClientSecretBeenUpdated(dexv1Client, ctx)
	if err != nil {
		return ctrl.Result{}, err
	}	

	if err != nil {
		log.Error(err, "Failed to determine whether the dex client secret has been updated")
		return ctrl.Result{}, err
	}

	if !isOAuth2ClientCreated(dexv1Client.Status.Conditions) {
		// Create a new OAuth2Client
		requeue, err := r.CreateOAuth2Client(dexApiClient, dexv1Client, ctx)
		if err != nil {
			return ctrl.Result{}, err
		} else if requeue {
			return ctrl.Result{Requeue: true}, nil 
		}
	} else {
		if hasClientSecretBeenUpdated { // If the client secret has been updated, we will need to delete and recreate the OAuth2Client (since the dex API for UpdateClient does not accept the secret for updating)
			// Delete OAuth2Client
			err := r.DeleteOAuth2Client(dexApiClient, dexv1Client, ctx)
			if err != nil {
				return ctrl.Result{}, err
			}			

			// Recreate OAuth2Client
			requeue, err := r.CreateOAuth2Client(dexApiClient, dexv1Client, ctx)
			if err != nil {
				return ctrl.Result{}, err
			} else if requeue {
				return ctrl.Result{Requeue: true}, nil 
			}
		} else {
			// Update Oauth2Client
			r.UpdateOAuth2Client(dexApiClient, dexv1Client, ctx)
			if err != nil {
				return ctrl.Result{}, err
			}				
		}
	}
	return ctrl.Result{}, nil
}

func (r *DexClientReconciler) CreateOAuth2Client(dexApiClient *dexapi.APIClient, dexv1Client *authv1alpha1.DexClient, ctx context.Context) (bool, error) {
	log := ctrllog.FromContext(ctx)
	requeue := false

	log.Info("Creating dex client", "name", dexv1Client.Name,
		"redirectURIs", dexv1Client.Spec.RedirectURIs,
		"TrustedPeers", dexv1Client.Spec.TrustedPeers,
		"Public", dexv1Client.Spec.Public,
		"ClientID", dexv1Client.Spec.ClientID,
		"LogoURL", dexv1Client.Spec.LogoURL,
		"clientSecretRef", dexv1Client.Spec.ClientSecretRef.Name)

	// read clientSecret from secret
	dexclientclientSecret, err := r.getClientClientSecretFromRef(dexv1Client, ctx)

	if err != nil {
		log.Error(err, "Client create failed on client secret", "client", dexv1Client.Name)
		cond := metav1.Condition{
			Type:    authv1alpha1.DexClientConditionTypeApplied,
			Status:  metav1.ConditionFalse,
			Reason:  "DexClientSecretFailed",
			Message: fmt.Sprintf("failed getting client secret. error: %s", err.Error()),
		}
		if err := r.updateDexClientStatusConditions(dexv1Client, ctx, cond); err != nil {
			return requeue, err
		}
		return requeue, err
	}

	// Implement dex auth client creation here
	res, createClientError := dexApiClient.CreateClient(
		ctx,
		dexv1Client.Spec.RedirectURIs,
		dexv1Client.Spec.TrustedPeers,
		dexv1Client.Spec.Public,
		dexv1Client.Name,
		dexv1Client.Spec.ClientID,
		dexv1Client.Spec.LogoURL,
		dexclientclientSecret,
	)
	if createClientError != nil {
		if createClientError.AlreadyExists {
			// We didn't expect an oauth2client, but it's there... requeue to call UpdateClient instead
			cond := metav1.Condition{
				Type:    authv1alpha1.DexClientConditionTypeOAuth2ClientCreated,
				Status:  metav1.ConditionTrue,
				Reason:  "Exists",
				Message: "oauth2client found",
			}
			if err := r.updateDexClientStatusConditions(dexv1Client, ctx, cond); err != nil {
				return requeue, err
			}
			requeue = true
			return requeue, nil
		} else {
			log.Error(createClientError.ApiError, "Client create failed", "client", dexv1Client.Name)
			cond := metav1.Condition{
				Type:    authv1alpha1.DexClientConditionTypeApplied,
				Status:  metav1.ConditionFalse,
				Reason:  "DexClientCreateFailed",
				Message: fmt.Sprintf("failed creating client. error: %s", createClientError.ApiError.Error()),
			}
			if err := r.updateDexClientStatusConditions(dexv1Client, ctx, cond); err != nil {
				return requeue, err
			}
			return requeue, createClientError.ApiError
		}
	} else {
		log.Info("Client created", "client ID", res.GetId())
		condApplied := metav1.Condition{
			Type:    authv1alpha1.DexClientConditionTypeApplied,
			Status:  metav1.ConditionTrue,
			Reason:  "Created",
			Message: "Dex client is created",
		}
		condOauth := metav1.Condition{
			Type:    authv1alpha1.DexClientConditionTypeOAuth2ClientCreated,
			Status:  metav1.ConditionTrue,
			Reason:  "Created",
			Message: "oauth2client is created",
		}
		if err := r.updateDexClientStatusConditions(dexv1Client, ctx, condApplied, condOauth); err != nil {
			return requeue, err
		}
	}
	return requeue, nil
}

func (r *DexClientReconciler) UpdateOAuth2Client(dexApiClient *dexapi.APIClient, dexv1Client *authv1alpha1.DexClient, ctx context.Context) (error) {
	log := ctrllog.FromContext(ctx)
	// Update Client
	log.Info("Client update", "client ID", dexv1Client.Name)
	err := dexApiClient.UpdateClient(
		ctx,
		dexv1Client.Spec.ClientID,
		dexv1Client.Spec.RedirectURIs,
		dexv1Client.Spec.TrustedPeers,
		dexv1Client.Spec.Public,
		dexv1Client.Name,
		dexv1Client.Spec.LogoURL,
	)
	if err != nil {
		log.Error(err, "Client update failed", "client", dexv1Client.Name)
		cond := metav1.Condition{
			Type:    authv1alpha1.DexClientConditionTypeApplied,
			Status:  metav1.ConditionFalse,
			Reason:  "DexClientUpdateFailed",
			Message: fmt.Sprintf("failed updating client. error: %s", err.Error()),
		}
		if err := r.updateDexClientStatusConditions(dexv1Client, ctx, cond); err != nil {
			return err
		}
		return err
	} else {
		log.Info("Client updated", "client ID", dexv1Client.Name)
		cond := metav1.Condition{
			Type:    authv1alpha1.DexClientConditionTypeApplied,
			Status:  metav1.ConditionTrue,
			Reason:  "Updated",
			Message: "Dex client is updated",
		}
		if err := r.updateDexClientStatusConditions(dexv1Client, ctx, cond); err != nil {
			return err
		}
	}
	return nil
}

func (r *DexClientReconciler) DeleteOAuth2Client(dexApiClient *dexapi.APIClient, dexv1Client *authv1alpha1.DexClient, ctx context.Context) (error) {
	log := ctrllog.FromContext(ctx)
	// Delete Client
	log.Info("Client delete", "client ID", dexv1Client.Name)
	err := dexApiClient.DeleteClient(
		ctx,
		dexv1Client.Spec.ClientID,
	)
	if err != nil {
		log.Error(err, "Client deletion failed", "client", dexv1Client.Name)
		return err
	}
	return nil
}

// Check if the secret already contains the required label "auth.identitatem.io/dex-client-secret"
// and if it doesn't then add the label - this label allows us to watch specific secrets for updates
func checkAndAddLabelToClientSecret(secret *corev1.Secret, r *DexClientReconciler, ctx context.Context) {
	log := ctrllog.FromContext(ctx)

	if secret.Labels == nil {
		secret.Labels = make(map[string]string)
	}
	if _, ok := secret.Labels[DEX_CLIENT_SECRET_LABEL]; !ok {
		secret.Labels[DEX_CLIENT_SECRET_LABEL] = ""
		if err := r.Update(ctx, secret); err != nil {
			log.Error(err, "Error updating dex client secret with label")
		}
	}
}

// Get the sha256 checksum for the Dex Client secret
func (r *DexClientReconciler) getHashForASecret(dexv1Client *authv1alpha1.DexClient, ctx context.Context) (string, error) {
	log := ctrllog.FromContext(ctx)
	secretName := dexv1Client.Spec.ClientSecretRef.Name
	secretNamespace := dexv1Client.Spec.ClientSecretRef.Namespace

	// Get client secret from ref
	dexclientclientSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, dexclientclientSecret); err != nil {
		if !kubeerrors.IsNotFound(err) {
			return "", err
		}
	} else {
		// Get hash for client secret
		jsonData, err := json.Marshal(dexclientclientSecret)
		if err != nil {
			log.Error(err, "failed to marshal dex client secret JSON")
		}
		h := sha256.New()
		h.Write([]byte(jsonData))
		return fmt.Sprintf("%x", h.Sum(nil)), nil
	}
	return "", nil
}

// Check to see if the dex client secret has been updated: This is done by adding an annotation containing
// the client secret's hash to the Dex Client resource and comparing the stored hash with the newly computed hash
func (r *DexClientReconciler) hasClientSecretBeenUpdated(dexv1Client *authv1alpha1.DexClient, ctx context.Context) (bool, error) {
	log := ctrllog.FromContext(ctx)

	// Get hash for the client secret
	dexClientSecretHash, err := r.getHashForASecret(dexv1Client, ctx)

	if err != nil {
		log.Error(err, "failed to get sha256 checksum for the dex client secret")
		return false, err
	}

	if dexv1Client.Annotations == nil {
		dexv1Client.Annotations = make(map[string]string)
	}

	if hashValue, ok := dexv1Client.Annotations[DEX_CLIENT_SECRET_HASH_ANNOTATION]; !ok {
		// In the dex client add an annotation for the client secret hash if there isn't one yet
		dexv1Client.Annotations[DEX_CLIENT_SECRET_HASH_ANNOTATION] = dexClientSecretHash
		if err := r.Update(ctx, dexv1Client); err != nil {
			log.Error(err, "Error updating dex client with client secret hash")
			return false, err
		}
	} else if hashValue != dexClientSecretHash { // The Dex client secret has been edited, we must delete and recreate the Oauth2Client
		log.Info("The Dex client secret has been updated")
		// In the dex client update the annotation with the newly computed client secret hash
		dexv1Client.Annotations[DEX_CLIENT_SECRET_HASH_ANNOTATION] = dexClientSecretHash
		if err := r.Update(ctx, dexv1Client); err != nil {
			log.Error(err, "Error updating dex client with client secret hash")
			return true, err
		}
		return true, nil
	}
	return false, nil
}

func isOAuth2ClientCreated(conditions []metav1.Condition) bool {
	for _, condition := range conditions {
		if condition.Type == authv1alpha1.DexClientConditionTypeOAuth2ClientCreated {
			return condition.Status == metav1.ConditionTrue
		}
	}
	return false
}

func (r *DexClientReconciler) updateDexClientStatusConditions(dexClient *authv1alpha1.DexClient, ctx context.Context, newConditions ...metav1.Condition) error {
	dexClient.Status.Conditions = mergeStatusConditions(dexClient.Status.Conditions, newConditions...)
	return r.Client.Status().Update(ctx, dexClient)
}

// SetupWithManager sets up the controller with the Manager.
func (r *DexClientReconciler) SetupWithManager(mgr ctrl.Manager) error {

	dexClientPredicate := predicate.Predicate(predicate.Funcs{
		GenericFunc: func(e event.GenericEvent) bool { return false },
		DeleteFunc:  func(e event.DeleteEvent) bool { return false },
		CreateFunc:  func(e event.CreateEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			dexClientOld := e.ObjectOld.(*authv1alpha1.DexClient)
			dexClientNew := e.ObjectNew.(*authv1alpha1.DexClient)
			// only handle the Finalizer and Spec changes
			return !equality.Semantic.DeepEqual(e.ObjectOld.GetFinalizers(), e.ObjectNew.GetFinalizers()) ||
				!equality.Semantic.DeepEqual(dexClientOld.Spec, dexClientNew.Spec)

		},
	})

	// Watch for updates to the secrets containing the client secret for clusters to connect to the DexServer
	// These secrets are labelled with auth.identitatem.io/dex-client-secret=""
	clientSecretPredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			if _, ok := e.ObjectNew.GetLabels()[DEX_CLIENT_SECRET_LABEL]; ok {
				return true
			}
			return false
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&authv1alpha1.DexClient{}, builder.WithPredicates(dexClientPredicate)).
		Owns(&corev1.Secret{}).
		Watches(&source.Kind{Type: &corev1.Secret{}}, // Since the client secrets for Dex Clients are not generated by this controller, updates to them will not trigger the reconcile loop. We need map them to a resource (dex client) that is managed by this controller.
			handler.EnqueueRequestsFromMapFunc(func(a client.Object) []reconcile.Request {
				var dexClientList authv1alpha1.DexClientList
				_ = mgr.GetClient().List(context.TODO(), &dexClientList)

				var requests = []reconcile.Request{}

				for _, dexClient := range dexClientList.Items {
					requests = append(requests, reconcile.Request{
						NamespacedName: types.NamespacedName{
							Name:      dexClient.Name,
							Namespace: dexClient.Namespace,
						},
					})
				}
				return requests // Events from the watched secrets mapped to the DexClient resource
			}),
			builder.WithPredicates(clientSecretPredicate)). // Predicate to ensure we're only watching secrets that have the label "auth.identitatem.io/dex-client-secret" on them
		Complete(r)
}

func (r *DexClientReconciler) getMTLSSecret(m *authv1alpha1.DexClient, ctx context.Context) (*corev1.Secret, error) {
	// each dexserver will run in its own namespace
	// the dex controller will connect to mulitple dexservers
	// given a DexClient, the MTLS secret will be in the same namespace
	// we can find this secret by convention name
	secretNamespace := m.Namespace

	resource := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: SECRET_MTLS_NAME, Namespace: secretNamespace}, resource); err != nil {
		// failed to find the secret, wait for the secret to exist
		return nil, err
	}
	// secret exists, continue reading MTLS and connect to GRPC
	return resource, nil
}

func (r *DexClientReconciler) getClientClientSecretFromRef(m *authv1alpha1.DexClient, ctx context.Context) (string, error) {
	log := ctrllog.FromContext(ctx)
	secretName := m.Spec.ClientSecretRef.Name
	secretNamespace := m.Spec.ClientSecretRef.Namespace
	log.Info("getClientClientSecretFromRef", "secretName", secretName, "secretNamespace", "secretNamespace")

	resource := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: secretNamespace}, resource); err != nil {
		return "", err
	}

	// Add the label "auth.identitatem.io/dex-client-secret" to the Dex Client so that we can watch for any updates to it
	checkAndAddLabelToClientSecret(resource, r, ctx)

	log.Info("retrieve clientSecret in ", "secretName", secretName, "secretNamespace", "secretNamespace")
	if secret, ok := resource.Data["clientSecret"]; ok {
		log.Info("found clientSecret in ", "secretName", secretName, "secretNamespace", "secretNamespace")
		return string(secret), nil
	}
	return "", fmt.Errorf("secret %s/%s doesn't contain the data clientSecret", secretNamespace, secretName)
}
