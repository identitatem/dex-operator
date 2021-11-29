// Copyright Red Hat

package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghodss/yaml"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1beta1 "k8s.io/api/extensions/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	dexoperatorconfig "github.com/identitatem/dex-operator/config"

	clusteradmasset "open-cluster-management.io/clusteradm/pkg/helpers/asset"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	authv1alpha1 "github.com/identitatem/dex-operator/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	k8sClient client.Client
	testEnv   *envtest.Environment
	ctx       context.Context
	cancel    context.CancelFunc
	r         DexServerReconciler
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func(done Done) {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	By("bootstrapping test environment")

	// Set the environment variable required by the dex server controller
	err := os.Setenv("RELATED_IMAGE_DEX", "dex_image")
	Expect(err).NotTo(HaveOccurred())

	// Registering our APIs
	err = authv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	err = appsv1.AddToScheme(scheme.Scheme)
	Expect(err).Should(BeNil())

	//+kubebuilder:scaffold:scheme

	// Configure a new test environment which ingests our CRDs to allow an API server to know about our custom resources
	testEnv = &envtest.Environment{
		Scheme:                scheme.Scheme,
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	// Start the environment (API server)
	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	// Create a client to talk to the API server
	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	Expect(err).ToNot(HaveOccurred())

	By("Init the reconciler")
	r = DexServerReconciler{
		Client:             k8sClient,
		KubeClient:         kubernetes.NewForConfigOrDie(cfg),
		DynamicClient:      dynamic.NewForConfigOrDie(cfg),
		APIExtensionClient: apiextensionsclient.NewForConfigOrDie(cfg),
		Scheme:             scheme.Scheme,
	}

	err = (r).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		err = k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred(), "failed to run manager")
	}()

	close(done)
}, 60)

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

var _ = Describe("Setup Dex", func() {
	It("Check the CRDs availability", func() {
		// This is to test if the CRD are available through resources.go
		// as they are needed by other operators to dynamically install this operator
		readerDex := dexoperatorconfig.GetScenarioResourcesReader()
		_, err := getCRD(readerDex, "crd/bases/auth.identitatem.io_dexclients.yaml")
		Expect(err).Should(BeNil())

		_, err = getCRD(readerDex, "crd/bases/auth.identitatem.io_dexservers.yaml")
		Expect(err).Should(BeNil())
	})
})

var _ = Describe("DexServer CR with GitHub connector", func() {
	DexServerName := "my-dexserver"
	DexServerNamespace := "my-dexserver-ns"
	AuthRealmName := "my-authrealm"
	AuthRealmNameSpace := "my-authrealm-ns"
	MyGithubAppClientID := "my-github-app-client-id"
	MyGithubAppClientSecretName := AuthRealmName + "github"
	DexServerIssuer := "https://testroutesubdomain.testhost.com"
	var dexServer *authv1alpha1.DexServer

	It("should create a DexServer", func() {
		By("creating a test namespace for the DexServer", func() {
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: DexServerNamespace,
				},
			}
			err := k8sClient.Create(context.TODO(), ns)
			Expect(err).To(BeNil())
		})
		By("creating a test namespace for the AuthRealm", func() {
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: AuthRealmNameSpace,
				},
			}
			err := k8sClient.Create(context.TODO(), ns)
			Expect(err).To(BeNil())
		})
		By("creating a secret containing the Github OAuth client secret", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      MyGithubAppClientSecretName,
					Namespace: AuthRealmNameSpace,
				},
				StringData: map[string]string{
					"clientSecret": "BogusSecret",
				},
			}
			err := k8sClient.Create(context.TODO(), secret)
			Expect(err).To(BeNil())
		})
		By("creating the DexServer CR", func() {
			// A DexServer object with metadata and spec.
			dexServer = &authv1alpha1.DexServer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      DexServerName,
					Namespace: DexServerNamespace,
				},
				Spec: authv1alpha1.DexServerSpec{
					Issuer: DexServerIssuer,
					Connectors: []authv1alpha1.ConnectorSpec{
						{
							Name: "my-github",
							Type: "github",
							GitHub: authv1alpha1.GitHubConfigSpec{
								ClientID: MyGithubAppClientID,
								ClientSecretRef: corev1.SecretReference{
									Name:      MyGithubAppClientSecretName,
									Namespace: AuthRealmNameSpace,
								},
							},
						},
					},
				},
			}
			ctx := context.Background()
			err := k8sClient.Create(ctx, dexServer)
			Expect(err).To(BeNil())

			createdDexServer := &authv1alpha1.DexServer{}

			// Retry getting this newly created dexserver, given that creation may not immediately happen.
			Eventually(func() bool {
				err := k8sClient.Get(ctx, client.ObjectKey{Name: DexServerName, Namespace: DexServerNamespace}, createdDexServer)
				return err == nil
			}, 10, 1).Should(BeTrue())
		})
		By("running reconcile", func() {
			Eventually(func() bool {
				req := ctrl.Request{}
				req.Name = DexServerName
				req.Namespace = DexServerNamespace
				_, err := r.Reconcile(context.TODO(), req)
				return err == nil
			}, 10, 1).Should(BeTrue())
		})
	})
	It("should set finalizer on the DexServer", func() {
		dexServer := &authv1alpha1.DexServer{}
		err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: DexServerName, Namespace: DexServerNamespace}, dexServer)
		Expect(controllerutil.ContainsFinalizer(dexServer, "auth.identitatem.io/cleanup")).To(BeTrue())
		Expect(err).Should(BeNil())
	})
	It("should create http service for the dex server (with the default ingress certificate)", func() {
		const SECRET_WEB_TLS_SUFFIX = "-tls-secret"
		httpService := &corev1.Service{}
		err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: DexServerName, Namespace: DexServerNamespace}, httpService)
		Expect(err).Should(BeNil())
		Expect(httpService).ShouldNot(BeNil())
		Expect(httpService.Spec.Ports[0].Name).To(Equal("http"))
		Expect(httpService.Spec.Ports[0].Port).To(Equal(int32(5556)))
		Expect(httpService.ObjectMeta.Annotations["service.beta.openshift.io/serving-cert-secret-name"]).To(Equal(DexServerName + SECRET_WEB_TLS_SUFFIX))
	})
	It("should create grpc service for the dex server", func() {
		const GRPC_SERVICE_NAME = "grpc"
		grpcService := &corev1.Service{}
		err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: GRPC_SERVICE_NAME, Namespace: DexServerNamespace}, grpcService)
		Expect(err).Should(BeNil())
		Expect(grpcService).ShouldNot(BeNil())
		Expect(grpcService.Spec.Ports[0].Name).To(Equal("grpc"))
		Expect(grpcService.Spec.Ports[0].Port).To(Equal(int32(5557)))
	})
	It("should create ingress for the dex server", func() {
		ingress := &v1beta1.Ingress{}
		err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: DexServerName, Namespace: DexServerNamespace}, ingress)
		Expect(err).Should(BeNil())
		Expect(ingress).ShouldNot(BeNil())
		By("Not specifying an Ingress Certificate ref in the dex server CR")
		Expect(ingress.Spec.TLS).Should(BeNil())
		By("Specifying an Ingress Certificate ref in the dex server CR")
		// Get current dexserver
		err = k8sClient.Get(ctx, client.ObjectKey{Name: DexServerName, Namespace: DexServerNamespace}, dexServer)
		Expect(err).Should(BeNil())
		dexServer.Spec.IngressCertificateRef = corev1.LocalObjectReference{
			Name: "customcert",
		}
		// Update dex server with Ingress cert ref
		err = k8sClient.Update(ctx, dexServer)
		Expect(err).To(BeNil())
		// Retry getting the updated dexserver, given that the update may not immediately happen.
		updatedDexServer := &authv1alpha1.DexServer{}
		Eventually(func() bool {
			err := k8sClient.Get(ctx, client.ObjectKey{Name: DexServerName, Namespace: DexServerNamespace}, updatedDexServer)
			Expect(err).To(BeNil())
			return updatedDexServer.Spec.IngressCertificateRef.Name == "customcert"
		}, 10, 1).Should(BeTrue())
		By("running syncIngress again")
		err = r.syncIngress(updatedDexServer, ctx)
		Expect(err).Should(BeNil())
		err = k8sClient.Get(context.TODO(), client.ObjectKey{Name: DexServerName, Namespace: DexServerNamespace}, ingress)
		Expect(err).Should(BeNil())
		Expect(ingress).ShouldNot(BeNil())
		Expect(ingress.Spec.TLS[0].SecretName).To(Equal("customcert"))
	})
	It("should create ClusterRoleBinding", func() {
		crb := &rbacv1.ClusterRoleBinding{}
		const SERVICE_ACCOUNT_NAME = "dex-operator-dexsso"
		clusterRoleBindingName := SERVICE_ACCOUNT_NAME + "-" + DexServerNamespace
		err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: clusterRoleBindingName}, crb)
		Expect(err).Should(BeNil())
		Expect(crb.RoleRef.Name).To(Equal(SERVICE_ACCOUNT_NAME))
		Expect(len(crb.Subjects)).To(Equal(1))
		Expect(crb.Subjects[0].Namespace).To(Equal(DexServerNamespace))
	})
	It("should create ConfigMap for dex", func() {
		dexConfigMap := &corev1.ConfigMap{}
		err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: DexServerName, Namespace: DexServerNamespace}, dexConfigMap)
		Expect(err).Should(BeNil())
		Expect(dexConfigMap.Data["config.yaml"]).ShouldNot(BeNil())
	})
	It("should create Dex server deployment", func() {
		dsDeployment := &appsv1.Deployment{}
		err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: DexServerName, Namespace: DexServerNamespace}, dsDeployment)
		Expect(err).Should(BeNil())
		By("using the dex image for the deployment", func() {
			Expect(dsDeployment.Spec.Template.Spec.Containers[0].Image).To(Equal("dex_image"))
		})
		By("setting the configHash in the deployment", func() {
			// Get ConfigMap
			dexConfigMap := &corev1.ConfigMap{}
			err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: DexServerName, Namespace: DexServerNamespace}, dexConfigMap)
			Expect(err).Should(BeNil())
			// Calculate hash
			jsonData, err := json.Marshal(dexConfigMap)
			Expect(err).Should(BeNil())
			h := sha256.New()
			h.Write([]byte(jsonData))
			dexConfigMapHash := fmt.Sprintf("%x", h.Sum(nil))
			Expect(dsDeployment.Spec.Template.ObjectMeta.Annotations["auth.identitatem.io/configHash"]).To(Equal(dexConfigMapHash))
		})
		By("setting the MTLS secret expiry timestamp in the deployment", func() {
			// Check that the GRPC MTLS expiry is a valid time in the future
			grpcMTlsExpiry := dsDeployment.Spec.Template.ObjectMeta.Annotations["auth.identitatem.io/grpcMtlsExpiry"]
			Expect(grpcMTlsExpiry).ShouldNot(BeNil())
			t, err := time.Parse(time.RFC3339, grpcMTlsExpiry)
			Expect(err).Should(BeNil())
			currentTime := time.Now()
			Expect(t.After(currentTime)).To(BeTrue())
		})
	})
})

func getCRD(reader *clusteradmasset.ScenarioResourcesReader, file string) (*apiextensionsv1.CustomResourceDefinition, error) {
	b, err := reader.Asset(file)
	if err != nil {
		return nil, err
	}
	crd := &apiextensionsv1.CustomResourceDefinition{}
	if err := yaml.Unmarshal(b, crd); err != nil {
		return nil, err
	}
	return crd, nil
}
