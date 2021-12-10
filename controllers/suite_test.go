// Copyright Red Hat

package controllers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	authv1alpha1 "github.com/identitatem/dex-operator/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	k8sClient  client.Client
	testEnv    *envtest.Environment
	ctx        context.Context
	cancel     context.CancelFunc
	rDexServer DexServerReconciler
	rDexClient DexClientReconciler
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

	By("Init the reconcilers")
	rDexServer = DexServerReconciler{
		Client:             k8sClient,
		KubeClient:         kubernetes.NewForConfigOrDie(cfg),
		DynamicClient:      dynamic.NewForConfigOrDie(cfg),
		APIExtensionClient: apiextensionsclient.NewForConfigOrDie(cfg),
		Scheme:             scheme.Scheme,
	}

	err = (rDexServer).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	rDexClient = DexClientReconciler{
		Client: k8sClient,
		Scheme: scheme.Scheme,
	}

	err = (rDexClient).SetupWithManager(k8sManager)
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
