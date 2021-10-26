// Copyright Red Hat

package controllers

import (
	"path/filepath"
	"testing"

	"github.com/ghodss/yaml"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	dexoperatorconfig "github.com/identitatem/dex-operator/config"

	clusteradmasset "open-cluster-management.io/clusteradm/pkg/helpers/asset"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	authv1alpha1 "github.com/identitatem/dex-operator/api/v1alpha1"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = authv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	err = authv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

var _ = Describe("Setup Dex", func() {
	By("Checking the CRDs availability", func() {
		//This is to test if the CRD are available through resources.go
		//as they are needed by other operators to dynamically install this operator
		readerDex := dexoperatorconfig.GetScenarioResourcesReader()
		_, err := getCRD(readerDex, "crd/bases/auth.identitatem.io_dexclients.yaml")
		Expect(err).Should(BeNil())

		_, err = getCRD(readerDex, "crd/bases/auth.identitatem.io_dexservers.yaml")
		Expect(err).Should(BeNil())
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
	// apiClient.ApiextensionsV1().CustomResourceDefinitions().Get()
}
