// Copyright Red Hat

package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ghodss/yaml"
	dexoperatorconfig "github.com/identitatem/dex-operator/config"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	authv1alpha1 "github.com/identitatem/dex-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1beta1 "k8s.io/api/extensions/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clusteradmasset "open-cluster-management.io/clusteradm/pkg/helpers/asset"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

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

var _ = Describe("Process DexServer CR", func() {
	DexServerName := "my-dexserver"
	DexServerNamespace := "my-dexserver-ns"
	AuthRealmName := "my-authrealm"
	AuthRealmNameSpace := "my-authrealm-ns"
	MyGithubAppClientID := "my-github-app-client-id"
	MyGithubAppClientSecretName := AuthRealmName + "github"
	DexServerIssuer := "https://testroutesubdomain.testhost.com"
	MyLDAPHost := "testldaphost:636"
	MyLDAPBindDN := "fakebinddn"
	MyLDAPBaseDN := "fakebasedn"
	MyLDAPBindPW := "fakebindpw"
	MyLDAPPWSecretName := AuthRealmName + "my-ldap-pw"
	MyLDAPCertsSecretName := AuthRealmName + "my-ldap-certs"

	var dexServer *authv1alpha1.DexServer
	var configHashWithGitHub string
	const SERVICE_ACCOUNT_NAME = "dex-operator-dexsso"

	By("Creating a CR with a GitHub connector")
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
							Id:   "my-github",
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
				_, err := rDexServer.Reconcile(context.TODO(), req)
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
	It("should create a service account", func() {
		serviceAccount := &corev1.ServiceAccount{}
		err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: SERVICE_ACCOUNT_NAME, Namespace: DexServerNamespace}, serviceAccount)
		Expect(err).Should(BeNil())
		Expect(serviceAccount.Labels["app"]).To(Equal(DexServerName))
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
		err = rDexServer.syncIngress(updatedDexServer, ctx)
		Expect(err).Should(BeNil())
		err = k8sClient.Get(context.TODO(), client.ObjectKey{Name: DexServerName, Namespace: DexServerNamespace}, ingress)
		Expect(err).Should(BeNil())
		Expect(ingress).ShouldNot(BeNil())
		Expect(ingress.Spec.TLS[0].SecretName).To(Equal("customcert"))
	})
	It("should create ClusterRoleBinding", func() {
		crb := &rbacv1.ClusterRoleBinding{}
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
		configMapYamlString := dexConfigMap.Data["config.yaml"]
		// Parse yaml
		var configMapData map[string]interface{}
		err = yaml.Unmarshal([]byte(configMapYamlString), &configMapData)
		Expect(err).Should(BeNil())
		// Verify the ConfigMap for GitHub
		Expect(configMapData["issuer"]).To(Equal(DexServerIssuer))
		connectors := configMapData["connectors"].([]interface{})
		connector := connectors[0].(map[string]interface{})
		Expect(connector["Type"]).To(Equal("github"))
		connectorConfig := connector["Config"].(map[string]interface{})
		Expect(connectorConfig["ClientID"]).To(Equal(MyGithubAppClientID))
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
			configHashWithGitHub = fmt.Sprintf("%x", h.Sum(nil))
			Expect(dsDeployment.Spec.Template.ObjectMeta.Annotations["auth.identitatem.io/configHash"]).To(Equal(configHashWithGitHub))
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
	It("should process an updated DexServer CR with LDAP", func() {
		dexServer := &authv1alpha1.DexServer{}
		By("retrieving the DexServer", func() {
			err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: DexServerName, Namespace: DexServerNamespace}, dexServer)
			Expect(err).Should(BeNil())
		})
		By("creating a secret containing the bind password secret for LDAP", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      MyLDAPPWSecretName,
					Namespace: AuthRealmNameSpace,
				},
				StringData: map[string]string{
					"bindPW": MyLDAPBindPW,
				},
			}
			err := k8sClient.Create(context.TODO(), secret)
			Expect(err).To(BeNil())
		})
		By("creating a secret containing the root CA secret for LDAP", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      MyLDAPCertsSecretName,
					Namespace: AuthRealmNameSpace,
				},
				Data: map[string][]byte{
					"tls.crt": []byte("tls.mycrt"),
					"tls.key": []byte("tls.mykey"),
					"ca.crt":  []byte("ca.crt"),
				},
			}
			err := k8sClient.Create(context.TODO(), secret)
			Expect(err).To(BeNil())
		})
		By("adding an LDAP connector to the DexServer", func() {
			dexServerConnectors := []authv1alpha1.ConnectorSpec{
				{
					Name: "my-github",
					Id:   "my-github",
					Type: "github",
					GitHub: authv1alpha1.GitHubConfigSpec{
						ClientID: MyGithubAppClientID,
						ClientSecretRef: corev1.SecretReference{
							Name:      MyGithubAppClientSecretName,
							Namespace: AuthRealmNameSpace,
						},
					},
				},
				{
					Name: "my-ldap",
					Id:   "my-ldap",
					Type: "ldap",
					LDAP: authv1alpha1.LDAPConfigSpec{
						Host:          MyLDAPHost,
						InsecureNoSSL: false,
						BindDN:        MyLDAPBindDN,
						RootCARef: corev1.SecretReference{
							Name:      MyLDAPCertsSecretName,
							Namespace: AuthRealmNameSpace,
						},
						BindPWRef: corev1.SecretReference{
							Name:      MyLDAPPWSecretName,
							Namespace: AuthRealmNameSpace,
						},
						UsernamePrompt: "Email Address",
						UserSearch: authv1alpha1.UserSearchSpec{
							BaseDN:    MyLDAPBaseDN,
							Filter:    "(objectClass=person)",
							Username:  "userPrincipalName",
							IDAttr:    "DN",
							EmailAttr: "userPrincipalName",
							NameAttr:  "cn",
						},
					},
				},
			}
			dexServer.Spec.Connectors = dexServerConnectors

			ctx := context.Background()
			err := k8sClient.Update(ctx, dexServer)
			Expect(err).To(BeNil())

			updatedDexServer := &authv1alpha1.DexServer{}

			// Retry getting this newly updated dexserver
			Eventually(func() bool {
				err := k8sClient.Get(ctx, client.ObjectKey{Name: DexServerName, Namespace: DexServerNamespace}, updatedDexServer)
				return err == nil && len(updatedDexServer.Spec.Connectors) == 2
			}, 10, 1).Should(BeTrue())

			By("running reconcile", func() {
				Eventually(func() bool {
					req := ctrl.Request{}
					req.Name = DexServerName
					req.Namespace = DexServerNamespace
					_, err := rDexServer.Reconcile(context.TODO(), req)
					return err == nil
				}, 10, 1).Should(BeTrue())
			})
		})
		By("Checking that the configMap is updated with the LDAP connector", func() {
			dexConfigMap := &corev1.ConfigMap{}
			err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: DexServerName, Namespace: DexServerNamespace}, dexConfigMap)
			Expect(err).Should(BeNil())
			Expect(dexConfigMap.Data["config.yaml"]).ShouldNot(BeNil())
			configMapYamlString := dexConfigMap.Data["config.yaml"]
			// Parse yaml
			var configMapData map[string]interface{}
			err = yaml.Unmarshal([]byte(configMapYamlString), &configMapData)
			Expect(err).Should(BeNil())
			// Verify the ConfigMap for LDAP
			connectors := configMapData["connectors"].([]interface{})
			Expect(len(connectors)).To(Equal(2)) // 2 connectors: Github, LDAP
			connector := connectors[1].(map[string]interface{})
			Expect(connector["Type"]).To(Equal("ldap"))
			connectorConfig := connector["Config"].(map[string]interface{})
			Expect(connectorConfig["BindDN"]).To(Equal(MyLDAPBindDN))
			Expect(connectorConfig["rootCA"]).To(Equal("/etc/dex/ldapcerts/my-ldap/ca.crt"))
		})
		By("Checking that the configHash in the deployment is updated", func() {
			dsDeployment := &appsv1.Deployment{}
			err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: DexServerName, Namespace: DexServerNamespace}, dsDeployment)
			Expect(err).Should(BeNil())
			Expect(dsDeployment.Spec.Template.ObjectMeta.Annotations["auth.identitatem.io/configHash"]).ToNot(Equal(configHashWithGitHub))
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
