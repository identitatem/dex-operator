// Copyright Red Hat

package controllers

import (
	"context"
	"time"

	api "github.com/dexidp/dex/api/v2"
	authv1alpha1 "github.com/identitatem/dex-operator/api/v1alpha1"
	dexapi "github.com/identitatem/dex-operator/controllers/dex"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

/* Mock api.DexClient:
This is so that we can override the implementation of CreateClient, UpdateClient and DeleteClient.
Note: All the interface methods of api.DexClient need to be implemented by the mock so that we can use this mock
to generate the api client that will be returned to the dex client controller.
*/
type MockDexAPIClient struct{}

func (m *MockDexAPIClient) CreateClient(ctx context.Context, in *api.CreateClientReq, opts ...grpc.CallOption) (*api.CreateClientResp, error) {
	client := &api.Client{
		Id: "dex-client-id1",
	}
	return &api.CreateClientResp{
		Client: client,
	}, nil
}
func (m *MockDexAPIClient) UpdateClient(ctx context.Context, in *api.UpdateClientReq, opts ...grpc.CallOption) (*api.UpdateClientResp, error) {
	return &api.UpdateClientResp{}, nil
}
func (m *MockDexAPIClient) DeleteClient(ctx context.Context, in *api.DeleteClientReq, opts ...grpc.CallOption) (*api.DeleteClientResp, error) {
	return &api.DeleteClientResp{}, nil
}
func (m *MockDexAPIClient) CreatePassword(ctx context.Context, in *api.CreatePasswordReq, opts ...grpc.CallOption) (*api.CreatePasswordResp, error) {
	return nil, nil
}
func (m *MockDexAPIClient) UpdatePassword(ctx context.Context, in *api.UpdatePasswordReq, opts ...grpc.CallOption) (*api.UpdatePasswordResp, error) {
	return nil, nil
}
func (m *MockDexAPIClient) DeletePassword(ctx context.Context, in *api.DeletePasswordReq, opts ...grpc.CallOption) (*api.DeletePasswordResp, error) {
	return nil, nil
}
func (m *MockDexAPIClient) ListPasswords(ctx context.Context, in *api.ListPasswordReq, opts ...grpc.CallOption) (*api.ListPasswordResp, error) {
	return nil, nil
}
func (m *MockDexAPIClient) GetVersion(ctx context.Context, in *api.VersionReq, opts ...grpc.CallOption) (*api.VersionResp, error) {
	return nil, nil
}
func (m *MockDexAPIClient) ListRefresh(ctx context.Context, in *api.ListRefreshReq, opts ...grpc.CallOption) (*api.ListRefreshResp, error) {
	return nil, nil
}
func (m *MockDexAPIClient) RevokeRefresh(ctx context.Context, in *api.RevokeRefreshReq, opts ...grpc.CallOption) (*api.RevokeRefreshResp, error) {
	return nil, nil
}
func (m *MockDexAPIClient) VerifyPassword(ctx context.Context, in *api.VerifyPasswordReq, opts ...grpc.CallOption) (*api.VerifyPasswordResp, error) {
	return nil, nil
}
func (m *MockDexAPIClient) CloseConnection() error {
	return nil
}

var _ = Describe("Process DexClient CR", func() {
	MyDexClientName := "dex-client-cluster1"
	MyDexClientNamespace := "dex-client-cluster1-ns"
	MyDexClientID := "dex-client-id1"
	MyUpdatedDexClientID := "dex-client"
	MyDexClientSecretName := "dex-client-secret1-name"
	MyDexClientSecret := "dex-client-secret1"
	MyDexClientSecretNamespace := "dex-client-secret1-ns"
	MyRedirectURI := "https://oauth-openshift.testroutesubdomain1.testhost.com/oauth2callback/dex-client-id1"
	const SECRET_MTLS_NAME = "grpc-mtls"
	var dexClient *authv1alpha1.DexClient

	It("should create a DexClient", func() {
		By("creating a test namespace for the DexClient", func() {
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: MyDexClientNamespace,
				},
			}
			err := k8sClient.Create(context.TODO(), ns)
			Expect(err).To(BeNil())
		})
		By("creating a test namespace for the DexClient client secret", func() {
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: MyDexClientSecretNamespace,
				},
			}
			err := k8sClient.Create(context.TODO(), ns)
			Expect(err).To(BeNil())
		})
		By("creating a secret containing the dexclient's client secret", func() {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      MyDexClientSecretName,
					Namespace: MyDexClientSecretNamespace,
				},
				StringData: map[string]string{
					"clientSecret": MyDexClientSecret,
				},
			}
			err := k8sClient.Create(context.TODO(), secret)
			Expect(err).To(BeNil())
		})
		By("creating the DexClient CR", func() {
			// A DexClient object with metadata and spec.
			dexClient = &authv1alpha1.DexClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      MyDexClientName,
					Namespace: MyDexClientNamespace,
				},
				Spec: authv1alpha1.DexClientSpec{
					ClientID: MyDexClientID,
					ClientSecretRef: corev1.SecretReference{
						Name:      MyDexClientSecretName,
						Namespace: MyDexClientSecretNamespace,
					},
					RedirectURIs: []string{MyRedirectURI},
				},
			}
			ctx := context.Background()
			err := k8sClient.Create(ctx, dexClient)
			Expect(err).To(BeNil())

			createdDexClient := &authv1alpha1.DexClient{}

			// Retry getting this newly created dexclient, given that creation may not immediately happen.
			Eventually(func() bool {
				err := k8sClient.Get(ctx, client.ObjectKey{Name: MyDexClientName, Namespace: MyDexClientNamespace}, createdDexClient)
				return err == nil
			}, 10, 1).Should(BeTrue())
		})
		By("running dex client reconcile", func() {
			Eventually(func() bool {
				req := ctrl.Request{}
				req.Name = MyDexClientName
				req.Namespace = MyDexClientNamespace
				_, err := rDexClient.Reconcile(context.TODO(), req)
				return err == nil
			}, 10, 1).Should(BeTrue())
		})
	})
	It("should update status condition in the DexClient if MTLS secret is not found", func() {
		err := k8sClient.Get(ctx, client.ObjectKey{Name: MyDexClientName, Namespace: MyDexClientNamespace}, dexClient)
		Expect(err).To(BeNil())
		Expect(len(dexClient.Status.Conditions)).Should(BeNumerically(">", 0))
		Expect(dexClient.Status.Conditions[0].Reason).To(Equal("MTLSSecretNotFound"))
	})
	It("should update status condition with GRPCConnectionFailed since dex server is not running", func() {
		By("creating an MTLS secret", func() {
			now := time.Now()
			certDuration := time.Hour * 24
			expiry := now.Add(certDuration)
			labels := map[string]string{
				"app": "dex-server-name",
			}
			annotations := map[string]string{
				"auth.identitatem.io/expiry": expiry.UTC().Format(time.RFC3339),
			}
			secretSpec := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        SECRET_MTLS_NAME,
					Namespace:   MyDexClientNamespace,
					Labels:      labels,
					Annotations: annotations,
				},
				Data: map[string][]byte{
					"ca.crt":     []byte("ca.crt"),
					"ca.key":     []byte("ca.key"),
					"tls.crt":    []byte("tls.crt"),
					"tls.key":    []byte("tls.key"),
					"client.crt": []byte("client.crt"),
					"client.key": []byte("client.key"),
				},
			}
			err := k8sClient.Create(context.TODO(), secretSpec)
			Expect(err).To(BeNil())
		})
		By("running reconcile", func() {
			Eventually(func() bool {
				req := ctrl.Request{}
				req.Name = MyDexClientName
				req.Namespace = MyDexClientNamespace
				_, err := rDexClient.Reconcile(context.TODO(), req)
				return err != nil // Reconcile will have an error
			}, 10, 5).Should(BeTrue())
		})
		err := k8sClient.Get(ctx, client.ObjectKey{Name: MyDexClientName, Namespace: MyDexClientNamespace}, dexClient)
		Expect(err).To(BeNil())
		Expect(len(dexClient.Status.Conditions)).Should(BeNumerically(">", 0))
		Expect(dexClient.Status.Conditions[0].Reason).To(Equal("GRPCConnectionFailed"))
	})
	It("should apply CR (status condition: Created) if dex api and grpc are mocked", func() {
		By("mocking the dex api client and grpc connection", func() {
			DexapiNewClientPEM = func(opts *dexapi.Options) (*dexapi.APIClient, error) {
				// Mock dex API client
				dexApiClient := new(MockDexAPIClient)
				// Mock GRPC connection
				conn, err := grpc.Dial("localhost:3000", grpc.WithInsecure())
				Expect(err).To(BeNil())
				return &dexapi.APIClient{
					Dex: dexApiClient,
					Cc:  conn,
				}, nil
			}
		})
		By("running reconcile", func() {
			Eventually(func() bool {
				req := ctrl.Request{}
				req.Name = MyDexClientName
				req.Namespace = MyDexClientNamespace
				_, err := rDexClient.Reconcile(context.TODO(), req)
				Expect(err).To(BeNil())
				err = k8sClient.Get(ctx, client.ObjectKey{Name: MyDexClientName, Namespace: MyDexClientNamespace}, dexClient)
				Expect(err).To(BeNil())
				Expect(len(dexClient.Status.Conditions)).Should(BeNumerically(">", 0))
				return dexClient.Status.Conditions[0].Reason == "Created"
			}, 30, 1).Should(BeTrue())
		})
	})
	It("should update the dex client", func() {
		dexClient := &authv1alpha1.DexClient{}
		By("retrieving the DexClient", func() {
			err := k8sClient.Get(ctx, client.ObjectKey{Name: MyDexClientName, Namespace: MyDexClientNamespace}, dexClient)
			Expect(err).Should(BeNil())
		})
		By("updating the DexClient", func() {
			dexClient.Spec.ClientID = MyUpdatedDexClientID
			ctx := context.Background()
			err := k8sClient.Update(ctx, dexClient)
			Expect(err).To(BeNil())
			// Retry getting this newly updated dexclient
			updatedDexClient := &authv1alpha1.DexClient{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, client.ObjectKey{Name: MyDexClientName, Namespace: MyDexClientNamespace}, updatedDexClient)
				return err == nil && updatedDexClient.Spec.ClientID == MyUpdatedDexClientID
			}, 10, 1).Should(BeTrue())
		})
		By("running reconcile", func() {
			Eventually(func() bool {
				req := ctrl.Request{}
				req.Name = MyDexClientName
				req.Namespace = MyDexClientNamespace
				_, err := rDexClient.Reconcile(context.TODO(), req)
				Expect(err).To(BeNil())
				err = k8sClient.Get(ctx, client.ObjectKey{Name: MyDexClientName, Namespace: MyDexClientNamespace}, dexClient)
				Expect(err).To(BeNil())
				return dexClient.Status.Conditions[0].Reason == "Updated"
			}, 30, 1).Should(BeTrue())
		})
		By("Revert NewClientPEM", func() {
			DexapiNewClientPEM = dexapi.NewClientPEM
		})
	})
})
