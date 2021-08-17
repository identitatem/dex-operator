module github.com/identitatem/dex-operator

go 1.16

require (
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.2
	github.com/openshift/api v0.0.0-20210127195806-54e5e88cf848 //Openshift 4.6
	github.com/pkg/errors v0.9.1
	google.golang.org/grpc v1.40.0
	google.golang.org/protobuf v1.27.1
	k8s.io/api v0.20.2
	k8s.io/apimachinery v0.20.2
	k8s.io/client-go v0.20.2
	sigs.k8s.io/controller-runtime v0.8.3
)
