# dex-operator

This is a operator-sdk based operator to deploy Dex. The development is focused on OpenShift, but hopefully, this can be a generic operator that runs just as fine on Kubernetes.

# Usage

You'll need operator-sdk 1.9.0+.

```
git clone https://github.com/identitatem/dex-operator.git
oc new-project dex-operator
```

# To use prebuilt image. Otherwise, you can reset these variables and build your own.
export IMAGE_TAG_BASE=quay.io/cdoan/dex-operator
export VERSION=0.0.1

# this will deploy the operator bundle as a catalog source and deploy the operator from there.
make sdk-run

cd hack/gitops-community
./start.sh

# add dex roles/bindings to the service account
oc apply -f rbac-dex-operator-dexsso-community.yaml

# edit the DexConfig to reference your domain, eventually this will be in the operator, then apply
oc apply -f config/sample/dexconfig-community.yaml
```

# References

See Reference: https://hackmd.io/@0HKGaOf5Rg-SU-pJybkgKw/B1GhGowAO
