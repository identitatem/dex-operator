# dex-operator

This is a operator-sdk based operator to deploy and manage a Dex server instance.

# Usage

## Option 1: Building your own image and bundle

### Requirements

* You will need operator-sdk 1.9.0+
* OpenShift cluster
* Github OAuth Application, for now, we will use github as id provider
* To narrow the scope, you will want the OCP cluster where you run dex to be using signed certificates, as opposed to the default self-signed certificates. If we use self-signed certificates, of course, we have to distribute the CA to each cluster that try to access the dex service. Of cource, this should be supported in the final cut. You can follow the steps defined here to enable LetsEncrypt certificates: https://github.com/open-cluster-management/sre-tools/wiki/ACM---Day-1#add-an-acme-certificate

### Steps

1. build and deploy the operator/controller

    ```bash
    git clone https://github.com/identitatem/dex-operator.git
    cd dex-operator
    oc new-project dex-operator

    # HACK - for now, manually create the clusterrole/binding to give dex access to dex resources
    oc apply -f hack/community/rbac-dex-operator-dexsso-community.yaml

    # Set the path to your quay repo.
    export IMAGE_TAG_BASE=quay.io/cdoan/dex-operator
    # OPTIONAL: arbitrarly change the version number of the image and bundle.
    export VERSION=0.0.5

    # build all the components
    make bits

    # deploy the operator from the bundle image (creates a catalog source). We can deploy the controller directly, but I started using the bundle and got used to it.
    make sdk-run
    ```

2. verify the pods are running

    ```bash
    oc get pods
    # At this point you should see this in the current namespace.
    NAME                                                              READY   STATUS      RESTARTS   AGE
    da3e6fd7599777c30bcf01817583a0dd66a5d8a2c09b7a802ea083b878lnf7x   0/1     Completed   0          25s
    dex-operator-controller-manager-57b7464cb6-hr5d9                  2/2     Running     0          16s
    quay-io-cdoan-dex-operator-bundle-v0-0-5                          1/1     Running     0          35s
    ```

3. if you have not done so already, generate or collect the github oauth information and set the appropriate environment variables. An example of a github app will have these values:

    | key | value |
    |-----|-------|
    | Application name: | any-string |
    | Homepage URL: | https://dex2-dex-operator.apps.pool-sno8x32sp2-w4qpg.demo.red-chesterfield.com |
    | Authorization callback URL: | https://dex2-dex-operator.apps.pool-sno8x32sp2-w4qpg.demo.red-chesterfield.com/callback |

    Where the URL references the location of the dex **Service**.

    ```bash
    export GITHUB_APP_CLIENTID=xxx
    export GITHUB_APP_CLIENTSECRET=xxx
    export CLIENT_NAME=some-string
    export CLIENT_SECRET=some-secret-string
    ```

4. generate the manifests

    ```bash
    cd hack
    ./generate-cr.sh
    cd ..
    ```

5. create a dex server instance

    ```bash
    oc apply -f hack/demo-dexserver-dex2-dex-operator.yaml
    ```

6. verify the dex server is accessible

   ```bash
   make curl
   ```

7. create a dex client

    ```bash
    oc apply -f hack/demo-dexclient-hub.yaml
    ```

8. verify the dex client record is created in dex
   ```bash
   oc get oauth2clients -A
   ```

9. apply the OAUTH changes

    ```bash
    oc apply -f hack/demo-oauth.yaml
    ```

## Option 2: Using a deployment manifest

```bash
oc new-project dex-operator
oc apply -f bundle/manifests/auth.identitatem.io_dexclients.yaml
oc apply -f bundle/manifests/auth.identitatem.io_dexservers.yaml
oc apply -f hack/deployment.yaml
```

# References

See Reference: https://hackmd.io/@0HKGaOf5Rg-SU-pJybkgKw/B1GhGowAO
