[comment]: # ( Copyright Red Hat )
# dex-operator

This is a operator-sdk based operator to deploy and manage a Dex server instance.

![component diagram](/docs/img/dex-component-diagram.png)

# Usage

## Option 1: Building your own image and bundle

### Requirements

- You will need operator-sdk 1.9.0+
- OpenShift cluster
- Github OAuth Application, for now, we will use github as id provider
- To narrow the scope, you will want the OCP cluster where you run dex to be using signed certificates, as opposed to the default self-signed certificates. If we use self-signed certificates, of course, we have to distribute the CA to each cluster that try to access the dex service. Of cource, this should be supported in the final cut. You can follow the steps defined here to enable LetsEncrypt certificates: https://github.com/open-cluster-management/sre-tools/wiki/ACM---Day-1#add-an-acme-certificate

### Steps

1. build and deploy the operator/controller

   ```bash
   git clone https://github.com/identitatem/dex-operator.git
   cd dex-operator
   oc new-project dex-operator

   # Set the path to your quay repo.
   export IMAGE_TAG_BASE=quay.io/cdoan/dex-operator
   # OPTIONAL: arbitrarly change the version number of the image and bundle.
   export VERSION=0.0.5
   # OPTIONAL: specify an alternate dex server image
   # export DEX_IMAGE=your.internal.registry.io/x/y:v0.0.0

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

3. Setup for IDP connectors:

   - **Github:**
     If you have not done so already, generate or collect the github oauth application information and set the appropriate environment variables. An example of a github app will have these values like this to reference the dex service :

     | key                         | example values format                                                                   |
     | --------------------------- | --------------------------------------------------------------------------------------- |
     | Application name:           | any-string                                                                              |
     | Homepage URL:               | https://dex2-dex-operator.apps.pool-sno8x32sp2-w4qpg.demo.red-chesterfield.com          |
     | Authorization callback URL: | https://dex2-dex-operator.apps.pool-sno8x32sp2-w4qpg.demo.red-chesterfield.com/callback |

     Where the URL references the location of the dex **Service**.

     ```bash
     # override your github application client id
     export DEXSERVER_GH_CLIENT_ID=...
     # override your github application client secret
     export DEXSERVER_GH_CLIENT_SECRET=...
     ```

   - **LDAP:**
     Follow the steps [here](https://medium.com/ibm-garage/how-to-host-and-deploy-an-openldap-sever-in-openshift-affab06a4365) to setup an OpenLDAP instance.
     Override the following environment variables:

     ```bash
     # LDAP Host
     export DEXSERVER_LDAP_HOST=...
     # LDAP Bind DN
     export DEXSERVER_LDAP_BIND_DN=...
     # LDAP Bind PW (The bindDN and bindPW are used as credentials to search for users and passwords)
     export DEXSERVER_LDAP_SECRET=...
     # Base DN to start the search from
     export DEXSERVER_LDAP_USERSEARCH_BASEDN=...
     ```

     Populate the LDAP server with some sample data. For example:

     ```
     ldapadd -H ldap://<ldap_server_url> -D "cn=Manager,dc=example,dc=com" -W << EOF
     heredoc> dn: cn=jane,dc=example,dc=com
     heredoc> objectClass: person
     heredoc> objectClass: inetOrgPerson
     heredoc> sn: doe
     heredoc> cn: jane
     heredoc> mail: janedoe@example.com
     heredoc> userpassword: foo
     heredoc> EOF
     Enter LDAP Password:
     adding new entry "cn=jane,dc=example,dc=com"
     ```

     You can make additional modifications as needed to the LDAP connector configuration in the DexServer manifest definition in `hack/generate_cr.sh`

   - **Microsoft OAuth2**
     Follow the steps [here](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) to register an application with the Microsoft Identity platform.
     Set the **Redirect URI** to the callback URL for the dex service. `https://<location of dex service>/callback`
     Note the Client ID and Client Secret for the registered application.
     Set the following evironment variables:

     ```bash
     # your microsoft application client id
     export DEXSERVER_MS_CLIENT_ID=...
     # your microsoft application client secret
     export DEXSERVER_MS_CLIENT_SECRET=...
     # your Azure AD tenant ID (the tenant in which this application was registered)
     export DEXSERVER_MS_TENANT=...
     ```

   - **LDAP using Azure Active Directory:**
     - Follow the steps [here](https://docs.google.com/document/d/1TC23Ok-CaXFm7AI0JatjEZbYUiycV_PeyHk9GRTylzA/edit?usp=sharing) to setup secure LDAP with Azure Active Directory.
     - Place the Root CA, Client Cert and Client key (ca.crt, tls.crt, tls.key) files in the hack/ldap-certs directory
     - Override the following environment variables:
     ```bash
     # AD DS Secure LDAP Host
     export DEXSERVER_LDAP_AD_HOST=...
     # LDAP Bind DN
     export DEXSERVER_LDAP_AD_BIND_DN=...
     # LDAP Bind PW (The bindDN and bindPW are used as credentials to search for users and passwords)
     export DEXSERVER_LDAP_AD_BP_SECRET=...
     # Base DN to start the search from
     export DEXSERVER_LDAP_AD_USERSEARCH_BASEDN=...
     ```
     You can make additional modifications as needed to the LDAP connector configuration in the DexServer manifest definition in `hack/generate_cr.sh`

4. generate the minimal set of manifests for github OAUTH application and LDAP authentication

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
   oc apply -f hack/demo-dexclient-dexclient-cluster2.yaml
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

## Option 3: Local development

```bash
oc new-project dex-operator
export RELATED_IMAGE_DEX=quay.io/dexidp/dex:v2.28.1
make run-local
```

The `run-local` make target will generate and install the Custom Resource Definitions, then run the controller locally.

Follow the "Setup for IDP connectors" steps above to generate and apply sample CRs to trigger your reconcile loops.

If you are testing with DexClients, some extra steps are necessary.

1. Add the following to your `/etc/hosts` file:

```bash
127.0.0.1 	grpc.dex-operator.svc.cluster.local
```

If you are using a namespace other than `dex-operator`, update the line above accordingly.

2. Once you've created a DexServer CR and the dex server pod is running, you'll need to do a port forward to allow the controller to make grpc calls to the dex server.

```bash
oc port-forward dex2-97d78b6d5-rg9d7 5557:5557
```

You'll replace the pod name above with your pod, retrieved via `oc get pods` in your namespace where the dex server is running.

If you want to test using the VSCode debugger, you will need a .vscode/launch.json file. Here is an example:

```bash
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch Dex operator",
            "type": "go",
            "request": "launch",
            "mode": "debug",
            "program": "${workspaceFolder}/main.go",
            "env": {
                "RELATED_IMAGE_DEX": "quay.io/dexidp/dex:v2.28.1"
            }
        }


    ]
}
```

# Run tests

`make test`


# References

See Reference: https://hackmd.io/@0HKGaOf5Rg-SU-pJybkgKw/B1GhGowAO
