#!/bin/bash

export NAME=${NAME:-"dex2"}
export NS=${NS:-"dex-operator"}
export SECRET_NS=${SECRET_NS:-"dex-operator"}

export APPS=$(oc get infrastructure cluster -ojsonpath='{.status.apiServerURL}' | cut -d':' -f2 | sed 's/\/\/api/apps/g')
export OAUTH_CLIENT_SECRET_NAME=cluster1-clientsecret

export DEXSERVER_CLIENT_NAME=${NAME}
export DEXSERVER_GH_CLIENT_SECRET_NAME=${NAME}-dexserver-client-secret
export DEXSERVER_GH_CLIENT_ID=${DEXSERVER_GH_CLIENT_ID:-"dexserverclientid"}
export DEXSERVER_GH_CLIENT_SECRET=${DEXSERVER_GH_CLIENT_SECRET:-"dexserversecret123456"}

export DEXCLIENT_NAME=dexclient-cluster2
export DEXCLIENT_SECRET_NAME=dexclient-client-secret
export DEXCLIENT_ID=dexclientcluster2clientid
export DEXCLIENT_SECRET=dexclientsecret123456

export DEXSERVER_LDAP_HOST=${DEXSERVER_LDAP_HOST:-"adf558f301d884463a9d44329fbafc4c-145647244.us-east-1.elb.amazonaws.com:636"}
export DEXSERVER_LDAP_SECRET_NAME=${DEXSERVER_LDAP_SECRET_NAME:-"ldap-bindpw"}
export DEXSERVER_LDAP_SECRET=${DEXSERVER_LDAP_SECRET:-"admin"}
export DEXSERVER_LDAP_BIND_DN=${DEXSERVER_LDAP_BIND_DN:-"cn=Manager,dc=example,dc=com"}
export DEXSERVER_LDAP_USERSEARCH_BASEDN=${DEXSERVER_LDAP_USERSEARCH_BASEDN:-"dc=example,dc=com"}

cat > demo-dexserver-${NAME}-${NS}.yaml <<EOF
---
apiVersion: v1
kind: Secret
metadata:
  name: ${DEXSERVER_GH_CLIENT_SECRET_NAME}
  namespace: ${SECRET_NS}
type: Opaque
stringData:
  clientSecret: ${DEXSERVER_GH_CLIENT_SECRET}
---
apiVersion: v1
kind: Secret
metadata:
  name: ${DEXSERVER_LDAP_SECRET_NAME}
  namespace: ${SECRET_NS}
type: Opaque
stringData:
  bindPW: ${DEXSERVER_LDAP_SECRET}
---
apiVersion: auth.identitatem.io/v1alpha1
kind: DexServer
metadata:
  name: ${NAME}
spec:
  issuer: https://${NAME}-${NS}.${APPS}
  enablePasswordDB: false
  storage:
    type: kubernetes
    config:
      inCluster: true
  web:
    http: 0.0.0.0:5556
    tlsCert: secretRef
    tlsKey: secretRef
  grpc:
    addr: 0.0.0.0:5557
    tlsCert: secretRef
    tlsKey: secretRef
    tlsClientCA: secretRef
  expiry:
    deviceRequests: "5m"
    signingKeys: "6h"
    idTokens: "24h"
    refreshTokens:
      reuseInterval: "3s"
      validIfNotUsedFor: "2160h"
      absoluteLifetime: "3960h"
  logger:
    level: "1"
    format: "json"
  oauth2:
    responseTypes:
    - "code"
    - "token"
    skipApprovalScreen: false
    alwasyShowLoginScreen: false
    passwordConnector: "local"
  connectors:
  - type: github
    id: github
    name: github
    github:
      clientID: "${DEXSERVER_GH_CLIENT_ID}"
      clientSecretRef:
        name: ${DEXSERVER_GH_CLIENT_SECRET_NAME}
        namespace: ${NS}
      redirectURI: "https://${NAME}-${NS}.${APPS}/callback"
  - type: ldap
    id: ldap
    name: OpenLDAP
    ldap:
      host: ${DEXSERVER_LDAP_HOST}
      insecureNoSSL: false
      insecureSkipVerify: true
      bindDN: ${DEXSERVER_LDAP_BIND_DN}
      bindPWRef:
        name: ${DEXSERVER_LDAP_SECRET_NAME}
        namespace: ${NS}
      usernamePrompt: Email Address
      userSearch:
        baseDN: ${DEXSERVER_LDAP_USERSEARCH_BASEDN}
        filter: "(objectClass=person)"
        username: mail
        idAttr: DN
        emailAttr: mail
        nameAttr: cn      
EOF

# DEX CLIENT

oc create secret generic ${DEXCLIENT_SECRET_NAME} \
--from-literal=clientSecret=${DEXCLIENT_SECRET} \
-n ${SECRET_NS} --dry-run -o yaml > demo-dexclient-${DEXCLIENT_NAME}.yaml

cat >> demo-dexclient-${DEXCLIENT_NAME}.yaml <<EOF
---
apiVersion: auth.identitatem.io/v1alpha1
kind: DexClient
metadata:
  name: ${DEXCLIENT_NAME}
spec:
  clientID: ${DEXCLIENT_ID}
  clientSecretRef:
    name: ${DEXCLIENT_SECRET_NAME}
    namespace: ${SECRET_NS}
  redirectURIs:
  - "https://oauth-openshift.${APPS}/oauth2callback/${DEXCLIENT_NAME}"
  public: false
EOF

# OAUTH MANIFESTS

oc create secret generic ${OAUTH_CLIENT_SECRET_NAME} \
--from-literal=clientSecret=${DEXCLIENT_SECRET} \
-n openshift-config --dry-run -o yaml > demo-oauth.yaml

cat >> demo-oauth.yaml <<EOF
---
apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  annotations:
    include.release.openshift.io/ibm-cloud-managed: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
    include.release.openshift.io/single-node-developer: "true"
    release.openshift.io/create-only: "true"
  name: cluster
spec:
  identityProviders:
    - mappingMethod: claim
      name: ${DEXCLIENT_NAME}
      openID:
        claims:
          email:
            - email
          name:
            - name
          preferredUsername:
            - preferred_username
            - email
            - name
        clientID: ${DEXCLIENT_ID}
        clientSecret:
          name: ${OAUTH_CLIENT_SECRET_NAME}
        extraAuthorizeParameters:
          include_granted_scopes: 'true'
        extraScopes:
          - email
          - profile
          - groups
          - 'federated:id'
          - offline_access
        issuer: >-
          https://${NAME}-${NS}.${APPS}
      type: OpenID
EOF

