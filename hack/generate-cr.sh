#!/bin/bash

export NAME=${NAME:-"dex2"}
export NS=${NS:-"dex-operator"}
export APPS=$(oc get infrastructure cluster -ojsonpath='{.status.apiServerURL}' | cut -d':' -f2 | sed 's/\/\/api/apps/g')
export GITHUB_APP_CLIENTID=${GITHUB_APP_CLIENTID:-"githubappclientid"}
export GITHUB_APP_CLIENTSECRET=${GITHUB_APP_CLIENTSECRET:-"githubappclientsecret"}
export CLIENT_NAME=${CLIENT_NAME:-"thing"}
export CLIENT_SECRET=${CLIENT_SECRET:-"thing123456"}
export CLIENT_SECRET_NAME=cluster1-clientsecret

cat > demo-dexserver-${NAME}-${NS}.yaml <<EOF
---
apiVersion: v1
kind: Secret
metadata:
  name: ${NAME}-client-secret
type: Opaque
stringData:
  clientSecret: ${GITHUB_APP_CLIENTSECRET}
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
    config:
      clientID: "${GITHUB_APP_CLIENTID}"
      clientSecretRef:
        name: ${NAME}-client-secret
      redirectURI: "https://${NAME}-${NS}.${APPS}/callback"
EOF

cat > demo-dexclient-hub.yaml <<EOF
apiVersion: auth.identitatem.io/v1alpha1
kind: DexClient
metadata:
  name: ${CLIENT_NAME}
spec:
  clientID: ${CLIENT_NAME}
  clientSecret: ${CLIENT_SECRET}
  redirectURIs:
  - "https://oauth-openshift.${APPS}/oauth2callback/${CLIENT_NAME}"
  public: false
EOF

oc create secret generic ${CLIENT_SECRET_NAME} \
--from-literal=clientSecret=${CLIENT_SECRET} \
-n openshift-config --dry-run -o yaml > demo-${CLIENT_SECRET_NAME}.yaml

cat > demo-oauth.yaml <<EOF
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
      name: ${CLIENT_NAME}
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
        clientID: ${CLIENT_NAME}
        clientSecret:
          name: cluster1-clientsecret
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

