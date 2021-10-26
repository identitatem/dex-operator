#!/bin/bash
# Copyright Red Hat


export NAME=${NAME:-"dex2"}
export NS=${NS:-"idp-mgmt-dex"}
export DEXSERVER_NS=${DEXSERVER_NS:-"idp-mgmt-my-route"}
export SECRET_NS=${SECRET_NS:-"itdove-mc-1"}

export SECRET_SERVER_NS=${SECRET_SERVER_NS:-"my-authrealm"}
export APPS=$(oc get infrastructure cluster -ojsonpath='{.status.apiServerURL}' | cut -d':' -f2 | sed 's/\/\/api/apps/g')
export OAUTH_CLIENT_SECRET_NAME=cluster1-clientsecret

export DEXSERVER_CLIENT_NAME=${NAME}
export DEXSERVER_CLIENT_SECRET_NAME=${NAME}-dexserver-client-secret
export DEXSERVER_CLIENT_ID=${DEXSERVER_CLIENT_ID:-"dexserverclientid"}
export DEXSERVER_CLIENT_SECRET=${DEXSERVER_CLIENT_SECRET:-"abcdefghijklmnopqrstuvwxyz1234567890"}

export DEXCLIENT_NAME=dexclient-cluster2
export DEXCLIENT_SECRET_NAME=dexclient-client-secret
export DEXCLIENT_ID=dexclientcluster2clientid
export DEXCLIENT_SECRET=abcdefghijklmnopqrstuvwxyz1234567890


cat > demo-all-idp.yaml <<EOF
---
apiVersion: v1
kind: Secret
metadata:
  name: ${DEXSERVER_CLIENT_SECRET_NAME}
  namespace: ${SECRET_SERVER_NS}
type: Opaque
stringData:
  clientSecret: ${DEXSERVER_CLIENT_SECRET}
---
apiVersion: auth.identitatem.io/v1alpha1
kind: DexServer
metadata:
  name: ${NAME}
  namespace: ${DEXSERVER_NS}
spec:
  issuer: https://${NAME}-${DEXSERVER_NS}.${APPS}
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
      clientID: "${DEXSERVER_CLIENT_ID}"
      clientSecretRef:
        name: ${DEXSERVER_CLIENT_SECRET_NAME}
        namespace: ${SECRET_SERVER_NS}
      redirectURI: "https://${NAME}-${DEXSERVER_NS}.${APPS}/callback"
---
apiVersion: v1
stringData:
  clientSecret: ${DEXCLIENT_SECRET}
kind: Secret
metadata:
  creationTimestamp: null
  name: ${DEXCLIENT_SECRET_NAME}
  namespace: ${SECRET_NS}
---
apiVersion: auth.identitatem.io/v1alpha1
kind: DexClient
metadata:
  name: ${DEXCLIENT_NAME}
  namespace: ${DEXSERVER_NS}
spec:
  clientID: ${DEXCLIENT_ID}
  clientSecretRef:
    name: ${DEXCLIENT_SECRET_NAME}
    namespace: ${SECRET_NS}
  redirectURIs:
  - "https://oauth-openshift.${APPS}/oauth2callback/${DEXCLIENT_NAME}"
  public: false
EOF
