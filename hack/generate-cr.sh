#!/bin/bash
# Copyright Red Hat

export NAME=${NAME:-"dex2"}
export NS=${NS:-"dex-operator"}
export SECRET_NS=${SECRET_NS:-"dex-operator"}

export APPS=$(oc get infrastructure cluster -ojsonpath='{.status.apiServerURL}' | cut -d':' -f2 | sed 's/\/\/api/apps/g')
export OAUTH_CLIENT_SECRET_NAME=cluster1-clientsecret

export DEXSERVER_CLIENT_NAME=${NAME}
export DEXSERVER_GH_CLIENT_SECRET_NAME=${NAME}-dexserver-gh-client-secret
export DEXSERVER_GH_CLIENT_ID=${DEXSERVER_GH_CLIENT_ID:-"dexserverclientid"}
export DEXSERVER_GH_CLIENT_SECRET=${DEXSERVER_GH_CLIENT_SECRET:-"dexserversecret123456"}

export DEXSERVER_MS_CLIENT_SECRET_NAME=${NAME}-dexserver-ms-client-secret
export DEXSERVER_MS_CLIENT_ID=${DEXSERVER_MS_CLIENT_ID:-"dexservermsclientid"}
export DEXSERVER_MS_CLIENT_SECRET=${DEXSERVER_MS_CLIENT_SECRET:-"dexservermssecret123456"}
export DEXSERVER_MS_TENANT=${DEXSERVER_MS_TENANT:-"organizations"}

export DEXCLIENT_NAME=dexclient-cluster2
export DEXCLIENT_SECRET_NAME=dexclient-client-secret
export DEXCLIENT_ID=dexclientcluster2clientid
export DEXCLIENT_SECRET=dexclientsecret123456

export DEXSERVER_LDAP_HOST=${DEXSERVER_LDAP_HOST:-"ldaphost:636"}
export DEXSERVER_LDAP_SECRET_NAME=${DEXSERVER_LDAP_SECRET_NAME:-"ldap-bindpw"}
export DEXSERVER_LDAP_SECRET=${DEXSERVER_LDAP_SECRET:-"foo"}
export DEXSERVER_LDAP_BIND_DN=${DEXSERVER_LDAP_BIND_DN:-"cn=fake,dc=sample,dc=com"}
export DEXSERVER_LDAP_USERSEARCH_BASEDN=${DEXSERVER_LDAP_USERSEARCH_BASEDN:-"dc=sample,dc=com"}

export DEXSERVER_LDAP_AD_HOST=${DEXSERVER_LDAP_AD_HOST:-"adhost:636"}
export DEXSERVER_LDAP_AD_BP_SECRET_NAME=${DEXSERVER_LDAP_AD_BP_SECRET_NAME:-"ldap-ad-bind-pw"}
export DEXSERVER_LDAP_AD_BP_SECRET=${DEXSERVER_LDAP_AD_BP_SECRET:-"bind-pw-ad"}
export DEXSERVER_LDAP_AD_ROOTCA_SECRET_NAME=${DEXSERVER_LDAP_AD_ROOTCA_SECRET_NAME:-"ldap-ad-rootca"}
export DEXSERVER_LDAP_AD_BIND_DN=${DEXSERVER_LDAP_AD_BIND_DN:-"cn=fakecn,dc=fakedomain,dc=com"}
export DEXSERVER_LDAP_AD_USERSEARCH_BASEDN=${DEXSERVER_LDAP_AD_USERSEARCH_BASEDN:-"ou=fakeou,dc=fakedomain,dc=com"}

export DEXSERVER_OIDC_CLIENT_ID=${DEXSERVER_OPENID_CLIENT_ID:-"dexserverclientid"}
export DEXSERVER_OIDC_CLIENT_SECRET=${DEXSERVER_OPENID_CLIENT_SECRET:-"dexservermssecret123456"}
export DEXSERVER_OIDC_ISSUER=${DEXSERVER_OIDC_ISSUER}

# Secret containing root ca (ca.crt), and client cert and key (tls.crt, tls.key) to test LDAP on Azure AD with self-signed certificates
oc create secret generic ${DEXSERVER_LDAP_AD_ROOTCA_SECRET_NAME} \
--from-file=ca.crt=ldap-certs/ca.crt \
--from-file=tls.crt=ldap-certs/tls.crt \
--from-file=tls.key=ldap-certs/tls.key \
-n ${SECRET_NS} --dry-run -o yaml > demo-dexserver-${NAME}-${NS}.yaml

cat >> demo-dexserver-${NAME}-${NS}.yaml <<EOF
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
  name: ${DEXSERVER_MS_CLIENT_SECRET_NAME}
  namespace: ${SECRET_NS}
type: Opaque
stringData:
  clientSecret: ${DEXSERVER_MS_CLIENT_SECRET}
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
apiVersion: v1
kind: Secret
metadata:
  name: ${DEXSERVER_LDAP_AD_BP_SECRET_NAME}
  namespace: ${SECRET_NS}
type: Opaque
stringData:
  bindPW: ${DEXSERVER_LDAP_AD_BP_SECRET}
---
apiVersion: auth.identitatem.io/v1alpha1
kind: DexServer
metadata:
  name: ${NAME}
spec:
  issuer: https://${NAME}-${NS}.${APPS}
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
  - type: microsoft
    id: microsoft
    name: microsoft
    microsoft:
      clientID: "${DEXSERVER_MS_CLIENT_ID}"
      clientSecretRef:
        name: ${DEXSERVER_MS_CLIENT_SECRET_NAME}
        namespace: ${NS}
      redirectURI: "https://${NAME}-${NS}.${APPS}/callback"
      tenant: ${DEXSERVER_MS_TENANT}     
  - type: ldap
    id: ldap
    name: openldap
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
  - type: ldap
    id: ldap2
    name: activedirectory
    ldap:
      host: ${DEXSERVER_LDAP_AD_HOST}
      insecureNoSSL: false
      bindDN: ${DEXSERVER_LDAP_AD_BIND_DN}
      bindPWRef:
        name: ${DEXSERVER_LDAP_AD_BP_SECRET_NAME}
        namespace: ${NS}
      rootCARef:
        name: ${DEXSERVER_LDAP_AD_ROOTCA_SECRET_NAME}
        namespace: ${NS}                    
      usernamePrompt: Email Address
      userSearch:
        baseDN: ${DEXSERVER_LDAP_AD_USERSEARCH_BASEDN}
        filter: "(objectClass=person)"
        username: userPrincipalName
        idAttr: DN
        emailAttr: userPrincipalName
        nameAttr: cn
  - type: oidc
    id: oidc
    name: oidc
    oidc: 
      issuer: "${DEXSERVER_OIDC_ISSUER}"
      clientID: "${DEXSERVER_OIDC_CLIENT_ID}"
      clientSecretRef:
        name: ${DEXSERVER_OIDC_CLIENT_SECRET}
        namespace: ${NS}
      redirectURI: "https://${NAME}-${NS}.${APPS}/callback"

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

