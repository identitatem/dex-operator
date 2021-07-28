#!/bin/bash

if [ ! -d ssl ]; then
mkdir -p ssl
export BASE_DOMAIN=$(oc cluster-info | grep api | sed 's/.*api.//g' | cut -d':' -f1)
cat << EOF > ssl/req.cnf
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = dex-gitops
DNS.2 = dex-gitops-grpc
DNS.3 = dex-gitops.svc.cluster.local
DNS.4 = dex-gitops.apps.${BASE_DOMAIN}
EOF

openssl genrsa -out ssl/ca-key.pem 2048
openssl req -x509 -new -nodes -key ssl/ca-key.pem -days 10 -out ssl/ca.pem -subj "/CN=kube-ca"

openssl genrsa -out ssl/key.pem 2048
openssl req -new -key ssl/key.pem -out ssl/csr.pem -subj "/CN=kube-ca" -config ssl/req.cnf
openssl x509 -req -in ssl/csr.pem -CA ssl/ca.pem -CAkey ssl/ca-key.pem -CAcreateserial -out ssl/cert.pem -days 10 -extensions v3_req -extfile ssl/req.cnf
fi

cat <<EOF | oc apply -f -
apiVersion: v1
data:
  admin.password: JDJhJDEwJHMyR0FEZm5zWmxITTVLOU0wSzN5aWVaOUVibHFzYTFtS3BVUE9NMnJCOVhNdlNLeno4aVNl
  admin.passwordMtime: MjAyMS0wNy0xNFQyMDoxMzo0OFo=
  server.secretkey: ejJtMDFiOVdwNE5vbEhTdE1HVWk=
  tls.crt: $(cat ssl/cert.pem | base64)
  tls.key: $(cat ssl/key.pem | base64)
kind: Secret
metadata:
  labels:
    app.kubernetes.io/managed-by: openshift-gitops
    app.kubernetes.io/name: argocd-secret
    app.kubernetes.io/part-of: argocd
  name: argocd-secret
type: Opaque
EOF

cat <<EOF | oc apply -f -
apiVersion: v1
data:
  admin.enabled: "true"
  application.instanceLabelKey: ""
  configManagementPlugins: ""
  dex.config: |
    connectors:
    - config:
        clientID: system:serviceaccount:dex-gitops:gitops-argocd-dex-server
        clientSecret: eyJhbGciOiJSUzI1NiIsImtpZCI6ImgzdXNfT1JLZE9tUlE3cXFHUzV4RmxoODJHWEVJVlFfeHJsa0xpa0k2U2MifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJvcGVuc2hpZnQtZ2l0b3BzIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6Im9wZW5zaGlmdC1naXRvcHMtYXJnb2NkLWRleC1zZXJ2ZXItdG9rZW4tN245azUiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoib3BlbnNoaWZ0LWdpdG9wcy1hcmdvY2QtZGV4LXNlcnZlciIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6Ijc4Zjg5ZTYwLWQ4YmMtNGUyYS1iNWFjLWRhYTBjOWNmMmFjYiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpvcGVuc2hpZnQtZ2l0b3BzOm9wZW5zaGlmdC1naXRvcHMtYXJnb2NkLWRleC1zZXJ2ZXIifQ.n94sLiToDOIlnLEqiQ8Mc8EPG8_tVP2hNoM0A9mFTxTYeL14B6fUZcjdNDjA5vG7Wnmz-LDr0qG888cLxdvau4VjkthT_y9YfheWkpPN8S4nEob-1ddIFVmp1eangnr5A9qodAJpjSsqxpfCv4932Z0reUCklsJVlJDl-22mmP0oO1DWcuUM4hm6c4NZUyHP0rkSekYf0A1DKVM_5tjsmrvVfBYLlsfYHKPPuSO8-6oXqnFnQVpGFTMnrP8akJjqfadUQXG4spwiR3RA21kmeJBKuCxmt6ZtdGRy3X6l6fK6fIXTtW6NTsNkfqv5Aq0K58pqkISmzaCG03-7JMBvIB2IUdRs7JbQtAUsKZBTcLIatz0q5-DbdvSj0PLiqQZN5Elf5arWXuFlU8tpijBYbaebOZrl8l9yqRWgFJSPK75xpKmYrMgA964o-krtRUCFqRQtpHhjZoWutQYOQ_kpiekE1fQMJQTTzRfAJ0A_QX9VHJpfZijtluTOZuvPBB3-gPoLYndI7MtRabRTnOsc0IrzH_cFtjV28YDj-dz93DQs6ORUdAjED8bAwpqtYCQ5CSPe9cr8zpHFbkiTDUj8Gz2qLU6Mq6KQkBIkPIkDMq5KsJqR72-YDzWV8rhcuZdh0ZnhvLUK6KDjkPHUcjnOiGkocFaqjRrShzfWT8Uspes
        insecureCA: true
        issuer: https://kubernetes.default.svc
        redirectURI: https://dex-gitops.apps.${BASE_DOMAIN}/api/dex/callback
      id: openshift
      name: OpenShift
      type: openshift
  ga.anonymizeusers: "false"
  ga.trackingid: ""
  help.chatText: ""
  help.chatUrl: ""
  kustomize.buildOptions: ""
  repositories: ""
  repository.credentials: ""
  resource.exclusions: |
    - apiGroups:
      - tekton.dev
      clusters:
      - '*'
      kinds:
      - TaskRun
      - PipelineRun
  resource.inclusions: ""
  statusbadge.enabled: "false"
  url: https://dex-gitops.apps.${BASE_DOMAIN}
  users.anonymous.enabled: "false"
kind: ConfigMap
metadata:
  labels:
    app.kubernetes.io/managed-by: openshift-gitops
    app.kubernetes.io/name: argocd-cm
    app.kubernetes.io/part-of: argocd
  name: argocd-cm
EOF
