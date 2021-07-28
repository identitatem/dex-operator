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

cat > argocd-secret-gen.yaml <<EOF
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
