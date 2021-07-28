#!/bin/bash

export GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID:-foo}
export GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET:-foobar}
export BASE_DOMAIN=$(oc cluster-info | grep api | sed 's/.*api.//g' | cut -d':' -f1)
export DEX_ROUTE=dex.apps.${BASE_DOMAIN}

current_project=$(oc project -q)
# oc new-project dex-community
oc new-project $current_project || echo "project already exists ..."

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
DNS.1 = dex-community
DNS.2 = dex-community-grpc
DNS.3 = dex-community.svc.cluster.local
DNS.4 = dex-community.apps.${BASE_DOMAIN}
EOF

openssl genrsa -out ssl/ca-key.pem 2048
openssl req -x509 -new -nodes -key ssl/ca-key.pem -days 10 -out ssl/ca.pem -subj "/CN=kube-ca"

openssl genrsa -out ssl/key.pem 2048
openssl req -new -key ssl/key.pem -out ssl/csr.pem -subj "/CN=kube-ca" -config ssl/req.cnf
openssl x509 -req -in ssl/csr.pem -CA ssl/ca.pem -CAkey ssl/ca-key.pem -CAcreateserial -out ssl/cert.pem -days 10 -extensions v3_req -extfile ssl/req.cnf
fi

#
# Create self signed cert for the Service/Route
#
# TODO: can we create the CERT after the route is created ?
#
oc create secret tls dex-community.tls --cert=ssl/cert.pem --key=ssl/key.pem

# 2. Define the github application client bits in a secret
# 
# * The github client can be updated after the dex pod is running?
# * Test changing the client bits
oc create secret generic github-client-community \
--from-literal=client-id=${GITHUB_CLIENT_ID} \
--from-literal=client-secret=${GITHUB_CLIENT_SECRET}

# 3. Create the Dex Configuration configmap.
# 
cat <<EOF | oc apply -f -
---
kind: ConfigMap
apiVersion: v1
metadata:
  name: dex-community
data:
  config.yaml: |
    issuer: https://dex-community.apps.${BASE_DOMAIN}
    storage:
      type: kubernetes
      config:
        inCluster: true
    web:
      https: 0.0.0.0:5556
      tlsCert: /etc/dex/tls/tls.crt
      tlsKey: /etc/dex/tls/tls.key
    connectors:
    - type: github
      id: github
      name: GitHub
      config:
        clientID: \$GITHUB_CLIENT_ID
        clientSecret: \$GITHUB_CLIENT_SECRET
        redirectURI: https://dex-community.apps.${BASE_DOMAIN}/callback
        org: kubernetes
    oauth2:
      skipApprovalScreen: true
    staticClients:
    - id: example-app
      redirectURIs:
      - 'http://127.0.0.1:5555/callback'
      name: 'Example App'
      secret: ZXhhbXBsZS1hcHAtc2VjcmV0
    enablePasswordDB: true
    staticPasswords:
    - email: "admin@example.com"
      # bcrypt hash of the string "password"
      hash: "\$2a\$10\$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W"
      username: "admin"
      userID: "08a8684b-db88-4b73-90a9-3cd1661f5466"
EOF
