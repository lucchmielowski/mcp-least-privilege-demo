```sh
# create cluster with our generated certificate
# and pass necessary arguments to api server
kind create cluster --image kindest/node:v1.33.1 --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
kubeadmConfigPatches:
- |-
  kind: ClusterConfiguration
  apiServer:
    extraArgs:
      oidc-client-id: kube
      oidc-issuer-url: https://keycloak.kind.cluster/realms/master
      oidc-username-claim: email
      oidc-groups-claim: groups
      oidc-ca-file: /etc/ca-certificates/keycloak/root-ca.pem
nodes:
- role: control-plane
  extraMounts:
  - hostPath: $PWD/.ssl/root-ca.pem
    containerPath: /etc/ca-certificates/keycloak/root-ca.pem
    readOnly: true
- role: worker
EOF
```

```sh
helm upgrade --install --wait --timeout 15m \
  --namespace ingress-nginx --create-namespace \
  --repo https://kubernetes.github.io/ingress-nginx \
  ingress-nginx ingress-nginx \
  --values - <<EOF
defaultBackend:
  enabled: true
EOF
```


## Keycloak config

```sh
helm upgrade --install --wait --timeout 15m \
  --namespace keycloak --create-namespace \
  --repo https://charts.bitnami.com/bitnami keycloak keycloak \
  --reuse-values --values - <<EOF
auth:
  createAdminUser: true
  adminUser: admin
  adminPassword: admin
  managementUser: manager
  managementPassword: manager
proxyAddressForwarding: true
ingress:
  enabled: true
  hostname: keycloak.kind.cluster
  annotations:
    kubernetes.io/ingress.class: nginx
  tls: true
  extraTls:
  - hosts:
    - keycloak.kind.cluster
    secretName: keycloak.kind.cluster-tls
postgresql:
  enabled: true
  postgresqlPassword: password
EOF
```

```sh
# create certificate configuration file
cat <<EOF > .ssl/req.cnf
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = keycloak.kind.cluster
EOF

# generate private key
openssl genrsa -out .ssl/key.pem 2048

# create certificate signing request
openssl req -new -key .ssl/key.pem -out .ssl/csr.pem \
  -subj "/CN=kube-ca" \
  -addext "subjectAltName = DNS:keycloak.kind.cluster" \
  -sha256 -config .ssl/req.cnf
  
# create certificate
openssl x509 -req -in .ssl/csr.pem \
  -CA .ssl/root-ca.pem -CAkey .ssl/root-ca-key.pem \
  -CAcreateserial -sha256 -out .ssl/cert.pem -days 3650 \
  -extensions v3_req -extfile .ssl/req.cnf
  
# create secret used by keycloak ingress
kubectl create secret tls -n keycloak keycloak.kind.cluster-tls \
  --cert=.ssl/cert.pem \
  --key=.ssl/key.pem
```

## RBAC Creation

```sh
# DevTeam Role
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: dev-namespace-developer
  namespace: dev-team
rules:
  - apiGroups: [""]
    resources: ["pods","services","configmaps"]
    verbs: ["get","list","watch","create","update","patch","delete"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
  - apiGroups: ["apps"]
    resources: ["deployments","replicasets","statefulsets"]
    verbs: ["get","list","watch","create","update","patch","delete"]
  - apiGroups: ["apps"]
    resources: ["deployments/scale","statefulsets/scale"]
    verbs: ["get","update","patch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses","networkpolicies"]
    verbs: ["get","list","watch","create","update","patch","delete"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["get","list","watch"]
---
# Bind the role to the Keycloak group kube-dev in that namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dev-namespace-developer-binding
  namespace: dev-team
subjects:
  - kind: Group
    name: kube-dev
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: dev-namespace-developer
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dev-discovery
rules:
  - nonResourceURLs: ["/api","/apis","/openapi","/version"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get","list","watch"]  # read-only; helps clients pick namespaces
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dev-discovery-binding
subjects:
  - kind: Group
    name: kube-dev
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: dev-discovery
  apiGroup: rbac.authorization.k8s.io
EOF
```

```sh
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: platform-admin-binding
subjects:
  - kind: Group
    name: kube-admin
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: admin        # built-in role
  apiGroup: rbac.authorization.k8s.io
EOF
```

```sh
kubectl apply -f - <<EOF
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: kube-admin
subjects:
- kind: Group
  name: kube-admin
  apiGroup: rbac.authorization.k8s.io
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: kube-dev
subjects:
- kind: Group
  name: kube-dev
  apiGroup: rbac.authorization.k8s.io
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: edit
EOF
```

## Create user configs

```sh
./create-config.sh
```

## Install Kyverno authz-server

```sh
# Install Kyverno authz-server
echo "🔐 Installing cert-manager..."
helm upgrade -i cert-manager \
  --namespace cert-manager --create-namespace \
  --wait \
  --repo https://charts.jetstack.io cert-manager \
  --set crds.enabled=true

echo "🔐 Creating ClusterIssuer..."
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
EOF

make install-kyverno-authz-server
```

## KGateway Install

```sh
echo "📦 Installing Gateway API CDRDs..."
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.3.0/experimental-install.yaml

echo "📦 Installing KGateway CDRDs..."
helm upgrade -i --create-namespace --namespace kgateway-system --version v2.1.0-main kgateway-crds oci://cr.kgateway.dev/kgateway-dev/charts/kgateway-crds

echo "📦 Installing KGateway..."
helm upgrade -i --namespace kgateway-system --version v2.1.0-main kgateway oci://cr.kgateway.dev/kgateway-dev/charts/kgateway \
  --set agentgateway.enabled=true \
  --set gateway.aiExtension.enabled=true \
  --set agentgateway.enableAlphaAPIs=true
  
  
helm upgrade -i -n kagent --create-namespace kagent-tools oci://ghcr.io/kagent-dev/tools/helm/kagent-tools --version 0.0.12

kubectl apply -f gateway/
```

## Get user token

```sh
curl -k -X POST https://keycloak.kind.cluster/realms/master/protocol/openid-connect/token \
-H 'Content-Type: application/x-www-form-urlencoded' \
-d 'grant_type=password' \
-d 'client_id=mcp-inspector' \
-d "username=user-dev" \
-d "password=user-dev" \
-d 'scope=openid'
```