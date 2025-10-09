# MCP Least Privilege Demo - Complete Tutorial

This tutorial walks you through setting up a complete demonstration of the MCP (Model Context Protocol) Gateway with least privilege access controls for Kubernetes. You'll learn how to integrate Keycloak for authentication, implement OIDC-based access control, and enforce fine-grained authorization policies using Kyverno.

## Overview

By the end of this tutorial, you will have:
- A Kind cluster configured with OIDC authentication
- Keycloak as an identity provider with user groups
- Role-based access control (RBAC) for different user personas
- Kyverno authorization policies enforcing MCP tool access
- KGateway for routing MCP requests with authorization checks

## Prerequisites

Before starting, ensure you have the following tools installed:
- `kind` (Kubernetes in Docker)
- `kubectl`
- `helm` (v3)
- `openssl`
- `curl`
- `jq`

You should also have basic familiarity with:
- Kubernetes concepts (pods, deployments, namespaces)
- RBAC (roles, role bindings)
- Basic networking concepts

## Architecture

This demo implements a gateway pattern where:
1. Users authenticate via Keycloak and receive JWT tokens
2. MCP requests are routed through KGateway
3. Kyverno validates requests against RBAC policies and business rules
4. Only authorized actions reach the Kubernetes API server

## Step 1: Generate SSL Certificates

First, we need to create a Certificate Authority (CA) and SSL certificates for securing Keycloak. These certificates will be used to enable HTTPS communication with the Keycloak instance.

```sh
# Create directory for SSL certificates
mkdir -p .ssl

# Generate a private key for the root CA
openssl genrsa -out .ssl/root-ca-key.pem 4096

# Generate a self-signed root CA certificate (valid for 10 years)
openssl req -x509 -new -nodes -key .ssl/root-ca-key.pem \
  -sha256 -days 3650 -out .ssl/root-ca.pem \
  -subj "/CN=Kind Root CA"
```

The root CA certificate will be mounted into the Kubernetes API server so it can validate tokens from Keycloak.

## Step 2: Create Kind Cluster with OIDC Support

Now we'll create a Kind cluster configured to use Keycloak as an OIDC provider. The API server needs specific flags to enable OIDC authentication.

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

**What this does:**
- Creates a Kind cluster with OIDC authentication enabled
- Configures the API server with Keycloak as the OIDC issuer
- Mounts the root CA certificate so the API server can verify Keycloak's SSL certificate
- Extracts user identity from the `email` claim and group membership from the `groups` claim in JWT tokens

## Step 3: Install Ingress Controller

To expose services like Keycloak outside the cluster, we need an ingress controller. We'll use the NGINX Ingress Controller.

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

This installs the NGINX Ingress Controller which will route external traffic to our Keycloak instance.

## Step 4: Configure DNS Resolution

Add the following entry to your `/etc/hosts` file to resolve the Keycloak hostname:

```sh
NGINX_LB_IP=$(kubectl get svc -n ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
echo "address=/keycloak.kind.cluster/${NGINX_LB_IP}" | sudo tee /etc/dnsmasq.d/keycloak.kind.cluster.conf
sudo systemctl restart dnsmasq

# On macOS, we need to add a resolver file for the custom domai
sudo mkdir -p /etc/resolver
echo "nameserver 127.0.0.1" | sudo tee /etc/resolver/keycloak.kind.cluster
```

## Step 5: Install and Configure Keycloak

```sh
helm upgrade --install --wait --timeout 15m \
  --namespace keycloak --create-namespace \
  --repo https://charts.bitnami.com/bitnami keycloak keycloak \
  --reuse-values --values - <<EOF
keycloak:
  image: bitnamilegacy/keycloak:latest
auth:
  createAdminUser: true
  adminUser: admin
  adminPassword: admin
  managementUser: manager
  managementPassword: manager
proxyAddressForwarding: true
ingress:
  enabled: true
  ingressClass: nginx
  hostname: keycloak.kind.cluster
  tls: true
  extraTls:
  - hosts:
    - keycloak.kind.cluster
    secretName: keycloak.kind.cluster-tls
postgresql:
  image: bitnamilegacy/postgresql:latest
  enabled: true
  postgresqlPassword: password
EOF
```

Keycloak is now installed with:
- Admin credentials: `admin/admin`
- PostgreSQL backend for persistence
- Ingress enabled for external access at `https://keycloak.kind.cluster`
- Proxy headers forwarding enabled for correct redirect URIs

**Note:** This installation may take several minutes. Wait for all pods to be ready before proceeding.

### Setup Keycloak with keycloak.tf

This repo includes a `keycloak.tf` file that uses the [terraform-provider-keycloak](https://registry.terraform.io/providers/mrparkers/keycloak/latest/docs) to automate the creation of Keycloak users, groups, and OIDC clients.  
You can review and customize `keycloak.tf` to match your environment, then run `terraform apply` to provision all required Keycloak resources for the demo.

## Step 6: Generate Keycloak SSL Certificates

Next, we'll create SSL certificates specifically for the Keycloak ingress, signed by our root CA.

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

These certificates enable HTTPS for the Keycloak ingress and are trusted by our Kind cluster since they're signed by the root CA we mounted earlier.

## Step 7: Configure Keycloak Users and Groups

Before setting up RBAC, you need to configure Keycloak with users and groups. Access the Keycloak admin console:

1. Navigate to `https://keycloak.kind.cluster` in your browser
2. Login with credentials: `admin/admin`
3. In the "master" realm, create two groups:
   - `kube-admin` - for platform administrators
   - `kube-dev` - for developers
4. Create two users:
   - **user-admin**: Add to `kube-admin` group, set password to `user-admin`
   - **user-dev**: Add to `kube-dev` group, set password to `user-dev`
5. Create an OIDC client named `kube` with:
   - Client ID: `kube`
   - Client Secret: `kube-client-secret`
   - Valid Redirect URIs: `*`
   - Access Type: `confidential`
6. Create another OIDC client named `mcp-inspector` for testing:
   - Client ID: `mcp-inspector`
   - Access Type: `public`
   - Valid Redirect URIs: `*`
   - Direct Access Grants Enabled: `ON`
7. Configure the `kube` client to include the `groups` claim in tokens:
   - Go to the client's "Mappers" tab
   - Add a "Group Membership" mapper named `groups`
   - Token Claim Name: `groups`
8. Create a namespace in Kubernetes for our dev team:

```sh
kubectl create namespace dev-team
```

## Step 8: Configure RBAC for Developers

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

This creates a namespace-scoped role for developers that allows them to:
- Manage common resources (pods, services, configmaps, deployments)
- View logs and events
- Scale deployments and statefulsets
- Manage ingresses and network policies

The role is bound to the `kube-dev` group from Keycloak, and developers also get cluster-level discovery permissions to list namespaces and access API endpoints.

## Step 9: Configure RBAC for Platform Administrators

Now let's set up permissions for platform administrators who need broader cluster access.

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

This gives members of the `kube-admin` group the built-in `admin` role across the cluster.

## Step 10: Create Kubectl Configurations for Users

```sh
./create-config.sh
```

This script:
1. Obtains OIDC tokens from Keycloak for both `user-admin` and `user-dev`
2. Configures kubectl contexts for each user with their respective credentials
3. Creates kubeconfig entries that automatically refresh tokens using the OIDC provider

After running this, you can switch between users with:
```sh
kubectl config use-context user-admin
# or
kubectl config use-context user-dev
```

**Test the RBAC setup:**
```sh
# Switch to dev user
kubectl config use-context user-dev

# This should work (dev-team namespace)
kubectl get pods -n dev-team

# This should fail (no access to kube-system)
kubectl get pods -n kube-system

# Switch back to admin
kubectl config use-context user-admin
```

## Step 11: Install cert-manager

cert-manager is required by Kyverno for managing TLS certificates used in webhook configurations.

```sh
helm upgrade -i cert-manager \
  --namespace cert-manager --create-namespace \
  --wait \
  --repo https://charts.jetstack.io cert-manager \
  --set crds.enabled=true
```

## Step 12: Install Kyverno Authorization Server

Kyverno will act as an authorization server that validates MCP requests against Kubernetes RBAC policies and custom business rules.

```sh
echo "🔐 Creating ClusterIssuer for certificate generation..."
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
EOF


```sh
helm upgrade -i kyverno-authz-server \
  --namespace kyverno --create-namespace \
  --version v0.3.0 \
  --wait \
  --repo https://kyverno.github.io/kyverno-envoy-plugin kyverno-authz-server \
  --set service.appProtocol="kubernetes.io/h2c" \
  --set certificates.certManager.issuerRef.group=cert-manager.io \
  --set certificates.certManager.issuerRef.kind=ClusterIssuer \
  --set certificates.certManager.issuerRef.name=selfsigned-issuer
```

The Kyverno authorization server will:
- Intercept requests sent to the MCP gateway
- Decode JWT tokens to extract user identity and groups
- Perform SubjectAccessReview checks against Kubernetes RBAC
- Enforce custom validation policies (namespace restrictions, label policies, etc.)


## Step 13: Deploy Kyverno Policies

Apply the custom validation policies that will enforce our security rules:

```sh
kubectl apply -f policies/
```

These policies include:
- **opt-in-namespaces.yaml**: Restricts MCP tool calls to specific whitelisted namespaces (default, dev-team, test)
- **restrict-mcp-label-update.yaml**: Validates that users have RBAC permissions before allowing label updates via MCP tools

## Step 14: Install KGateway and Gateway API

```sh
# Install Gateway API
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.3.0/experimental-install.yaml

# Install Kgateway CRDS
helm upgrade -i --create-namespace --namespace kgateway-system --version v2.1.0-main kgateway-crds oci://cr.kgateway.dev/kgateway-dev/charts/kgateway-crds

# Installl KGateway
helm upgrade -i --namespace kgateway-system --version v2.1.0-main kgateway oci://cr.kgateway.dev/kgateway-dev/charts/kgateway \
  --set agentgateway.enabled=true \
  --set gateway.aiExtension.enabled=true \
  --set agentgateway.enableAlphaAPIs=true
  
```

We also need install kubernetes-aware MCP tools:

```sh
helm upgrade -i -n kagent --create-namespace kagent-tools oci://ghcr.io/kagent-dev/tools/helm/kagent-tools --version 0.0.12
```

**What we just installed:**
- **Gateway API CRDs**: Custom Resource Definitions for the Gateway API (HTTPRoute, Gateway, etc.)
- **KGateway CRDs**: Additional CRDs specific to KGateway
- **KGateway**: The main gateway controller with AI/MCP extension support
- **Agent Gateway**: Enables agent-based interactions with enhanced AI features
- **kagent-tools**: Kubernetes-aware tools that can be called through the MCP protocol

## Step 15: Configure Gateway Resources

Now we'll apply the gateway configurations that set up routing and authorization policies:

```sh
kubectl apply -f gateway/
```

The `gateway/` directory contains:
- **gateway.yaml**: Main gateway configuration
- **gateway-extension.yaml**: AI/MCP extension configuration
- **http-route.yaml**: Routing rules for MCP requests
- **mcp-backend.yaml**: Backend service configuration for MCP tools
- **ref-grant.yaml**: Cross-namespace reference permissions
- **traffic-policy.yaml**: Traffic policies including authorization checks with Kyverno

This creates the complete routing pipeline:
```
User Request → Gateway → Kyverno Authorization Check → MCP Backend → Kubernetes API
```

## Step 16: Testing the Setup

### Get a User Token

First, obtain a token for testing the MCP endpoint:

```sh
# Get token for dev user
DEV_TOKEN=$(curl -k -X POST https://keycloak.kind.cluster/realms/master/protocol/openid-connect/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password' \
  -d 'client_id=mcp-inspector' \
  -d "username=user-dev" \
  -d "password=user-dev" \
  -d 'scope=openid' | jq -r '.access_token')

echo "Dev Token: $DEV_TOKEN"
```

You can also get the full token response to examine it:

```sh
curl -k -X POST https://keycloak.kind.cluster/realms/master/protocol/openid-connect/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password' \
  -d 'client_id=mcp-inspector' \
  -d "username=user-dev" \
  -d "password=user-dev" \
  -d 'scope=openid'
```

### Test MCP Tool Access

Once you have the gateway deployed, you can test MCP tool calls. The exact endpoint will depend on your gateway configuration, but it typically looks like:

```sh
# Get the gateway endpoint
GATEWAY_URL="$(kubectl get gateway -n kgateway-system -o jsonpath='{.items[0].status.addresses[0].value}'):8080"

# Get a session ID
SESSION_ID=$(curl -sS --http1.1 -i http://$GATEWAY_URL/mcp \
  -H "Authorization: Bearer $DEV_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1.0"}}}' \
  | grep -i "^Mcp-Session-Id:" | cut -d' ' -f2 | tr -d '\r')


# Try calling a tool (e.g., list pods in dev-team namespace)
curl -k http://$GATEWAY_URL/mcp \
  -H "Authorization: Bearer $DEV_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream, application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -H "MCP-Protocol-Version: 2025-06-18" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "k8s_get_resources",
      "arguments": {
        "all_namespaces": "false",
        "namespace": "kube-system",
        "output": "json",
        "resource_name": "",
        "resource_type": "pods"
      },
      "_meta": {
        "progressToken": 0
      }
    }
  }'
```

Note that this, since we're using the dev token, this **shouldn't work**. This is what we're going to enforce in the next part.

### Policy Enforcement with restrict-mcp-label-update Policy

Now let's apply the `restrict-mcp-label-update.yaml` policy to enforce RBAC checks on `k8s_get_resources` calls.

```sh
kubectl apply -f - <<EOF
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: restrict-get-resource
spec:
  evaluation:
    mode: Envoy
  variables:
    - name: body
      expression: json.Unmarshal(object.attributes.request.http.body)
    - name: isAllowedNamespace
      expression: has(variables.body.params.arguments) && string(variables.body.params.arguments.namespace) in ["default", "dev-team", "test"]
    - name: jwks
      expression: jwks.Fetch("http://keycloak.keycloak.svc.cluster.local/realms/master/protocol/openid-connect/certs")
    - name: jwtString
      expression: object.attributes.request.http.headers["authorization"].split(" ")[1]
    - name: decodedJwt
      expression: jwt.Decode(variables.jwtString, variables.jwks)
    - name: res
      expression: >-
        {
          "kind": dyn("SubjectAccessReview"),
          "apiVersion": dyn("authorization.k8s.io/v1"),
          "spec": dyn({
            "resourceAttributes": dyn({
              "group": "",
              "resource": string(variables.body.params.arguments.resource_type),
              "namespace": string(variables.body.params.arguments.namespace),
              "verb": "list"
            }),
            "user": dyn(variables.decodedJwt.Claims["email"]),
            "groups": dyn(variables.decodedJwt.Claims["groups"])
          })
        }
    - name: sar
      expression: >-
        resource.Post("authorization.k8s.io/v1", "subjectaccessreviews", variables.res)
  matchConditions:
  - expression: |
      has(json.Unmarshal(object.attributes.request.http.body).method)
        && json.Unmarshal(object.attributes.request.http.body).method == "tools/call"
        && has(json.Unmarshal(object.attributes.request.http.body).params.name)
        && json.Unmarshal(object.attributes.request.http.body).params.name == "k8s_get_resources"
    name: isToolsCall
  validations:
  - expression: |
      has(variables.body.params.arguments.all_namespaces)
        && variables.body.params.arguments.all_namespaces == "false"
        && has(variables.sar.status)
        && variables.sar.status.allowed == true ? envoy.Allowed().Response() : envoy.Denied(403).Response()
EOF
```

### Common Issues

**1. Keycloak not accessible**
- Verify ingress is running: `kubectl get ingress -n keycloak`
- Check `/etc/hosts` has the correct entry
- Verify SSL certificate: `kubectl get secret -n keycloak keycloak.kind.cluster-tls`

**2. Token validation failing**
- Ensure the root CA is mounted in the API server
- Check API server logs: `kubectl logs -n kube-system kube-apiserver-kind-control-plane`
- Verify OIDC configuration: `kubectl cluster-info dump | grep oidc`

**3. Policy denials**
- Check policy is applied: `kubectl get validatingpolicy -A`
- Review Kyverno logs for denial reasons
- Verify JWT token contains expected claims (email, groups)

**4. RBAC permission errors**
- Test permissions directly with kubectl: `kubectl auth can-i list pods -n dev-team --as=user-dev@domain.com`
- Review role bindings: `kubectl get rolebinding -n dev-team`
- Check cluster role bindings: `kubectl get clusterrolebinding | grep kube-dev`

### Cleanup

To tear down the demo environment:

```sh
# Delete the Kind cluster
kind delete cluster

# Remove hosts entry
sudo sed -i '/address=\/keycloak.kind.cluster\//d' /etc/dnsmasq.d/kind-cluster.conf
sudo systemctl restart dnsmasq
# Remove resolver file if present
sudo rm -f /etc/resolver/keycloak.kind.cluster

# Optional: Clean up SSL certificates
rm -rf .ssl/
```

## What You've Accomplished

Congratulations! You've successfully built a comprehensive MCP gateway with least privilege controls:

✅ **Authentication**: Users authenticate via Keycloak OIDC  
✅ **Authorization**: Kyverno validates every MCP request against RBAC  
✅ **Audit Trail**: All actions are logged with real user identity  
✅ **Namespace Isolation**: Policies restrict access to approved namespaces  
✅ **Business Rules**: Custom validation policies enforce organizational standards  
✅ **Least Privilege**: Users can only perform actions their RBAC roles allow  

This architecture solves the key challenges of AI/LLM integration with Kubernetes:
- No more shared service accounts with excessive permissions
- Complete audit trail of who did what
- Fine-grained control over AI-initiated actions
- Enforcement of business policies beyond RBAC

## Next Steps

Consider these enhancements:

1. **Add more granular policies**: Create policies for resource quotas, image restrictions, pod security standards
2. **Implement rate limiting**: Prevent abuse by limiting request rates per user
3. **Add metrics and monitoring**: Export authorization metrics to Prometheus
4. **Create custom MCP tools**: Build domain-specific tools that wrap complex Kubernetes operations
5. **Integrate with CI/CD**: Use this pattern for secure automated deployments
6. **Extend to multiple clusters**: Use the same pattern across dev, staging, and production environments

## References

- [MCP Authorization Blog Post](https://www.solo.io/blog/mcp-authorization-is-a-non-starter-for-enterprise)
- [Kubernetes OIDC Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens)
- [Kyverno Policies](https://kyverno.io/docs/)
- [Gateway API](https://gateway-api.sigs.k8s.io/)
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)