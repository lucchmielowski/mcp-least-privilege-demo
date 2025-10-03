!/bin/sh

kubectl_config(){
  local ISSUER=https://keycloak.kind.cluster/realms/master
  local ENDPOINT=$ISSUER/protocol/openid-connect/token
  local ID_TOKEN=$(curl -k -X POST $ENDPOINT \
    -d grant_type=password \
    -d client_id=kube \
    -d client_secret=kube-client-secret \
    -d username=$1 \
    -d password=$1 \
    -d scope=openid \
    -d response_type=id_token | jq -r '.id_token')
  local REFRESH_TOKEN=$(curl -k -X POST $ENDPOINT \
    -d grant_type=password \
    -d client_id=kube \
    -d client_secret=kube-client-secret \
    -d username=$1 \
    -d password=$1 \
    -d scope=openid \
    -d response_type=id_token | jq -r '.refresh_token')
  local CA_DATA=$(cat .ssl/cert.pem | base64 | tr -d '\n')
  kubectl config set-credentials $1 \
    --auth-provider=oidc \
    --auth-provider-arg=client-id=kube \
    --auth-provider-arg=client-secret=kube-client-secret \
    --auth-provider-arg=idp-issuer-url=$ISSUER \
    --auth-provider-arg=id-token=$ID_TOKEN \
    --auth-provider-arg=refresh-token=$REFRESH_TOKEN \
    --auth-provider-arg=idp-certificate-authority-data=$CA_DATA
  kubectl config set-context $1 --cluster=kind-kind --user=$1
}

# setup config for our users
kubectl_config user-admin
kubectl_config user-dev