terraform {
  required_providers {
    keycloak = {
      source  = "linz/keycloak"
      version = "4.4.1"
    }
  }
}
# configure keycloak provider
provider "keycloak" {
  client_id                = "admin-cli"
  username                 = "admin"
  password                 = "admin"
  url                      = "https://keycloak.kind.cluster"
  tls_insecure_skip_verify = true
}

locals {
  realm_id = "master"
  groups   = ["kube-dev", "kube-admin"]
  user_groups = {
    user-dev   = ["kube-dev"]
    user-admin = ["kube-admin"]
  }
}
# create groups
resource "keycloak_group" "groups" {
  for_each = toset(local.groups)
  realm_id = local.realm_id
  name     = each.key
}
# create users
resource "keycloak_user" "users" {
  for_each       = local.user_groups
  realm_id       = local.realm_id
  username       = each.key
  enabled        = true
  email          = "${each.key}@domain.com"
  email_verified = true
  first_name     = each.key
  last_name      = each.key
  initial_password {
    value = each.key
  }
}
# configure use groups membership
resource "keycloak_user_groups" "user_groups" {
  for_each  = local.user_groups
  realm_id  = local.realm_id
  user_id   = keycloak_user.users[each.key].id
  group_ids = [for g in each.value : keycloak_group.groups[g].id]
}
# create groups openid client scope
resource "keycloak_openid_client_scope" "groups" {
  realm_id               = local.realm_id
  name                   = "groups"
  include_in_token_scope = true
  gui_order              = 1
}

resource "keycloak_openid_group_membership_protocol_mapper" "groups" {
  realm_id        = local.realm_id
  client_scope_id = keycloak_openid_client_scope.groups.id
  name            = "groups"
  claim_name      = "groups"
  full_path       = false
}

# create kube openid client
resource "keycloak_openid_client" "kube" {
  realm_id                     = local.realm_id
  client_id                    = "kube"
  name                         = "kube"
  enabled                      = true
  access_type                  = "CONFIDENTIAL"
  client_secret                = "kube-client-secret"
  access_token_lifespan = 31536000 # 1 year
  standard_flow_enabled        = false
  implicit_flow_enabled        = false
  direct_access_grants_enabled = true
}
# configure kube openid client default scopes
resource "keycloak_openid_client_default_scopes" "kube" {
  realm_id  = local.realm_id
  client_id = keycloak_openid_client.kube.id
  default_scopes = [
    "email",
    keycloak_openid_client_scope.groups.name,
  ]
}


## MCP Client

resource "keycloak_openid_client" "mcp_inspector" {
  realm_id                    = local.realm_id
  client_id                   = "mcp-inspector"
  name                        = "MCP Inspector"
  access_type                 = "PUBLIC"

  standard_flow_enabled        = true
  implicit_flow_enabled        = false
  direct_access_grants_enabled = true

  pkce_code_challenge_method   = "S256"

  access_token_lifespan = 31536000 # 1 year

  valid_redirect_uris = [
    "http://localhost:6274/callback"
  ]
  web_origins = [
    "http://localhost:6274"
  ]
}

resource "keycloak_openid_client_default_scopes" "mcp_inspector" {
  realm_id  = local.realm_id
  client_id = keycloak_openid_client.mcp_inspector.id
  default_scopes = [
    "email",
    keycloak_openid_client_scope.groups.name,
  ]
}