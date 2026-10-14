terraform {
  required_version = ">= 1.9.0"
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
  }
  # Use the site's remote state; the state holds hashes of the secrets, so keep
  # it encrypted and access-controlled like any Terraform state.
  # backend "s3" {}
}
