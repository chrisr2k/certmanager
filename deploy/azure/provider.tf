terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  backend "azurerm" {
    resource_group_name  = "certmanager-tfstate"
    storage_account_name = "certmanagertfstate"
    container_name       = "tfstate"
    key                  = "azure/terraform.tfstate"
  }
}

provider "azurerm" {
  features {}
  # Note: the azurerm provider has no provider-level default_tags (that is an
  # AWS feature). Add `tags = { ... }` to individual resources as needed.
}

data "azurerm_client_config" "current" {}
