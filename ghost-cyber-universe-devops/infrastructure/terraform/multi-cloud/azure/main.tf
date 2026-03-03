# Infrastructure Azure pour Ghost Cyber Universe
# Configuration sécurisée avec Terraform

terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
  }
  
  # Backend Azure sécurisé
  backend "azurerm" {
    resource_group_name  = "ghost-cyber-universe-terraform-rg"
    storage_account_name = "ghostcyberuniversetfstate"
    container_name       = "tfstate"
    key                  = "azure/terraform.tfstate"
    encryption_key       = "ghost-cyber-universe-terraform-key"
  }
}

# Provider Azure
provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = true
    }
    
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
  }
}

# Provider Kubernetes
provider "kubernetes" {
  host                   = azurerm_kubernetes_cluster.main.kube_config.0.host
  client_certificate     = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.client_certificate)
  client_key             = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.client_key)
  cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.cluster_ca_certificate)
}

# Provider Helm
provider "helm" {
  kubernetes {
    host                   = azurerm_kubernetes_cluster.main.kube_config.0.host
    client_certificate     = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.client_certificate)
    client_key             = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.client_key)
    cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.main.kube_config.0.cluster_ca_certificate)
  }
}

# Resource Group
resource "azurerm_resource_group" "main" {
  name     = "${var.project_name}-rg"
  location = var.azure_region
  
  tags = {
    Project     = "Ghost Cyber Universe"
    Environment = var.environment
    Security    = "High"
    Compliance  = "Required"
    ManagedBy   = "Terraform"
  }
}

# Virtual Network sécurisé
resource "azurerm_virtual_network" "main" {
  name                = "${var.project_name}-vnet"
  address_space       = [var.vnet_address_space]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  
  tags = {
    Name        = "${var.project_name}-vnet"
    Environment = var.environment
    Security    = "High"
  }
}

# Subnets privées
resource "azurerm_subnet" "private" {
  count = length(var.private_subnets)
  
  name                 = "${var.project_name}-private-subnet-${count.index + 1}"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.private_subnets[count.index]]
  
  # Configuration de sécurité
  private_endpoint_network_policies_enabled = true
  private_link_service_network_policies_enabled = true
}

# Subnets publiques
resource "azurerm_subnet" "public" {
  count = length(var.public_subnets)
  
  name                 = "${var.project_name}-public-subnet-${count.index + 1}"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.public_subnets[count.index]]
}

# AKS Cluster sécurisé
resource "azurerm_kubernetes_cluster" "main" {
  name                = "${var.project_name}-aks"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = "${var.project_name}-aks"
  kubernetes_version  = var.kubernetes_version
  
  # Configuration de sécurité
  private_cluster_enabled = true
  private_dns_zone_id     = azurerm_private_dns_zone.main.id
  
  # Configuration réseau
  network_profile {
    network_plugin    = "azure"
    network_policy    = "azure"
    load_balancer_sku = "standard"
    
    service_cidr       = var.service_cidr
    dns_service_ip     = var.dns_service_ip
    docker_bridge_cidr = var.docker_bridge_cidr
  }
  
  # Configuration de sécurité
  default_node_pool {
    name                = "system"
    node_count         = 3
    vm_size            = var.vm_size
    os_disk_size_gb    = 50
    os_disk_type       = "Premium_LRS"
    vnet_subnet_id     = azurerm_subnet.private[0].id
    
    # Configuration de sécurité
    enable_auto_scaling = true
    min_count          = 2
    max_count          = 10
    
    # Configuration de sécurité
    node_taints = [
      "security.ghost-cyber-universe.com/scan=required:NoSchedule"
    ]
    
    # Configuration de sécurité
    node_labels = {
      environment = var.environment
      security    = "high"
    }
  }
  
  # Configuration de sécurité
  identity {
    type = "SystemAssigned"
  }
  
  # Configuration de sécurité
  azure_active_directory_role_based_access_control {
    managed                = true
    admin_group_object_ids = [var.admin_group_object_id]
    azure_rbac_enabled     = true
  }
  
  # Configuration de sécurité
  key_vault_secrets_provider {
    secret_rotation_enabled = true
  }
  
  # Configuration de monitoring
  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  }
  
  # Configuration de sécurité
  azure_policy_enabled = true
  
  # Configuration de sécurité
  auto_scaler_profile {
    balance_similar_node_groups      = true
    expander                         = "priority"
    max_graceful_termination_sec    = 600
    max_node_provisioning_time      = "15m"
    max_unready_nodes               = 3
    max_unready_percentage          = 45
    new_pod_scale_up_delay          = "10s"
    scale_down_delay_after_add      = "10m"
    scale_down_delay_after_delete   = "10s"
    scale_down_delay_after_failure  = "3m"
    scan_interval                   = "10s"
    scale_down_utilization_threshold = 0.5
    skip_nodes_with_local_storage   = false
    skip_nodes_with_system_pods     = true
  }
  
  # Configuration de sécurité
  maintenance_window {
    allowed {
      day   = "Sunday"
      hours = [3, 4]
    }
  }
  
  # Configuration de sécurité
  upgrade_settings {
    max_surge = "33%"
  }
  
  tags = {
    Name        = "${var.project_name}-aks"
    Environment = var.environment
    Security    = "High"
  }
}

# Private DNS Zone
resource "azurerm_private_dns_zone" "main" {
  name                = "privatelink.${var.azure_region}.azmk8s.io"
  resource_group_name = azurerm_resource_group.main.name
}

# Private DNS Zone Virtual Network Link
resource "azurerm_private_dns_zone_virtual_network_link" "main" {
  name                  = "${var.project_name}-dns-link"
  resource_group_name   = azurerm_resource_group.main.name
  private_dns_zone_name = azurerm_private_dns_zone.main.name
  virtual_network_id    = azurerm_virtual_network.main.id
  registration_enabled  = false
}

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.project_name}-logs"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                = "PerGB2018"
  retention_in_days  = 30
  
  tags = {
    Name        = "${var.project_name}-logs"
    Environment = var.environment
    Security    = "High"
  }
}

# Key Vault sécurisé
resource "azurerm_key_vault" "main" {
  name                = "${var.project_name}-kv"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "premium"
  
  # Configuration de sécurité
  enabled_for_disk_encryption = true
  enabled_for_deployment     = true
  enabled_for_template_deployment = true
  enable_rbac_authorization  = true
  purge_protection_enabled   = true
  soft_delete_retention_days = 90
  
  # Configuration de sécurité
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    
    ip_rules = var.allowed_ip_ranges
  }
  
  tags = {
    Name        = "${var.project_name}-kv"
    Environment = var.environment
    Security    = "High"
  }
}

# Key Vault Access Policy
resource "azurerm_key_vault_access_policy" "main" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id
  
  key_permissions = [
    "Get", "List", "Create", "Delete", "Update", "Import", "Backup", "Restore", "Recover", "Purge"
  ]
  
  secret_permissions = [
    "Get", "List", "Set", "Delete", "Backup", "Restore", "Recover", "Purge"
  ]
  
  certificate_permissions = [
    "Get", "List", "Create", "Delete", "Update", "Import", "Backup", "Restore", "Recover", "Purge"
  ]
}

# PostgreSQL Database sécurisé
resource "azurerm_postgresql_flexible_server" "main" {
  name                   = "${var.project_name}-db"
  resource_group_name    = azurerm_resource_group.main.name
  location               = azurerm_resource_group.main.location
  version                = "15"
  administrator_login    = "ghost_cyber_universe"
  administrator_password = var.db_password
  
  # Configuration de sécurité
  backup_retention_days = 7
  geo_redundant_backup_enabled = true
  
  # Configuration de sécurité
  high_availability {
    mode = "ZoneRedundant"
  }
  
  # Configuration de sécurité
  maintenance_window {
    day_of_week  = 0
    start_hour   = 3
    start_minute = 0
  }
  
  # Configuration de sécurité
  storage_mb = 32768
  sku_name   = var.db_sku_name
  
  # Configuration de sécurité
  zone = "1"
  
  # Configuration de sécurité
  delegated_subnet_id = azurerm_subnet.private[0].id
  private_dns_zone_id  = azurerm_private_dns_zone.postgresql.id
  
  # Configuration de sécurité
  ssl_enforcement_enabled = true
  ssl_minimal_tls_version_enforced = "TLS1_2"
  
  tags = {
    Name        = "${var.project_name}-db"
    Environment = var.environment
    Security    = "High"
  }
}

# Private DNS Zone pour PostgreSQL
resource "azurerm_private_dns_zone" "postgresql" {
  name                = "privatelink.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.main.name
}

# Private DNS Zone Virtual Network Link pour PostgreSQL
resource "azurerm_private_dns_zone_virtual_network_link" "postgresql" {
  name                  = "${var.project_name}-postgresql-dns-link"
  resource_group_name   = azurerm_resource_group.main.name
  private_dns_zone_name = azurerm_private_dns_zone.postgresql.name
  virtual_network_id    = azurerm_virtual_network.main.id
  registration_enabled  = false
}

# PostgreSQL Database
resource "azurerm_postgresql_flexible_server_database" "main" {
  name      = "ghost_cyber_universe"
  server_id = azurerm_postgresql_flexible_server.main.id
  collation = "en_US.utf8"
  charset   = "utf8"
}

# PostgreSQL Firewall Rule
resource "azurerm_postgresql_flexible_server_firewall_rule" "main" {
  name             = "AllowAzureServices"
  server_id        = azurerm_postgresql_flexible_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# Storage Account sécurisé
resource "azurerm_storage_account" "main" {
  name                     = "${var.project_name}storage${random_id.storage_suffix.hex}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"
  
  # Configuration de sécurité
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public  = false
  shared_access_key_enabled       = false
  public_network_access_enabled   = false
  
  # Configuration de sécurité
  network_rules {
    default_action = "Deny"
    bypass         = "AzureServices"
    
    ip_rules = var.allowed_ip_ranges
  }
  
  # Configuration de sécurité
  blob_properties {
    versioning_enabled = true
    change_feed_enabled = true
    change_feed_retention_in_days = 30
    
    delete_retention_policy {
      days = 30
    }
    
    container_delete_retention_policy {
      days = 30
    }
  }
  
  tags = {
    Name        = "${var.project_name}-storage"
    Environment = var.environment
    Security    = "High"
  }
}

# Storage Container
resource "azurerm_storage_container" "main" {
  name                  = "logs"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}

# Random ID pour le storage
resource "random_id" "storage_suffix" {
  byte_length = 4
}

# Data source pour la configuration client
data "azurerm_client_config" "current" {}

# Application Insights
resource "azurerm_application_insights" "main" {
  name                = "${var.project_name}-insights"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  application_type    = "web"
  
  tags = {
    Name        = "${var.project_name}-insights"
    Environment = var.environment
    Security    = "High"
  }
}

# Monitor Action Group
resource "azurerm_monitor_action_group" "main" {
  name                = "${var.project_name}-alerts"
  resource_group_name = azurerm_resource_group.main.name
  short_name          = "ghost-alerts"
  
  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
  
  tags = {
    Name        = "${var.project_name}-alerts"
    Environment = var.environment
    Security    = "High"
  }
}

# Monitor Alert Rule
resource "azurerm_monitor_metric_alert" "main" {
  name                = "${var.project_name}-cpu-alert"
  resource_group_name = azurerm_resource_group.main.name
  scopes              = [azurerm_kubernetes_cluster.main.id]
  description         = "High CPU usage alert"
  severity            = 2
  frequency           = "PT1M"
  window_size         = "PT5M"
  
  criteria {
    metric_namespace = "Microsoft.ContainerService/managedClusters"
    metric_name      = "cpuUsagePercentage"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 80
  }
  
  action {
    action_group_id = azurerm_monitor_action_group.main.id
  }
  
  tags = {
    Name        = "${var.project_name}-cpu-alert"
    Environment = var.environment
    Security    = "High"
  }
}
