# Infrastructure GCP pour Ghost Cyber Universe
# Configuration sécurisée avec Terraform

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
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
  
  # Backend GCS sécurisé
  backend "gcs" {
    bucket = "ghost-cyber-universe-terraform-state"
    prefix = "gcp/terraform.tfstate"
    encryption_key = "ghost-cyber-universe-terraform-key"
  }
}

# Provider Google Cloud
provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
  zone    = var.gcp_zone
}

# Provider Kubernetes
provider "kubernetes" {
  host  = "https://${google_container_cluster.primary.endpoint}"
  token = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(
    google_container_cluster.primary.master_auth[0].cluster_ca_certificate
  )
}

# Provider Helm
provider "helm" {
  kubernetes {
    host  = "https://${google_container_cluster.primary.endpoint}"
    token = data.google_client_config.default.access_token
    cluster_ca_certificate = base64decode(
      google_container_cluster.primary.master_auth[0].cluster_ca_certificate
    )
  }
}

# Data sources
data "google_client_config" "default" {}

data "google_compute_zones" "available" {
  region = var.gcp_region
}

# VPC sécurisé
resource "google_compute_network" "vpc" {
  name                    = "${var.project_name}-vpc"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  
  depends_on = [google_project_service.compute]
}

# Subnets privées
resource "google_compute_subnetwork" "private" {
  count = length(var.private_subnets)
  
  name          = "${var.project_name}-private-subnet-${count.index + 1}"
  ip_cidr_range = var.private_subnets[count.index]
  region        = var.gcp_region
  network       = google_compute_network.vpc.id
  
  private_ip_google_access = true
  
  secondary_range {
    range_name    = "${var.project_name}-pods-${count.index + 1}"
    ip_cidr_range = var.pod_ip_ranges[count.index]
  }
  
  secondary_range {
    range_name    = "${var.project_name}-services-${count.index + 1}"
    ip_cidr_range = var.service_ip_ranges[count.index]
  }
}

# Subnets publiques
resource "google_compute_subnetwork" "public" {
  count = length(var.public_subnets)
  
  name          = "${var.project_name}-public-subnet-${count.index + 1}"
  ip_cidr_range = var.public_subnets[count.index]
  region        = var.gcp_region
  network       = google_compute_network.vpc.id
}

# GKE Cluster sécurisé
resource "google_container_cluster" "primary" {
  name     = "${var.project_name}-cluster"
  location = var.gcp_region
  
  # Configuration de sécurité
  min_master_version = var.kubernetes_version
  initial_node_count = 1
  
  # Configuration réseau
  network    = google_compute_network.vpc.name
  subnetwork = google_compute_subnetwork.private[0].name
  
  # Configuration de sécurité
  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }
  
  # Configuration de chiffrement
  database_encryption {
    state    = "ENCRYPTED"
    key_name = google_kms_crypto_key.gke.self_link
  }
  
  # Configuration de sécurité
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "0.0.0.0/0"
      display_name = "All"
    }
  }
  
  # Configuration des nœuds
  node_config {
    machine_type = var.machine_type
    disk_size_gb = 50
    disk_type    = "pd-ssd"
    
    # Configuration de sécurité
    service_account = google_service_account.gke_node.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    
    # Labels et taints
    labels = {
      environment = var.environment
      security    = "high"
    }
    
    taint {
      key    = "security.ghost-cyber-universe.com/scan"
      value  = "required"
      effect = "NO_SCHEDULE"
    }
    
    # Configuration de sécurité
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }
  
  # Configuration des add-ons
  addons_config {
    horizontal_pod_autoscaling {
      disabled = false
    }
    
    network_policy_config {
      disabled = false
    }
    
    http_load_balancing {
      disabled = false
    }
  }
  
  # Configuration de sécurité
  network_policy {
    enabled = true
  }
  
  # Configuration de monitoring
  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS", "APISERVER", "CONTROLLER_MANAGER", "SCHEDULER"]
  }
  
  # Configuration de logging
  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "APISERVER", "CONTROLLER_MANAGER", "SCHEDULER"]
  }
  
  # Configuration des nœuds
  node_pool {
    name       = "${var.project_name}-nodes"
    node_count = 3
    
    node_config {
      machine_type = var.machine_type
      disk_size_gb = 50
      disk_type    = "pd-ssd"
      
      service_account = google_service_account.gke_node.email
      oauth_scopes = [
        "https://www.googleapis.com/auth/cloud-platform"
      ]
      
      labels = {
        environment = var.environment
        security    = "high"
      }
      
      taint {
        key    = "security.ghost-cyber-universe.com/scan"
        value  = "required"
        effect = "NO_SCHEDULE"
      }
      
      shielded_instance_config {
        enable_secure_boot          = true
        enable_integrity_monitoring = true
      }
    }
    
    autoscaling {
      min_node_count = 2
      max_node_count = 10
    }
    
    management {
      auto_repair  = true
      auto_upgrade = true
    }
  }
  
  # Configuration de sécurité
  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }
  
  # Configuration de sécurité
  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }
  
  depends_on = [
    google_project_service.container,
    google_project_service.compute,
    google_project_service.monitoring
  ]
}

# Service Account pour GKE
resource "google_service_account" "gke_node" {
  account_id   = "${var.project_name}-gke-node"
  display_name = "GKE Node Service Account"
  
  depends_on = [google_project_service.iam]
}

# IAM Binding pour GKE Node
resource "google_project_iam_member" "gke_node" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/monitoring.viewer",
    "roles/stackdriver.resourceMetadata.writer",
    "roles/storage.objectViewer"
  ])
  
  project = var.gcp_project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.gke_node.email}"
}

# KMS Key pour GKE
resource "google_kms_key_ring" "gke" {
  name     = "${var.project_name}-gke-keyring"
  location = var.gcp_region
  
  depends_on = [google_project_service.kms]
}

resource "google_kms_crypto_key" "gke" {
  name     = "${var.project_name}-gke-key"
  key_ring = google_kms_key_ring.gke.id
  
  rotation_period = "7776000s" # 90 days
  
  version_template {
    algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  }
}

# IAM Binding pour KMS
resource "google_kms_crypto_key_iam_member" "gke" {
  crypto_key_id = google_kms_crypto_key.gke.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.project.number}@container-engine-robot.iam.gserviceaccount.com"
}

# Cloud SQL Database sécurisé
resource "google_sql_database_instance" "main" {
  name             = "${var.project_name}-db"
  database_version = "POSTGRES_15"
  region           = var.gcp_region
  
  settings {
    tier = var.db_instance_class
    
    # Configuration de sécurité
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
      require_ssl     = true
    }
    
    # Configuration de sauvegarde
    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      location                       = var.gcp_region
      point_in_time_recovery_enabled = true
      transaction_log_retention_days  = 7
      backup_retention_settings {
        retained_backups = 7
        retention_unit   = "COUNT"
      }
    }
    
    # Configuration de maintenance
    maintenance_window {
      day          = 7
      hour         = 3
      update_track = "stable"
    }
    
    # Configuration de sécurité
    database_flags {
      name  = "log_statement"
      value = "all"
    }
    
    database_flags {
      name  = "log_min_duration_statement"
      value = "1000"
    }
    
    database_flags {
      name  = "log_connections"
      value = "on"
    }
    
    database_flags {
      name  = "log_disconnections"
      value = "on"
    }
    
    # Configuration de chiffrement
    disk_encryption_configuration {
      kms_key_name = google_kms_crypto_key.sql.self_link
    }
    
    # Configuration de monitoring
    insights_config {
      query_insights_enabled  = true
      query_string_length     = 1024
      record_application_tags = true
      record_client_address   = true
    }
  }
  
  deletion_protection = true
  
  depends_on = [
    google_project_service.sql,
    google_project_service.kms
  ]
}

# KMS Key pour Cloud SQL
resource "google_kms_crypto_key" "sql" {
  name     = "${var.project_name}-sql-key"
  key_ring = google_kms_key_ring.gke.id
  
  rotation_period = "7776000s" # 90 days
  
  version_template {
    algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  }
}

# IAM Binding pour Cloud SQL KMS
resource "google_kms_crypto_key_iam_member" "sql" {
  crypto_key_id = google_kms_crypto_key.sql.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_project_service.sql.email}"
}

# Database
resource "google_sql_database" "main" {
  name     = "ghost_cyber_universe"
  instance = google_sql_database_instance.main.name
}

# User
resource "google_sql_user" "main" {
  name     = "ghost_cyber_universe"
  instance = google_sql_database_instance.main.name
  password = var.db_password
}

# Cloud Storage Bucket sécurisé
resource "google_storage_bucket" "logs" {
  name          = "${var.project_name}-logs-${random_id.bucket_suffix.hex}"
  location      = var.gcp_region
  storage_class = "REGIONAL"
  
  # Configuration de sécurité
  uniform_bucket_level_access = true
  
  # Configuration de versioning
  versioning {
    enabled = true
  }
  
  # Configuration de lifecycle
  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }
  
  # Configuration de chiffrement
  encryption {
    default_kms_key_name = google_kms_crypto_key.storage.self_link
  }
  
  # Configuration de sécurité
  cors {
    origin          = ["https://ghost-cyber-universe.com"]
    method          = ["GET", "POST", "PUT", "DELETE"]
    response_header = ["*"]
    max_age_seconds = 3600
  }
  
  depends_on = [google_project_service.storage]
}

# KMS Key pour Cloud Storage
resource "google_kms_crypto_key" "storage" {
  name     = "${var.project_name}-storage-key"
  key_ring = google_kms_key_ring.gke.id
  
  rotation_period = "7776000s" # 90 days
  
  version_template {
    algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"
  }
}

# IAM Binding pour Cloud Storage KMS
resource "google_kms_crypto_key_iam_member" "storage" {
  crypto_key_id = google_kms_crypto_key.storage.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_project_service.storage.email}"
}

# Random ID pour les buckets
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Data source pour le projet
data "google_project" "project" {
  project_id = var.gcp_project_id
}

# Services requis
resource "google_project_service" "compute" {
  service = "compute.googleapis.com"
}

resource "google_project_service" "container" {
  service = "container.googleapis.com"
}

resource "google_project_service" "iam" {
  service = "iam.googleapis.com"
}

resource "google_project_service" "kms" {
  service = "cloudkms.googleapis.com"
}

resource "google_project_service" "sql" {
  service = "sqladmin.googleapis.com"
}

resource "google_project_service" "storage" {
  service = "storage.googleapis.com"
}

resource "google_project_service" "monitoring" {
  service = "monitoring.googleapis.com"
}
