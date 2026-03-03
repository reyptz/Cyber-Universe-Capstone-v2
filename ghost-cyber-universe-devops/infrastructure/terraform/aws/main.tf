# Infrastructure AWS pour Ghost Cyber Universe
# Configuration sécurisée avec Terraform

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
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
  
  # Backend S3 sécurisé
  backend "s3" {
    bucket         = "ghost-cyber-universe-terraform-state"
    key            = "aws/terraform.tfstate"
    region         = "us-west-2"
    encrypt        = true
    kms_key_id     = "alias/ghost-cyber-universe-terraform"
    dynamodb_table = "ghost-cyber-universe-terraform-locks"
  }
}

# Provider AWS
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "Ghost Cyber Universe"
      Environment = var.environment
      Security    = "High"
      Compliance  = "Required"
      ManagedBy   = "Terraform"
    }
  }
}

# Provider Kubernetes
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  token                  = data.aws_eks_cluster_auth.cluster.token
}

# Provider Helm
provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.cluster.token
  }
}

# Data sources
data "aws_eks_cluster_auth" "cluster" {
  name = module.eks.cluster_name
}

data "aws_availability_zones" "available" {
  state = "available"
}

# VPC sécurisé
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  
  name = "${var.project_name}-vpc"
  cidr = var.vpc_cidr
  
  azs             = data.aws_availability_zones.available.names
  private_subnets = var.private_subnets
  public_subnets  = var.public_subnets
  
  enable_nat_gateway   = true
  enable_vpn_gateway  = true
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  # Tags pour la sécurité
  tags = {
    Name        = "${var.project_name}-vpc"
    Environment = var.environment
    Security    = "High"
  }
}

# EKS Cluster sécurisé
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"
  
  cluster_name    = "${var.project_name}-cluster"
  cluster_version = var.kubernetes_version
  
  vpc_id                         = module.vpc.vpc_id
  subnet_ids                     = module.vpc.private_subnets
  cluster_endpoint_public_access = true
  cluster_endpoint_private_access = true
  
  # Configuration de sécurité
  cluster_encryption_config = {
    provider_key_arn = aws_kms_key.eks.arn
    resources        = ["secrets"]
  }
  
  # Node groups sécurisés
  eks_managed_node_groups = {
    main = {
      name = "${var.project_name}-nodes"
      
      instance_types = var.instance_types
      capacity_type  = "ON_DEMAND"
      
      min_size     = 2
      max_size     = 10
      desired_size = 3
      
      # Configuration de sécurité
      ami_type = "AL2_x86_64"
      disk_size = 50
      
      # Labels et taints
      labels = {
        Environment = var.environment
        Security    = "High"
      }
      
      taints = [
        {
          key    = "security.ghost-cyber-universe.com/scan"
          value  = "required"
          effect = "NO_SCHEDULE"
        }
      ]
      
      # Configuration de sécurité
      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size = 50
            volume_type = "gp3"
            encrypted   = true
            kms_key_id  = aws_kms_key.eks.arn
          }
        }
      }
    }
  }
  
  # Add-ons sécurisés
  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
    aws-ebs-csi-driver = {
      most_recent = true
    }
  }
  
  # Tags
  tags = {
    Name        = "${var.project_name}-eks"
    Environment = var.environment
    Security    = "High"
  }
}

# KMS Key pour EKS
resource "aws_kms_key" "eks" {
  description             = "KMS key for EKS cluster encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = {
    Name        = "${var.project_name}-eks-kms"
    Environment = var.environment
    Security    = "High"
  }
}

# KMS Key pour S3
resource "aws_kms_key" "s3" {
  description             = "KMS key for S3 bucket encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = {
    Name        = "${var.project_name}-s3-kms"
    Environment = var.environment
    Security    = "High"
  }
}

# S3 Bucket pour les logs
resource "aws_s3_bucket" "logs" {
  bucket = "${var.project_name}-logs-${random_id.bucket_suffix.hex}"
  
  tags = {
    Name        = "${var.project_name}-logs"
    Environment = var.environment
    Security    = "High"
  }
}

# S3 Bucket versioning
resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# S3 Bucket public access block
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# RDS Database sécurisé
module "rds" {
  source = "terraform-aws-modules/rds/aws"
  version = "~> 6.0"
  
  identifier = "${var.project_name}-db"
  
  engine            = "postgres"
  engine_version    = "15.4"
  instance_class    = var.db_instance_class
  allocated_storage = 100
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
  
  db_name  = "ghost_cyber_universe"
  username = "ghost_cyber_universe"
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = false
  final_snapshot_identifier = "${var.project_name}-db-final-snapshot"
  
  tags = {
    Name        = "${var.project_name}-db"
    Environment = var.environment
    Security    = "High"
  }
}

# KMS Key pour RDS
resource "aws_kms_key" "rds" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = {
    Name        = "${var.project_name}-rds-kms"
    Environment = var.environment
    Security    = "High"
  }
}

# Security Group pour RDS
resource "aws_security_group" "rds" {
  name_prefix = "${var.project_name}-rds-"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name        = "${var.project_name}-rds-sg"
    Environment = var.environment
    Security    = "High"
  }
}

# DB Subnet Group
resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-db-subnet-group"
  subnet_ids = module.vpc.private_subnets
  
  tags = {
    Name        = "${var.project_name}-db-subnet-group"
    Environment = var.environment
    Security    = "High"
  }
}

# Random ID pour les buckets
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "eks" {
  name              = "/aws/eks/${var.project_name}-cluster/cluster"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.eks.arn
  
  tags = {
    Name        = "${var.project_name}-eks-logs"
    Environment = var.environment
    Security    = "High"
  }
}

# IAM Role pour EKS
resource "aws_iam_role" "eks_cluster" {
  name = "${var.project_name}-eks-cluster-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Name        = "${var.project_name}-eks-cluster-role"
    Environment = var.environment
    Security    = "High"
  }
}

# IAM Policy pour EKS
resource "aws_iam_role_policy_attachment" "eks_cluster" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

# IAM Role pour EKS Node Group
resource "aws_iam_role" "eks_node_group" {
  name = "${var.project_name}-eks-node-group-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Name        = "${var.project_name}-eks-node-group-role"
    Environment = var.environment
    Security    = "High"
  }
}

# IAM Policies pour EKS Node Group
resource "aws_iam_role_policy_attachment" "eks_node_group" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  ])
  
  policy_arn = each.value
  role       = aws_iam_role.eks_node_group.name
}
