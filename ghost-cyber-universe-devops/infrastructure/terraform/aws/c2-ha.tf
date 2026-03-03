# C2 High Availability Infrastructure
# Cloud Security Engineer - IAM, encryption, network security

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket = "ghost-cyber-universe-terraform"
    key    = "c2-ha/terraform.tfstate"
    region = "us-east-1"
    encrypt = true
    dynamodb_table = "terraform-locks"
  }
}

# VPC with network security
resource "aws_vpc" "c2_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "ghost-c2-vpc"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

# Security groups with strict rules
resource "aws_security_group" "c2_sg" {
  name_prefix = "c2-"
  vpc_id      = aws_vpc.c2_vpc.id

  # Only allow required ports with source restrictions
  ingress {
    description = "C2 API from trusted IPs"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = var.trusted_ip_ranges
  }

  ingress {
    description = "SSH from bastion"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.bastion_ip]
  }

  egress {
    description = "Outbound HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ghost-c2-sg"
  }
}

# IAM roles with least privilege
resource "aws_iam_role" "c2_role" {
  name = "ghost-c2-server-role"
  
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
    Name = "ghost-c2-role"
  }
}

resource "aws_iam_policy" "c2_policy" {
  name        = "ghost-c2-policy"
  description = "Minimal permissions for C2 servers"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = var.kms_key_arn
      }
    ]
  })
}

# KMS for encryption at rest
resource "aws_kms_key" "c2_kms" {
  description             = "C2 encryption key"
  deletion_window_in_days = 7
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "ghost-c2-kms"
  }
}

# EC2 instances with encryption
resource "aws_instance" "c2_primary" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.medium"
  
  subnet_id                   = aws_subnet.c2_private.id
  vpc_security_group_ids      = [aws_security_group.c2_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.c2_profile.name
  
  # Encryption at rest
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted            = true
    kms_key_id           = aws_kms_key.c2_kms.arn
    delete_on_termination = true
  }

  user_data = base64encode(templatefile("${path.module}/user-data.sh", {
    kms_key_id = aws_kms_key.c2_kms.key_id
  }))

  tags = {
    Name        = "ghost-c2-primary"
    Environment = "production"
    Role        = "primary"
  }
}

# Auto Scaling for HA
resource "aws_autoscaling_group" "c2_asg" {
  name                = "ghost-c2-asg"
  vpc_zone_identifier  = [aws_subnet.c2_private.id]
  desired_capacity    = 3
  max_size           = 5
  min_size           = 2
  
  launch_template {
    id      = aws_launch_template.c2_lt.id
    version = "$Latest"
  }

  health_check_type   = "EC2"
  health_check_grace_period = 300

  tag {
    key                 = "Name"
    value               = "ghost-c2-asg"
    propagate_at_launch = true
  }
}

# Application Load Balancer
resource "aws_lb" "c2_alb" {
  name               = "ghost-c2-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.c2_sg.id]
  subnets           = [aws_subnet.c2_public.id]

  enable_deletion_protection = false

  tags = {
    Name = "ghost-c2-alb"
  }
}

# Target group for C2 servers
resource "aws_lb_target_group" "c2_tg" {
  name     = "ghost-c2-tg"
  port     = 8000
  protocol = "HTTP"
  vpc_id   = aws_vpc.c2_vpc.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval           = 5
    matcher           = "200"
    path              = "/health"
    port              = "traffic-port"
    protocol          = "HTTP"
    timeout           = 3
    unhealthy_threshold = 2
  }

  tags = {
    Name = "ghost-c2-tg"
  }
}

# Variables
variable "trusted_ip_ranges" {
  description = "CIDR blocks allowed to access C2"
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

variable "bastion_ip" {
  description = "Bastion host IP for SSH access"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN for encryption"
  type        = string
}
