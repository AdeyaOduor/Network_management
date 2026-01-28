# terraform-gcp/main.tf
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Service Account for Scanner
resource "google_service_account" "vulnerability_scanner" {
  account_id   = "vulnerability-scanner"
  display_name = "Vulnerability Scanner Service Account"
}

# IAM Roles for Scanner
resource "google_project_iam_member" "scanner_roles" {
  for_each = toset([
    "roles/compute.viewer",
    "roles/cloudsql.viewer",
    "roles/storage.objectViewer",
    "roles/container.clusterViewer",
    "roles/iam.securityReviewer",
    "roles/securitycenter.findingsViewer",
    "roles/cloudasset.viewer",
    "roles/osconfig.vulnerabilityReportsViewer",
    "roles/monitoring.metricWriter",
    "roles/logging.logWriter",
    "roles/bigquery.dataEditor",
    "roles/pubsub.publisher"
  ])
  
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.vulnerability_scanner.email}"
}

# Cloud Storage Bucket for Reports
resource "google_storage_bucket" "reports" {
  name     = "vulnerability-reports-${var.project_id}"
  location = var.region
  
  uniform_bucket_level_access = true
  
  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
  
  encryption {
    default_kms_key_name = google_kms_crypto_key.bucket_encryption.id
  }
}

# KMS Key for Encryption
resource "google_kms_key_ring" "security" {
  name     = "security-keys"
  location = var.region
}

resource "google_kms_crypto_key" "bucket_encryption" {
  name            = "bucket-encryption-key"
  key_ring        = google_kms_key_ring.security.id
  rotation_period = "7776000s" # 90 days
  
  lifecycle {
    prevent_destroy = false
  }
}

# BigQuery Dataset for Findings
resource "google_bigquery_dataset" "security_scanning" {
  dataset_id = "security_scanning"
  location   = var.region
  
  default_table_expiration_ms = 90 * 24 * 60 * 60 * 1000 # 90 days
  
  access {
    role          = "OWNER"
    user_by_email = google_service_account.vulnerability_scanner.email
  }
}

resource "google_bigquery_table" "vulnerability_findings" {
  dataset_id = google_bigquery_dataset.security_scanning.dataset_id
  table_id   = "vulnerability_findings"
  
  schema = <<EOF
[
  {
    "name": "scan_timestamp",
    "type": "TIMESTAMP",
    "mode": "REQUIRED"
  },
  {
    "name": "finding_id",
    "type": "STRING",
    "mode": "REQUIRED"
  },
  {
    "name": "severity",
    "type": "STRING",
    "mode": "REQUIRED"
  },
  {
    "name": "title",
    "type": "STRING",
    "mode": "REQUIRED"
  },
  {
    "name": "description",
    "type": "STRING",
    "mode": "NULLABLE"
  },
  {
    "name": "cvss_score",
    "type": "FLOAT",
    "mode": "NULLABLE"
  },
  {
    "name": "cve_id",
    "type": "STRING",
    "mode": "NULLABLE"
  },
  {
    "name": "affected_resource",
    "type": "STRING",
    "mode": "REQUIRED"
  },
  {
    "name": "resource_type",
    "type": "STRING",
    "mode": "REQUIRED"
  },
  {
    "name": "project_id",
    "type": "STRING",
    "mode": "REQUIRED"
  },
  {
    "name": "zone",
    "type": "STRING",
    "mode": "NULLABLE"
  },
  {
    "name": "detection_date",
    "type": "TIMESTAMP",
    "mode": "REQUIRED"
  },
  {
    "name": "category",
    "type": "STRING",
    "mode": "REQUIRED"
  },
  {
    "name": "remediation",
    "type": "STRING",
    "mode": "NULLABLE"
  },
  {
    "name": "references",
    "type": "STRING",
    "mode": "NULLABLE"
  }
]
EOF
  
  time_partitioning {
    type  = "DAY"
    field = "scan_timestamp"
  }
  
  clustering = ["severity", "resource_type", "project_id"]
}

# Pub/Sub Topic for Notifications
resource "google_pubsub_topic" "scan_results" {
  name = "vulnerability-scan-results"
  
  message_storage_policy {
    allowed_persistence_regions = [var.region]
  }
}

# Cloud Scheduler for Automated Scanning
resource "google_cloud_scheduler_job" "daily_scan" {
  name        = "daily-vulnerability-scan"
  description = "Daily vulnerability scan job"
  schedule    = "0 2 * * *" # Daily at 2 AM
  time_zone   = "UTC"
  
  pubsub_target {
    topic_name = google_pubsub_topic.scan_trigger.id
    data       = base64encode("{\"action\": \"start_scan\"}")
  }
}

resource "google_pubsub_topic" "scan_trigger" {
  name = "scan-trigger"
}

# Cloud Function for Scanner
resource "google_cloudfunctions_function" "vulnerability_scanner" {
  name        = "vulnerability-scanner"
  description = "GCP Vulnerability Scanner Function"
  runtime     = "python39"
  region      = var.region
  
  available_memory_mb   = 2048
  timeout               = 540
  entry_point           = "cloud_function_handler"
  
  source_archive_bucket = google_storage_bucket.function_code.name
  source_archive_object = google_storage_bucket_object.function_code.name
  
  service_account_email = google_service_account.vulnerability_scanner.email
  
  environment_variables = {
    CONFIG_PATH = "/workspace/config_gcp.yaml"
  }
  
  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.scan_trigger.id
  }
}

# Storage for Function Code
resource "google_storage_bucket" "function_code" {
  name     = "function-code-${var.project_id}"
  location = var.region
}

resource "google_storage_bucket_object" "function_code" {
  name   = "vulnerability-scanner.zip"
  bucket = google_storage_bucket.function_code.name
  source = "../vulnerability_scanner.zip"
}

# Cloud Monitoring Dashboard
resource "google_monitoring_dashboard" "security_dashboard" {
  dashboard_json = jsonencode({
    displayName = "Vulnerability Metrics"
    gridLayout = {
      columns = "2"
      widgets = [
        {
          title = "Vulnerabilities by Severity"
          xyChart = {
            dataSets = [
              {
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = 'metric.type="custom.googleapis.com/vulnerability/count" resource.type="global"'
                    aggregation = {
                      perSeriesAligner   = "ALIGN_SUM"
                      crossSeriesReducer = "REDUCE_SUM"
                      groupByFields      = ["metric.label.severity"]
                    }
                  }
                }
                plotType = "LINE"
              }
            ]
            timeshiftDuration = "0s"
            yAxis = {
              label = "Count"
              scale = "LINEAR"
            }
          }
        },
        {
          title = "Vulnerabilities by Resource Type"
          pieChart = {
            dataSets = [
              {
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = 'metric.type="custom.googleapis.com/vulnerability/count" resource.type="global"'
                    aggregation = {
                      perSeriesAligner   = "ALIGN_SUM"
                      crossSeriesReducer = "REDUCE_SUM"
                      groupByFields      = ["metric.label.resource_type"]
                    }
                  }
                }
              }
            ]
            chartType = "PIE"
          }
        }
      ]
    }
  })
}

# Variables
variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}
