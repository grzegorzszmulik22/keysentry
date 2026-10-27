output "workload_identity_provider_audience" {
  description = "STS exchange audience in the customer's project; share with the verified box configuration."
  value       = "//iam.googleapis.com/${google_iam_workload_identity_pool_provider.box.name}"
}

output "kms_key_name" {
  description = "Customer-owned KMS resource name used to wrap data keys."
  value       = google_kms_crypto_key.seal.id
}

output "box_identity" {
  description = "Approved external box project and service account for CLI attestation policy."
  value = {
    project_id            = var.box_project_id
    service_account_email = var.box_service_account_email
  }
}
