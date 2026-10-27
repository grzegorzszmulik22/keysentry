output "project_id" {
  description = "Expected GCE project ID for CLI attestation policy."
  value       = var.project_id
}

output "service_account_email" {
  description = "Expected box service account for CLI attestation and customer KMS policy."
  value       = google_service_account.box.email
}

output "workload_identity_provider_audience" {
  description = "STS exchange audience containing the pool owner's project number."
  value       = "//iam.googleapis.com/${google_iam_workload_identity_pool_provider.box.name}"
}

output "kms_key_name" {
  description = "Full KMS resource name used to wrap data keys."
  value       = google_kms_crypto_key.seal.id
}

output "instance_name" {
  description = "Name of the confidential box VM."
  value       = google_compute_instance.box.name
}

output "image_digest" {
  description = "Immutable container digest configured on the box."
  value       = split("@", var.image_reference)[1]
}
