output "service_uri" {
  description = "Authenticated Cloud Run service URI; no public invoker grant is provisioned."
  value       = google_cloud_run_v2_service.control_plane.uri
}

output "ciphertext_bucket_name" {
  description = "Private versioned bucket for ciphertext blobs and signed documents."
  value       = google_storage_bucket.ciphertext.name
}

output "service_account_email" {
  description = "Dedicated control-plane identity with access only to objects in the ciphertext bucket."
  value       = google_service_account.control_plane.email
}
