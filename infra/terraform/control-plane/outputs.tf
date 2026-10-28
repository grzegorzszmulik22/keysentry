output "service_uri" {
  description = "Public Cloud Run service URI; every route authenticates its own callers."
  value       = google_cloud_run_v2_service.control_plane.uri
}

output "ciphertext_bucket_name" {
  description = "Private versioned bucket holding accounts, sessions by hash, ownership and relay ciphertext."
  value       = google_storage_bucket.ciphertext.name
}

output "service_account_email" {
  description = "Dedicated control-plane identity with object access to its bucket and read access to two Stripe entries."
  value       = google_service_account.control_plane.email
}
