# Launch-ready scaffold only: this service has not been deployed.
resource "google_service_account" "control_plane" {
  project      = var.project_id
  account_id   = "${var.name_prefix}-run"
  display_name = "keysentry ciphertext control plane"
}

resource "google_storage_bucket" "ciphertext" {
  project                     = var.project_id
  name                        = var.bucket_name
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket_iam_member" "objects" {
  bucket = google_storage_bucket.ciphertext.name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.control_plane.email}"
}

resource "google_cloud_run_v2_service" "control_plane" {
  project             = var.project_id
  name                = var.name_prefix
  location            = var.region
  deletion_protection = true
  ingress             = "INGRESS_TRAFFIC_ALL"

  template {
    service_account                  = google_service_account.control_plane.email
    max_instance_request_concurrency = 40

    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }

    containers {
      image = var.image_reference

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "256Mi"
        }
      }
    }
  }

  depends_on = [google_storage_bucket_iam_member.objects]
}
