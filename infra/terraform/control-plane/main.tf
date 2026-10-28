# Not deployed. A public HTTPS service (browsers, the CLI, boxes and Stripe call it directly; every route authenticates
# its own caller) whose state lives in one private bucket. Live box provisioning is not granted here.
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

  # Overwritten and deleted records (sessions, queues, expired ciphertext) do not linger as old versions.
  lifecycle_rule {
    condition {
      with_state                 = "ARCHIVED"
      days_since_noncurrent_time = 7
    }
    action {
      type = "Delete"
    }
  }

  # Backstop for the relay's own expiry: blobs live at most 24 hours, queued messages ten minutes and sessions
  # twelve hours, so anything older is unreachable.
  lifecycle_rule {
    condition {
      age            = 2
      matches_prefix = ["blobs/", "relay/", "sessions/"]
    }
    action {
      type = "Delete"
    }
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

# The Stripe webhook signing secret and restricted API key are created out of band; only read access is granted.
resource "google_secret_manager_secret_iam_member" "stripe" {
  for_each  = toset([var.stripe_webhook_secret_id, var.stripe_api_key_secret_id])
  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.control_plane.email}"
}

resource "google_cloud_run_v2_service" "control_plane" {
  project             = var.project_id
  name                = var.name_prefix
  location            = var.region
  deletion_protection = true
  ingress             = "INGRESS_TRAFFIC_ALL"
  # Public invoker: passkey sessions, box attestation tokens and Stripe signatures authenticate each route.
  invoker_iam_disabled = true

  template {
    service_account                  = google_service_account.control_plane.email
    max_instance_request_concurrency = 20

    # One instance: per-box and per-account work is serialized in process and the bucket has no compare-and-swap.
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
          memory = "512Mi"
        }
      }

      env {
        name  = "KEYSENTRY_CONTROL_ORIGIN"
        value = var.public_origin
      }
      env {
        name  = "KEYSENTRY_CONTROL_BUCKET"
        value = google_storage_bucket.ciphertext.name
      }
      env {
        name  = "KEYSENTRY_STRIPE_PRICE_ID"
        value = var.stripe_price_id
      }
      env {
        name  = "KEYSENTRY_BOX_PROJECT_ID"
        value = var.box_project_id
      }
      env {
        name  = "KEYSENTRY_BOX_SERVICE_ACCOUNT"
        value = var.box_service_account_email
      }
      env {
        name  = "KEYSENTRY_BOX_ALLOWED_DIGESTS"
        value = join(",", sort(tolist(var.allowed_image_digests)))
      }
      env {
        name  = "KEYSENTRY_TRUSTED_PROXY_HOPS"
        value = tostring(var.trusted_proxy_hops)
      }
      env {
        name = "KEYSENTRY_STRIPE_WEBHOOK_SECRET"
        value_source {
          secret_key_ref {
            secret  = var.stripe_webhook_secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "KEYSENTRY_STRIPE_API_KEY"
        value_source {
          secret_key_ref {
            secret  = var.stripe_api_key_secret_id
            version = "latest"
          }
        }
      }
    }
  }

  depends_on = [google_storage_bucket_iam_member.objects, google_secret_manager_secret_iam_member.stripe]
}
