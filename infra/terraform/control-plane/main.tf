# Not deployed. A public HTTPS service (browsers, the CLI, boxes and Stripe call it directly; every route authenticates
# its own caller) whose state lives in one private bucket. It runs Dockerfile.control-plane's image by digest. The
# Stripe credentials stay in Secret Manager: the service gets their references and reads them itself at startup.
# Live box provisioning, and the Compute rights it needs, exist only when live_provisioning = true.
locals {
  # Secret Manager references, read by the process through the metadata-server token (never secret values).
  stripe_webhook_secret_ref = "projects/${var.project_id}/secrets/${var.stripe_webhook_secret_id}/versions/latest"
  stripe_api_key_secret_ref = "projects/${var.project_id}/secrets/${var.stripe_api_key_secret_id}/versions/latest"

  live_env = var.live_provisioning ? {
    KEYSENTRY_CONTROL_PLANE_LIVE  = "1"
    KEYSENTRY_BOX_ZONE            = var.box_zone
    KEYSENTRY_BOX_SUBNETWORK      = var.box_subnetwork
    KEYSENTRY_BOX_IMAGE_REFERENCE = var.box_image_reference
  } : {}
}
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

  # Backstop for the relay's own expiry: queued messages live ten minutes and sessions twelve hours, so anything older
  # is unreachable. (The relay keeps no blobs.)
  lifecycle_rule {
    condition {
      age            = 2
      matches_prefix = ["relay/", "sessions/"]
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

# The Stripe webhook signing secret and restricted API key are created out of band; only read access is granted. The
# process reads them through the Secret Manager API at startup (secretmanager.versions.access).
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
      # The image's own entry (Dockerfile.control-plane), stated so another image's entrypoint cannot run instead.
      command = ["/nodejs/bin/node"]
      args    = ["/app/control-plane.mjs"]

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
        name  = "KEYSENTRY_STRIPE_WEBHOOK_SECRET_REF"
        value = local.stripe_webhook_secret_ref
      }
      env {
        name  = "KEYSENTRY_STRIPE_API_KEY_REF"
        value = local.stripe_api_key_secret_ref
      }
      dynamic "env" {
        for_each = local.live_env
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = !var.live_provisioning || (var.box_zone != "" && var.box_subnetwork != "" && var.box_image_reference != "")
      error_message = "live_provisioning needs box_zone, box_subnetwork and box_image_reference."
    }
    precondition {
      condition     = !var.live_provisioning || (startswith(var.box_subnetwork, "projects/${var.box_project_id}/regions/") && endswith(var.box_service_account_email, "@${var.box_project_id}.iam.gserviceaccount.com"))
      error_message = "The box subnetwork and service account must belong to box_project_id."
    }
    precondition {
      condition     = !var.live_provisioning || contains(var.allowed_image_digests, element(concat(split("@", var.box_image_reference), [""]), 1))
      error_message = "The box image digest must be in allowed_image_digests."
    }
  }

  depends_on = [
    google_storage_bucket_iam_member.objects,
    google_secret_manager_secret_iam_member.stripe,
    google_project_iam_member.provision,
    google_service_account_iam_member.box_user,
  ]
}

# Live provisioning only, in the box project, and nothing else: what instances.insert needs for the Terraform-shaped
# box (instance, boot disk, metadata, attached service account, existing subnet); instances.get to reconcile a
# reservation whose insert had no definite answer; instances.stop to stop the boxes of an account that stopped paying;
# instances.start for the owner's start request after paying again. It cannot delete or reconfigure an instance.
resource "google_project_iam_custom_role" "provision" {
  count       = var.live_provisioning ? 1 : 0
  project     = var.box_project_id
  role_id     = "${replace(var.name_prefix, "-", "_")}_provisioner"
  title       = "keysentry control plane box provisioner"
  description = "Creates, reads, stops and starts keysentry box instances; cannot delete or reconfigure them."
  permissions = [
    "compute.disks.create",
    "compute.instances.create",
    "compute.instances.get",
    "compute.instances.setMetadata",
    "compute.instances.setServiceAccount",
    "compute.instances.start",
    "compute.instances.stop",
    "compute.subnetworks.use",
  ]
}

resource "google_project_iam_member" "provision" {
  count   = var.live_provisioning ? 1 : 0
  project = var.box_project_id
  role    = google_project_iam_custom_role.provision[0].name
  member  = "serviceAccount:${google_service_account.control_plane.email}"
}

# Attaching the box service account to a new instance needs iam.serviceAccounts.actAs on that one account.
resource "google_service_account_iam_member" "box_user" {
  count              = var.live_provisioning ? 1 : 0
  service_account_id = "projects/${var.box_project_id}/serviceAccounts/${var.box_service_account_email}"
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.control_plane.email}"
}
