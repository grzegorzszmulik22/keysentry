resource "google_compute_network" "box" {
  project                 = var.project_id
  name                    = "${var.name_prefix}-network"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "box" {
  project                  = var.project_id
  name                     = "${var.name_prefix}-subnet"
  region                   = var.region
  network                  = google_compute_network.box.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true
}

resource "google_compute_router" "box" {
  project = var.project_id
  name    = "${var.name_prefix}-router"
  region  = var.region
  network = google_compute_network.box.id
}

resource "google_compute_router_nat" "box" {
  project                            = var.project_id
  name                               = "${var.name_prefix}-nat"
  region                             = var.region
  router                             = google_compute_router.box.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

resource "google_compute_firewall" "deny_ingress" {
  project       = var.project_id
  name          = "${var.name_prefix}-deny-ingress"
  network       = google_compute_network.box.id
  direction     = "INGRESS"
  priority      = 0
  source_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }
}

resource "google_service_account" "box" {
  project      = var.project_id
  account_id   = "${var.name_prefix}-vm"
  display_name = "keysentry confidential box"
}

resource "google_project_iam_member" "attestation" {
  project = var.project_id
  role    = "roles/confidentialcomputing.workloadUser"
  member  = "serviceAccount:${google_service_account.box.email}"
}

resource "google_artifact_registry_repository_iam_member" "image_reader" {
  project    = var.artifact_registry_project_id
  location   = var.artifact_registry_location
  repository = var.artifact_registry_repository
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.box.email}"
}

resource "google_iam_workload_identity_pool" "box" {
  project                   = var.project_id
  workload_identity_pool_id = var.name_prefix
  display_name              = "keysentry box key release"
}

resource "google_iam_workload_identity_pool_provider" "box" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.box.workload_identity_pool_id
  workload_identity_pool_provider_id = "attestation-verifier"

  attribute_mapping = {
    "google.subject"         = "'gcpcs::' + assertion.submods.container.image_digest + '::' + assertion.submods.gce.project_number + '::' + assertion.submods.gce.instance_id"
    "attribute.image_digest" = "assertion.submods.container.image_digest"
  }
  attribute_condition = join(" && ", [
    "assertion.swname == 'CONFIDENTIAL_SPACE'",
    "'STABLE' in assertion.submods.confidential_space.support_attributes",
    "assertion.dbgstat == 'disabled-since-boot'",
    "assertion.submods.gce.project_id == '${var.project_id}'",
    "'${google_service_account.box.email}' in assertion.google_service_accounts",
  ])

  oidc {
    issuer_uri        = "https://confidentialcomputing.googleapis.com/"
    allowed_audiences = ["https://sts.googleapis.com"]
  }
}

resource "google_kms_key_ring" "seal" {
  project  = var.project_id
  name     = "${var.name_prefix}-seal"
  location = var.region

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "seal" {
  name                       = "token-bundle"
  key_ring                   = google_kms_key_ring.seal.id
  purpose                    = "ENCRYPT_DECRYPT"
  rotation_period            = "7776000s"
  destroy_scheduled_duration = "2592000s"
  deletion_policy            = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "decrypt" {
  for_each      = var.allowed_image_digests
  crypto_key_id = google_kms_crypto_key.seal.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.box.name}/attribute.image_digest/${each.value}"
}

# Wrapping a fresh data key needs encrypt permission under exactly the same policy.
resource "google_kms_crypto_key_iam_member" "encrypt" {
  for_each      = var.allowed_image_digests
  crypto_key_id = google_kms_crypto_key.seal.id
  role          = "roles/cloudkms.cryptoKeyEncrypter"
  member        = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.box.name}/attribute.image_digest/${each.value}"
}

resource "google_compute_instance" "box" {
  project                   = var.project_id
  name                      = var.name_prefix
  zone                      = var.zone
  machine_type              = var.confidential_type == "TDX" ? "c3-standard-4" : "n2d-standard-2"
  min_cpu_platform          = var.confidential_type == "SEV" ? "AMD Milan" : null
  allow_stopping_for_update = true

  confidential_instance_config {
    enable_confidential_compute = true
    confidential_instance_type  = var.confidential_type
  }

  shielded_instance_config {
    enable_secure_boot = true
  }

  scheduling {
    on_host_maintenance = var.confidential_type == "TDX" ? "TERMINATE" : "MIGRATE"
    automatic_restart   = true
  }

  boot_disk {
    initialize_params {
      image = "projects/confidential-space-images/global/images/family/confidential-space"
      type  = "pd-balanced"
      size  = 20
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.box.id
  }

  service_account {
    email  = google_service_account.box.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    "tee-image-reference" = var.image_reference
    "tee-restart-policy"  = "Always"
  }

  lifecycle {
    precondition {
      condition     = contains(var.allowed_image_digests, split("@", var.image_reference)[1])
      error_message = "The box image digest must be present in allowed_image_digests."
    }
    precondition {
      condition     = startswith(var.zone, "${var.region}-")
      error_message = "The box zone must be in the subnet region."
    }
  }

  depends_on = [
    google_compute_firewall.deny_ingress,
    google_compute_router_nat.box,
    google_project_iam_member.attestation,
    google_artifact_registry_repository_iam_member.image_reader,
    google_iam_workload_identity_pool_provider.box,
    google_kms_crypto_key_iam_member.decrypt,
    google_kms_crypto_key_iam_member.encrypt,
  ]
}
