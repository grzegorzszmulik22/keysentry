resource "google_iam_workload_identity_pool" "box" {
  project                   = var.project_id
  workload_identity_pool_id = var.name_prefix
  display_name              = "keysentry customer key release"
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
    "assertion.submods.gce.project_id == '${var.box_project_id}'",
    "'${var.box_service_account_email}' in assertion.google_service_accounts",
  ])

  oidc {
    issuer_uri        = "https://confidentialcomputing.googleapis.com/"
    allowed_audiences = ["https://sts.googleapis.com"]
  }

  lifecycle {
    precondition {
      condition     = endswith(var.box_service_account_email, "@${var.box_project_id}.iam.gserviceaccount.com")
      error_message = "The approved box service account must belong to box_project_id."
    }
  }
}

resource "google_kms_key_ring" "seal" {
  project  = var.project_id
  name     = "${var.name_prefix}-seal"
  location = var.location

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

# The customer grants wrapping under the same attested identity and digest policy.
resource "google_kms_crypto_key_iam_member" "encrypt" {
  for_each      = var.allowed_image_digests
  crypto_key_id = google_kms_crypto_key.seal.id
  role          = "roles/cloudkms.cryptoKeyEncrypter"
  member        = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.box.name}/attribute.image_digest/${each.value}"
}
