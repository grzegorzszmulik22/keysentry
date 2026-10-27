variable "project_id" {
  description = "Customer-owned Google Cloud project containing this pool, provider and KMS key."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be the customer's Google Cloud project ID of 6 to 30 characters."
  }
}

variable "location" {
  description = "Location of the customer's sealing key ring; independent of the global identity pool."
  type        = string
  default     = "global"
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,62}$", var.location))
    error_message = "location must be a Google Cloud KMS location such as global or us-central1."
  }
}

variable "name_prefix" {
  description = "Short prefix for the customer's key-ring and workload-identity pool names."
  type        = string
  default     = "keysentry-byo"
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,18}[a-z0-9]$", var.name_prefix)) && !startswith(var.name_prefix, "gcp-")
    error_message = "name_prefix must be 4 to 20 lowercase letters, digits or hyphens, starting with a letter, ending with a letter or digit, and not starting with gcp-."
  }
}

variable "box_project_id" {
  description = "Verified keysentry box project ID from the box module; this is not the customer's key project."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.box_project_id))
    error_message = "box_project_id must be the approved box project's Google Cloud project ID."
  }
}

variable "box_service_account_email" {
  description = "Exact verified keysentry box service account email, pinned in the attestation release policy."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\\.iam\\.gserviceaccount\\.com$", var.box_service_account_email))
    error_message = "box_service_account_email must be a full Google Cloud service account email."
  }
}

variable "allowed_image_digests" {
  description = "Customer-approved sha256 digests from the verified signed allow-list; keysentry cannot edit these grants."
  type        = set(string)
  nullable    = false
  validation {
    condition     = length(var.allowed_image_digests) > 0 && alltrue([for digest in var.allowed_image_digests : can(regex("^sha256:[a-f0-9]{64}$", digest))])
    error_message = "allowed_image_digests must contain at least one sha256 digest with 64 lowercase hexadecimal characters."
  }
}
