variable "project_id" {
  description = "Existing Google Cloud project for the separate control plane, never the customer KMS project."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a Google Cloud project ID of 6 to 30 characters."
  }
}

variable "region" {
  description = "Region for the control-plane Cloud Run service and ciphertext bucket."
  type        = string
  default     = "us-central1"
  nullable    = false
  validation {
    condition     = can(regex("^[a-z]+(-[a-z]+)+[0-9]+$", var.region))
    error_message = "region must be a Google Cloud region such as us-central1."
  }
}

variable "name_prefix" {
  description = "Short name for the control-plane service and its dedicated runtime account."
  type        = string
  default     = "keysentry-control"
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,18}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 3 to 20 lowercase letters, digits or hyphens, starting with a letter and ending with a letter or digit."
  }
}

variable "bucket_name" {
  description = "Globally unique private bucket name for encrypted blobs and signed relay documents only."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.bucket_name)) && !startswith(var.bucket_name, "goog") && !strcontains(var.bucket_name, "google")
    error_message = "bucket_name must be 3 to 63 lowercase letters, digits or hyphens, with alphanumeric ends and no reserved Google name."
  }
}

variable "image_reference" {
  description = "Control-plane container image pinned to an immutable published sha256 digest."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]+/[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$", var.image_reference))
    error_message = "image_reference must contain a registry, repository path and immutable @sha256 digest."
  }
}
