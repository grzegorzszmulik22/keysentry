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

variable "public_origin" {
  description = "Public HTTPS origin browsers, the CLI, boxes and Stripe use; passkeys and box tokens are bound to it."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?([.][a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", var.public_origin))
    error_message = "public_origin must be an https:// origin with a host name and no path, port or trailing slash."
  }
}

variable "stripe_price_id" {
  description = "The one Stripe price whose active subscription grants the paid plan."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^price_[A-Za-z0-9_]{1,120}$", var.stripe_price_id))
    error_message = "stripe_price_id must be a Stripe price ID such as price_123."
  }
}

variable "stripe_webhook_secret_id" {
  description = "Existing Secret Manager secret ID holding the Stripe webhook signing secret (created outside Terraform)."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,255}$", var.stripe_webhook_secret_id))
    error_message = "stripe_webhook_secret_id must be a Secret Manager secret ID, not the secret value."
  }
}

variable "stripe_api_key_secret_id" {
  description = "Existing Secret Manager secret ID holding a Stripe restricted key: Checkout Sessions write, Subscriptions read."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,255}$", var.stripe_api_key_secret_id))
    error_message = "stripe_api_key_secret_id must be a Secret Manager secret ID, not the key value."
  }
}

variable "box_project_id" {
  description = "Project that runs keysentry boxes; a box's attestation token must name it."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.box_project_id))
    error_message = "box_project_id must be the box project's Google Cloud project ID."
  }
}

variable "box_service_account_email" {
  description = "Box VM service account; a box's attestation token must name exactly this account."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9][.]iam[.]gserviceaccount[.]com$", var.box_service_account_email))
    error_message = "box_service_account_email must be a full Google Cloud service account email."
  }
}

variable "allowed_image_digests" {
  description = "Box image digests from the verified signed allow-list; only boxes running one of them reach the relay."
  type        = set(string)
  nullable    = false
  validation {
    condition     = length(var.allowed_image_digests) > 0 && length(var.allowed_image_digests) <= 64 && alltrue([for digest in var.allowed_image_digests : can(regex("^sha256:[a-f0-9]{64}$", digest))])
    error_message = "allowed_image_digests must contain 1 to 64 sha256 digests with 64 lowercase hexadecimal characters."
  }
}

variable "trusted_proxy_hops" {
  description = "X-Forwarded-For entries appended by trusted Google front ends; the client is this many from the right."
  type        = number
  default     = 1
  nullable    = false
  validation {
    condition     = var.trusted_proxy_hops >= 1 && var.trusted_proxy_hops <= 10 && floor(var.trusted_proxy_hops) == var.trusted_proxy_hops
    error_message = "trusted_proxy_hops must be a whole number from 1 to 10 (2 behind an external Application Load Balancer)."
  }
}

variable "live_provisioning" {
  description = "Create boxes for paying accounts (KEYSENTRY_CONTROL_PLANE_LIVE=1) and grant the Compute rights that needs."
  type        = bool
  default     = false
  nullable    = false
  validation {
    condition     = var.live_provisioning == true || var.live_provisioning == false
    error_message = "live_provisioning must be true or false."
  }
}

variable "box_zone" {
  description = "Zone for new boxes, in the box subnet's region (live provisioning only)."
  type        = string
  default     = ""
  nullable    = false
  validation {
    condition     = var.box_zone == "" || can(regex("^[a-z]+(-[a-z]+)+[0-9]+-[a-z]$", var.box_zone))
    error_message = "box_zone must be a zone such as us-central1-a, or empty."
  }
}

variable "box_subnetwork" {
  description = "Existing private box subnet, projects/BOX_PROJECT/regions/REGION/subnetworks/NAME (live provisioning only)."
  type        = string
  default     = ""
  nullable    = false
  validation {
    condition     = var.box_subnetwork == "" || can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/regions/[a-z]+(-[a-z]+)+[0-9]+/subnetworks/[a-z]([a-z0-9-]{0,61}[a-z0-9])?$", var.box_subnetwork))
    error_message = "box_subnetwork must be a full subnetwork path, or empty."
  }
}

variable "box_image_reference" {
  description = "Box image pinned by digest; the digest must be in allowed_image_digests (live provisioning only)."
  type        = string
  default     = ""
  nullable    = false
  validation {
    condition     = var.box_image_reference == "" || can(regex("^[a-z0-9.-]+/[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$", var.box_image_reference))
    error_message = "box_image_reference must contain a registry, repository path and @sha256 digest, or be empty."
  }
}
