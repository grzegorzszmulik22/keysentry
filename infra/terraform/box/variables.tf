variable "project_id" {
  description = "Existing dedicated Google Cloud project that owns the box VM and standard sealing key."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a Google Cloud project ID of 6 to 30 characters."
  }
}

variable "region" {
  description = "Region for the box subnet, router and standard sealing key."
  type        = string
  default     = "us-central1"
  nullable    = false
  validation {
    condition     = can(regex("^[a-z]+(-[a-z]+)+[0-9]+$", var.region))
    error_message = "region must be a Google Cloud region such as us-central1."
  }
}

variable "zone" {
  description = "Zone in the selected region with capacity for the chosen confidential VM type."
  type        = string
  default     = "us-central1-a"
  nullable    = false
  validation {
    condition     = can(regex("^[a-z]+(-[a-z]+)+[0-9]+-[a-z]$", var.zone))
    error_message = "zone must be a Google Cloud zone such as us-central1-a."
  }
}

variable "name_prefix" {
  description = "Short prefix for box network, identity, VM and key-ring resource names."
  type        = string
  default     = "keysentry-box"
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,18}[a-z0-9]$", var.name_prefix)) && !startswith(var.name_prefix, "gcp-")
    error_message = "name_prefix must be 4 to 20 lowercase letters, digits or hyphens, starting with a letter, ending with a letter or digit, and not starting with gcp-."
  }
}

variable "subnet_cidr" {
  description = "IPv4 CIDR reserved for the isolated box subnet."
  type        = string
  default     = "10.74.0.0/24"
  nullable    = false
  validation {
    condition     = can(cidrnetmask(var.subnet_cidr))
    error_message = "subnet_cidr must be a valid IPv4 CIDR."
  }
}

variable "confidential_type" {
  description = "Confidential Space hardware: TDX uses c3-standard-4; SEV uses n2d-standard-2 on AMD Milan."
  type        = string
  default     = "TDX"
  nullable    = false
  validation {
    condition     = contains(["TDX", "SEV"], var.confidential_type)
    error_message = "confidential_type must be TDX or SEV."
  }
}

variable "image_reference" {
  description = "Single-platform amd64 box container reference pinned to a published, allowed sha256 digest."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]+/[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$", var.image_reference))
    error_message = "image_reference must contain a registry, repository path and immutable @sha256 digest."
  }
}

variable "allowed_image_digests" {
  description = "Nonempty set of sha256 image digests from the verified, signed public allow-list; each receives a separate KMS grant."
  type        = set(string)
  nullable    = false
  validation {
    condition     = length(var.allowed_image_digests) > 0 && alltrue([for digest in var.allowed_image_digests : can(regex("^sha256:[a-f0-9]{64}$", digest))])
    error_message = "allowed_image_digests must contain at least one sha256 digest with 64 lowercase hexadecimal characters."
  }
}

variable "artifact_registry_project_id" {
  description = "Project owning the existing Artifact Registry repository used to pull the box image."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.artifact_registry_project_id))
    error_message = "artifact_registry_project_id must be a Google Cloud project ID of 6 to 30 characters."
  }
}

variable "artifact_registry_location" {
  description = "Region or multi-region of the existing box image repository."
  type        = string
  default     = "us-central1"
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,62}$", var.artifact_registry_location))
    error_message = "artifact_registry_location must be a lowercase Google Cloud region or multi-region."
  }
}

variable "artifact_registry_repository" {
  description = "Existing Artifact Registry repository ID; reader access is scoped to this repository."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z][a-z0-9_-]{0,62}$", var.artifact_registry_repository))
    error_message = "artifact_registry_repository must be a repository ID of up to 63 lowercase letters, digits, underscores or hyphens."
  }
}
