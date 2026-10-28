import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';
import { HOSTED_SETTINGS, hostedConfigFromEnv } from '../../packages/control-plane/src/hosted.js';

const root = new URL('../../infra/terraform/', import.meta.url);
const modules = ['box', 'byo-kms', 'control-plane'] as const;
const keyModules = ['box', 'byo-kms'] as const;

function source(module: string): string {
  const dir = new URL(`${module}/`, root);
  if (!existsSync(dir)) return '';
  return readdirSync(dir).filter(name => name.endsWith('.tf')).sort()
    .map(name => readFileSync(new URL(name, dir), 'utf8')).join('\n')
    .replace(/^\s*#.*$/gm, '');
}

function blocks(text: string, kind: string, type?: string): string[] {
  const labels = type === undefined ? '"[^"]+"' : `"${type}" "[^"]+"`;
  return [...text.matchAll(new RegExp(`^${kind} ${labels} \\{[\\s\\S]*?^\\}`, 'gm'))]
    .map(match => match[0]);
}

function resource(text: string, type: string): string {
  const found = blocks(text, 'resource', type);
  expect(found, `expected one ${type} resource`).toHaveLength(1);
  return found[0]!;
}

describe('cloud box Terraform (local static contracts; no Google calls)', () => {
  test.each(modules)('%s pins Google 8.9.0 and requires Terraform 1.6 or later', module => {
    const tf = source(module);
    expect(tf).toMatch(/required_version\s*=\s*">= 1\.6(?:\.0)?"/);
    expect(tf).toMatch(/required_providers\s*\{\s*google\s*=\s*\{\s*source\s*=\s*"hashicorp\/google"\s+version\s*=\s*"8\.9\.0"/);
    expect(tf).not.toMatch(/access_config\s*\{/);
    expect(tf).not.toContain('confidential-space-debug');
    expect(tf).not.toContain('tee-env-');
  });

  test.each(modules)('%s describes and validates every input and accepts no secret defaults', module => {
    const variables = blocks(source(module), 'variable');
    expect(variables.length).toBeGreaterThan(0);
    for (const variable of variables) {
      expect(variable).toMatch(/description\s*=\s*"[^"\n]+"/);
      expect(variable).toMatch(/validation\s*\{/);
      expect(variable).toMatch(/error_message\s*=\s*"[^"\n]+"/);
      expect(variable).toMatch(/nullable\s*=\s*false/);
      const name = variable.match(/^variable "([^"]+)"/)![1]!;
      if (/secret|token|password|credential|private_key/i.test(name) || /sensitive\s*=\s*true/.test(variable)) {
        expect(variable).not.toMatch(/^\s*default\s*=/m);
      }
    }
    // These modules provision identity and ciphertext storage, never secret material.
    expect(source(module)).not.toMatch(/resource "(?:google_service_account_key|google_secret_manager_secret_version|random_password|tls_private_key)"/);
  });

  test.each(keyModules)('%s releases only to production, stable workloads with both identity pins', module => {
    const provider = resource(source(module), 'google_iam_workload_identity_pool_provider');
    expect(provider).toMatch(/attribute_condition\s*=/);
    for (const clause of [
      "assertion.swname == 'CONFIDENTIAL_SPACE'",
      "'STABLE' in assertion.submods.confidential_space.support_attributes",
      "assertion.dbgstat == 'disabled-since-boot'",
    ]) expect(provider).toContain(clause);
    expect(provider).toContain(module === 'box'
      ? "assertion.submods.gce.project_id == '${var.project_id}'"
      : "assertion.submods.gce.project_id == '${var.box_project_id}'");
    expect(provider).toContain(module === 'box'
      ? "'${google_service_account.box.email}' in assertion.google_service_accounts"
      : "'${var.box_service_account_email}' in assertion.google_service_accounts");
    expect(provider).toMatch(/"attribute\.image_digest"\s*=\s*"assertion\.submods\.container\.image_digest"/);
    expect(provider).toContain('assertion.submods.gce.instance_id');
    expect(provider).toContain('assertion.submods.gce.project_number');
    expect(provider).not.toMatch(/"google\.subject"\s*=\s*"assertion\.sub"/);
    expect(provider).toMatch(/issuer_uri\s*=\s*"https:\/\/confidentialcomputing\.googleapis\.com\/?"/);
    expect(provider).toMatch(/allowed_audiences\s*=\s*\["https:\/\/sts\.googleapis\.com"\]/);
    expect(provider).not.toMatch(/\bLATEST\b|\|\|/);
  });

  test.each(keyModules)('%s grants encrypt and decrypt separately to each allowed digest, never the VM account', module => {
    const members = blocks(source(module), 'resource', 'google_kms_crypto_key_iam_member');
    expect(members).toHaveLength(2);
    for (const role of ['roles/cloudkms.cryptoKeyDecrypter', 'roles/cloudkms.cryptoKeyEncrypter']) {
      const grant = members.find(member => member.includes(`"${role}"`));
      expect(grant).toBeDefined();
      expect(grant).toMatch(/for_each\s*=\s*var\.allowed_image_digests/);
      expect(grant).toContain('principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.box.name}/attribute.image_digest/${each.value}');
      expect(grant).toMatch(/crypto_key_id\s*=\s*google_kms_crypto_key\.seal\.id/);
    }
    const digests = blocks(source(module), 'variable').find(block => block.startsWith('variable "allowed_image_digests"'))!;
    expect(digests).toMatch(/type\s*=\s*set\(string\)/);
    expect(digests).toContain('length(var.allowed_image_digests) > 0');
    expect(digests).toContain('^sha256:[a-f0-9]{64}$');
    expect(digests).not.toMatch(/\bdefault\s*=/);
  });

  test.each(keyModules)('%s protects the sealing key against destruction', module => {
    const key = resource(source(module), 'google_kms_crypto_key');
    expect(key).toMatch(/purpose\s*=\s*"ENCRYPT_DECRYPT"/);
    expect(key).toMatch(/lifecycle\s*\{\s*prevent_destroy\s*=\s*true/);
    expect(key).toMatch(/rotation_period\s*=\s*"7776000s"/);
    expect(key).toMatch(/deletion_policy\s*=\s*"PREVENT"/);
    const ring = resource(source(module), 'google_kms_key_ring');
    expect(ring).toMatch(/lifecycle\s*\{\s*prevent_destroy\s*=\s*true/);
  });

  test.each(keyModules)('%s rejects short and reserved workload identity pool IDs', module => {
    const prefix = blocks(source(module), 'variable').find(block => block.startsWith('variable "name_prefix"'))!;
    expect(prefix).toContain('^[a-z][a-z0-9-]{2,18}[a-z0-9]$');
    expect(prefix).toContain('!startswith(var.name_prefix, "gcp-")');
  });

  test('box network has no default rules or public IP, denies all ingress and provides private outbound NAT', () => {
    const tf = source('box');
    expect(resource(tf, 'google_compute_network')).toMatch(/auto_create_subnetworks\s*=\s*false/);
    expect(resource(tf, 'google_compute_subnetwork')).toMatch(/private_ip_google_access\s*=\s*true/);
    resource(tf, 'google_compute_router');
    const nat = resource(tf, 'google_compute_router_nat');
    expect(nat).toMatch(/nat_ip_allocate_option\s*=\s*"AUTO_ONLY"/);
    expect(nat).toMatch(/source_subnetwork_ip_ranges_to_nat\s*=\s*"ALL_SUBNETWORKS_ALL_IP_RANGES"/);
    const firewall = resource(tf, 'google_compute_firewall');
    expect(firewall).toMatch(/direction\s*=\s*"INGRESS"/);
    expect(firewall).toMatch(/priority\s*=\s*0/);
    expect(firewall).toMatch(/source_ranges\s*=\s*\["0\.0\.0\.0\/0"\]/);
    expect(firewall).toMatch(/deny\s*\{\s*protocol\s*=\s*"all"/);
    expect(tf).not.toMatch(/access_config|ipv6_access_config|google_compute_address/);
  });

  test('box uses production Confidential Space, secure boot and only digest/reference restart metadata', () => {
    const vm = resource(source('box'), 'google_compute_instance');
    expect(vm).toContain('projects/confidential-space-images/global/images/family/confidential-space');
    expect(vm).toMatch(/enable_confidential_compute\s*=\s*true/);
    expect(vm).toMatch(/confidential_instance_type\s*=\s*var\.confidential_type/);
    expect(vm).toMatch(/enable_secure_boot\s*=\s*true/);
    expect(vm).toMatch(/allow_stopping_for_update\s*=\s*true/);
    expect(vm).toMatch(/email\s*=\s*google_service_account\.box\.email/);
    expect(vm).toMatch(/scopes\s*=\s*\["cloud-platform"\]/);
    const metadata = vm.match(/metadata\s*=\s*\{([^}]+)\}/)![1]!;
    expect([...metadata.matchAll(/"([^"]+)"\s*=/g)].map(match => match[1]).sort()).toEqual([
      'tee-image-reference', 'tee-restart-policy',
    ]);
    expect(metadata).toMatch(/"tee-image-reference"\s*=\s*var\.image_reference/);
    expect(metadata).toMatch(/"tee-restart-policy"\s*=\s*"Always"/);
    expect(vm).toContain('contains(var.allowed_image_digests, split("@", var.image_reference)[1])');
  });

  test('box defaults to TDX and selects supported SEV hardware and maintenance when requested', () => {
    const tf = source('box');
    const input = blocks(tf, 'variable').find(block => block.startsWith('variable "confidential_type"'))!;
    expect(input).toBeDefined();
    expect(input).toMatch(/default\s*=\s*"TDX"/);
    expect(input).toContain('contains(["TDX", "SEV"], var.confidential_type)');
    expect(tf).toContain('var.confidential_type == "TDX" ? "c3-standard-4" : "n2d-standard-2"');
    expect(tf).toContain('var.confidential_type == "TDX" ? "TERMINATE" : "MIGRATE"');
    expect(tf).toContain('var.confidential_type == "SEV" ? "AMD Milan" : null');
  });

  test('box VM can attest and pull only the selected Artifact Registry repository', () => {
    const tf = source('box');
    const projectGrant = resource(tf, 'google_project_iam_member');
    expect(projectGrant).toMatch(/role\s*=\s*"roles\/confidentialcomputing\.workloadUser"/);
    const registryGrant = resource(tf, 'google_artifact_registry_repository_iam_member');
    expect(registryGrant).toMatch(/role\s*=\s*"roles\/artifactregistry\.reader"/);
    expect(registryGrant).toMatch(/repository\s*=\s*var\.artifact_registry_repository/);
    for (const grant of [projectGrant, registryGrant]) {
      expect(grant).toContain('serviceAccount:${google_service_account.box.email}');
    }
    expect(tf).not.toMatch(/roles\/(?:owner|editor|iam\.workloadIdentityUser)/);
  });

  test('BYO KMS creates only customer-owned key-release resources, with an external box identity', () => {
    const tf = source('byo-kms');
    const variables = blocks(tf, 'variable');
    for (const name of ['project_id', 'box_project_id', 'box_service_account_email']) {
      const variable = variables.find(block => block.startsWith(`variable "${name}"`));
      expect(variable).toBeDefined();
      expect(variable).not.toMatch(/\bdefault\s*=/);
    }
    expect(tf).not.toMatch(/resource "google_(?:compute_|service_account|project_iam)/);
    expect(tf).toContain('endswith(var.box_service_account_email, "@${var.box_project_id}.iam.gserviceaccount.com")');
  });

  test('control plane is a public Cloud Run service with a digest-pinned image, one instance and a dedicated account', () => {
    const tf = source('control-plane');
    const service = resource(tf, 'google_cloud_run_v2_service');
    expect(service).toMatch(/service_account\s*=\s*google_service_account\.control_plane\.email/);
    expect(service).toMatch(/image\s*=\s*var\.image_reference/);
    expect(service).toMatch(/deletion_protection\s*=\s*true/);
    // Browsers, the CLI, boxes and Stripe call it without Google credentials; every route authenticates its caller.
    expect(service).toMatch(/invoker_iam_disabled\s*=\s*true/);
    expect(service).toMatch(/ingress\s*=\s*"INGRESS_TRAFFIC_ALL"/);
    expect(tf).not.toMatch(/allAuthenticatedUsers/);
    // In-process serialization and a bucket without compare-and-swap need a single writer.
    expect(service).toMatch(/max_instance_count\s*=\s*1\b/);
    expect(service).toMatch(/memory\s*=\s*"512Mi"/);
    const image = blocks(tf, 'variable').find(block => block.startsWith('variable "image_reference"'))!;
    expect(image).toContain('@sha256:[a-f0-9]{64}$');
    expect(image).not.toMatch(/\bdefault\s*=/);
  });

  test('control plane runs the image entry and passes the hosted configuration, with Stripe credentials only by Secret Manager reference', () => {
    const tf = source('control-plane');
    const service = resource(tf, 'google_cloud_run_v2_service');
    // The same entry as Dockerfile.control-plane's ENTRYPOINT.
    const entry = readFileSync(new URL('../../Dockerfile.control-plane', import.meta.url), 'utf8').match(/^ENTRYPOINT (\[.*\])$/m)![1]!;
    const [command, ...args] = JSON.parse(entry) as string[];
    expect(service).toMatch(new RegExp(`command\\s*=\\s*\\["${command}"\\]`));
    expect(service).toMatch(new RegExp(`args\\s*=\\s*\\[${args.map(arg => `"${arg}"`).join(',\\s*')}\\]`));
    const names = [...service.matchAll(/name\s*=\s*"(KEYSENTRY_[A-Z_]+)"/g)].map(match => match[1]!).sort();
    expect(names).toEqual(['KEYSENTRY_BOX_ALLOWED_DIGESTS', 'KEYSENTRY_BOX_PROJECT_ID', 'KEYSENTRY_BOX_SERVICE_ACCOUNT', 'KEYSENTRY_CONTROL_BUCKET',
      'KEYSENTRY_CONTROL_ORIGIN', 'KEYSENTRY_STRIPE_API_KEY_REF', 'KEYSENTRY_STRIPE_PRICE_ID', 'KEYSENTRY_STRIPE_WEBHOOK_SECRET_REF', 'KEYSENTRY_TRUSTED_PROXY_HOPS']);
    expect(service).toMatch(/name\s*=\s*"KEYSENTRY_CONTROL_BUCKET"\s*value\s*=\s*google_storage_bucket\.ciphertext\.name/);
    // References only: no secret value reaches the environment, not even through Cloud Run's secret variables.
    expect(service).not.toMatch(/secret_key_ref|value_source/);
    expect(service).toMatch(/name\s*=\s*"KEYSENTRY_STRIPE_WEBHOOK_SECRET_REF"\s*value\s*=\s*local\.stripe_webhook_secret_ref/);
    expect(service).toMatch(/name\s*=\s*"KEYSENTRY_STRIPE_API_KEY_REF"\s*value\s*=\s*local\.stripe_api_key_secret_ref/);
    expect(tf).toContain('stripe_webhook_secret_ref = "projects/${var.project_id}/secrets/${var.stripe_webhook_secret_id}/versions/latest"');
    expect(tf).toContain('stripe_api_key_secret_ref = "projects/${var.project_id}/secrets/${var.stripe_api_key_secret_id}/versions/latest"');
    expect(tf).not.toMatch(/whsec_|[sr]k_(?:live|test)_/);
    // Live provisioning variables come only from the live_provisioning switch.
    expect(service).toMatch(/dynamic "env" \{\s*for_each = local\.live_env/);
    const live = tf.match(/live_env = var\.live_provisioning \? \{([\s\S]*?)\} : \{\}/)![1]!;
    const liveNames = [...live.matchAll(/(KEYSENTRY_[A-Z_]+)\s*=/g)].map(match => match[1]!).sort();
    expect(liveNames).toEqual(['KEYSENTRY_BOX_IMAGE_REFERENCE', 'KEYSENTRY_BOX_SUBNETWORK', 'KEYSENTRY_BOX_ZONE', 'KEYSENTRY_CONTROL_PLANE_LIVE']);
    expect(live).toMatch(/KEYSENTRY_CONTROL_PLANE_LIVE\s*=\s*"1"/);
    // Exactly the variables the hosted entry reads (Cloud Run sets PORT; the quota keeps its default).
    expect([...names, ...liveNames, 'PORT', 'KEYSENTRY_BOX_QUOTA'].sort()).toEqual([...HOSTED_SETTINGS].sort());
    const sample: Record<string, string> = {
      KEYSENTRY_BOX_ALLOWED_DIGESTS: `sha256:${'a'.repeat(64)}`, KEYSENTRY_BOX_PROJECT_ID: 'keysentry-box',
      KEYSENTRY_BOX_SERVICE_ACCOUNT: 'keysentry-box@keysentry-box.iam.gserviceaccount.com', KEYSENTRY_CONTROL_BUCKET: 'ks-control-state',
      KEYSENTRY_CONTROL_ORIGIN: 'https://control.example', KEYSENTRY_STRIPE_API_KEY_REF: 'projects/keysentry-control/secrets/stripe-api-key/versions/latest',
      KEYSENTRY_STRIPE_PRICE_ID: 'price_sample', KEYSENTRY_STRIPE_WEBHOOK_SECRET_REF: 'projects/keysentry-control/secrets/stripe-webhook/versions/latest',
      KEYSENTRY_TRUSTED_PROXY_HOPS: '1',
    };
    expect(Object.keys(sample).sort()).toEqual(names);
    expect(() => hostedConfigFromEnv(sample)).not.toThrow();
    for (const name of names.filter(name => name !== 'KEYSENTRY_TRUSTED_PROXY_HOPS')) {
      const { [name]: _removed, ...rest } = sample;
      expect(() => hostedConfigFromEnv(rest)).toThrow(name);
    }
    expect(hostedConfigFromEnv({ ...sample, KEYSENTRY_CONTROL_PLANE_LIVE: '1', KEYSENTRY_BOX_ZONE: 'us-central1-a',
      KEYSENTRY_BOX_SUBNETWORK: 'projects/keysentry-box/regions/us-central1/subnetworks/keysentry-box-subnet',
      KEYSENTRY_BOX_IMAGE_REFERENCE: `us-docker.pkg.dev/keysentry-box/box/keysentry@sha256:${'a'.repeat(64)}` }).live).not.toBeNull();
    // Live settings are checked before anything is created.
    expect(service).toContain('!var.live_provisioning || (var.box_zone != "" && var.box_subnetwork != "" && var.box_image_reference != "")');
    expect(service).toContain('contains(var.allowed_image_digests, element(concat(split("@", var.box_image_reference), [""]), 1))');
  });

  test('control plane stores ciphertext in a private versioned bucket and cannot destroy it implicitly', () => {
    const bucket = resource(source('control-plane'), 'google_storage_bucket');
    expect(bucket).toMatch(/uniform_bucket_level_access\s*=\s*true/);
    expect(bucket).toMatch(/public_access_prevention\s*=\s*"enforced"/);
    expect(bucket).toMatch(/versioning\s*\{\s*enabled\s*=\s*true/);
    expect(bucket).toMatch(/force_destroy\s*=\s*false/);
    expect(bucket).toMatch(/prevent_destroy\s*=\s*true/);
    // Old versions of overwritten or deleted records do not accumulate.
    expect(bucket).toMatch(/days_since_noncurrent_time\s*=\s*7/);
  });

  test('control plane has bucket object access and two Stripe secret reads, and no key release authority', () => {
    const tf = source('control-plane');
    const grant = resource(tf, 'google_storage_bucket_iam_member');
    expect(grant).toMatch(/role\s*=\s*"roles\/storage\.objectUser"/);
    expect(grant).toContain('serviceAccount:${google_service_account.control_plane.email}');
    expect(grant).toMatch(/bucket\s*=\s*google_storage_bucket\.ciphertext\.name/);
    const secrets = resource(tf, 'google_secret_manager_secret_iam_member');
    expect(secrets).toMatch(/role\s*=\s*"roles\/secretmanager\.secretAccessor"/);
    expect(secrets).toContain('toset([var.stripe_webhook_secret_id, var.stripe_api_key_secret_id])');
    expect(secrets).toContain('serviceAccount:${google_service_account.control_plane.email}');
    expect(tf).not.toMatch(/resource "google_(?:kms_|compute_|secret_manager_secret"|project_iam_binding|project_iam_policy)/);
    expect(tf).not.toMatch(/roles\/(?:owner|editor|storage\.admin|compute\.|cloudkms\.|secretmanager\.admin|iam\.serviceAccountTokenCreator)/);
  });

  test('control plane gets Compute rights only with live provisioning: create-only, in the box project, acting as the box account', () => {
    const tf = source('control-plane');
    const role = resource(tf, 'google_project_iam_custom_role');
    const member = resource(tf, 'google_project_iam_member');
    const user = resource(tf, 'google_service_account_iam_member');
    for (const block of [role, member, user]) expect(block).toMatch(/count\s*=\s*var\.live_provisioning \? 1 : 0/);
    const permissions = [...role.match(/permissions = \[([\s\S]*?)\]/)![1]!.matchAll(/"([a-z.A-Z]+)"/g)].map(match => match[1]!);
    expect(permissions).toEqual(['compute.disks.create', 'compute.instances.create', 'compute.instances.setMetadata',
      'compute.instances.setServiceAccount', 'compute.subnetworks.use']);
    expect(role).toMatch(/project\s*=\s*var\.box_project_id/);
    expect(member).toMatch(/project\s*=\s*var\.box_project_id/);
    expect(member).toMatch(/role\s*=\s*google_project_iam_custom_role\.provision\[0\]\.name/);
    expect(member).toContain('serviceAccount:${google_service_account.control_plane.email}');
    expect(user).toContain('service_account_id = "projects/${var.box_project_id}/serviceAccounts/${var.box_service_account_email}"');
    expect(user).toMatch(/role\s*=\s*"roles\/iam\.serviceAccountUser"/);
    const live = blocks(tf, 'variable').find(block => block.startsWith('variable "live_provisioning"'))!;
    expect(live).toMatch(/default\s*=\s*false/);
  });

  test.each(modules)('%s outputs resource identifiers only', module => {
    const outputs = blocks(source(module), 'output');
    expect(outputs.length).toBeGreaterThan(0);
    for (const output of outputs) {
      expect(output).toMatch(/description\s*=\s*"[^"\n]+"/);
      expect(output).not.toMatch(/secret|password|private_key|access_token|sensitive\s*=\s*true/i);
    }
  });
});

const terraform = spawnSync('terraform', ['version', '-json'], {
  encoding: 'utf8', windowsHide: true, timeout: 10_000,
  env: { ...process.env, CHECKPOINT_DISABLE: '1' },
});
const terraformMissing = (terraform.error as NodeJS.ErrnoException | undefined)?.code === 'ENOENT';
// Codex's Windows sandbox can expose Terraform on PATH but deny all Node child processes.
// Keep the native check active elsewhere; in this sandbox run the same check via exec_command.
const terraformSpawnBlocked = (terraform.error as NodeJS.ErrnoException | undefined)?.code === 'EPERM';

test.skipIf(terraformMissing || terraformSpawnBlocked).each(modules)('terraform fmt -check: %s (offline)', module => {
  expect(terraform.error).toBeUndefined();
  expect(terraform.status).toBe(0);
  const result = spawnSync('terraform', ['fmt', '-check', '-diff', fileURLToPath(new URL(`${module}/`, root))], {
    encoding: 'utf8', windowsHide: true, timeout: 10_000,
    env: { ...process.env, CHECKPOINT_DISABLE: '1' },
  });
  expect(result.error).toBeUndefined();
  expect(result.stdout + result.stderr).toBe('');
  expect(result.status).toBe(0);
});
