import { z } from 'zod';
import { HOST_IDS } from '../types.js';
import { PROVIDER_IDS } from '../core/provider-ids.js';

export const hostIdSchema = z.enum(HOST_IDS);
export const providerIdSchema = z.enum(PROVIDER_IDS);
export const tierSchema = z.enum(['crypto', 'cloud', 'database', 'payments', 'ai', 'comms', 'app', 'unknown']);
const method = z.enum(['auto', 'atomic-roll', 'generate', 'guided']);
const service = z.object({ host: hostIdSchema, projectId: z.string(), projectName: z.string(), serviceId: z.string(), serviceName: z.string(), environmentId: z.string(), environmentName: z.string() });
const consumer = z.object({ service, varName: z.string(), fingerprint: z.string().nullable(), hint: z.string().nullable(), sealed: z.boolean(), reference: z.boolean().optional() });
const classification = { provider: providerIdSchema, tier: tierSchema, isSecret: z.boolean(), confidence: z.enum(['high', 'medium', 'low']) };
export const inventorySchema = z.object({ version: z.literal(1), scannedAt: z.string(), hosts: z.array(hostIdSchema), services: z.array(service), findings: z.array(consumer.extend(classification)), clusters: z.array(z.object({ id: z.string(), fingerprint: z.string().nullable(), provider: providerIdSchema, tier: tierSchema, method, hint: z.string().nullable(), consumers: z.array(consumer) })), errors: z.array(z.object({ host: hostIdSchema, message: z.string() })) });
export const planIdSchema = z.string().regex(/^plan-\d{14}-[a-f0-9]{4}$/);
export const planSchema = z.object({ id: planIdSchema, createdAt: z.string(), steps: z.array(z.object({ clusterId: z.string(), provider: providerIdSchema, tier: tierSchema, method, hint: z.string().nullable(), consumers: z.array(consumer) })), services: z.array(service) });
