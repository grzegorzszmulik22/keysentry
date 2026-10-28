import { feedItemTexts, sanitizeFeedText, type FeedItem } from '../feeds/index.js';
import type { FeedSource, HostId, IncidentEvidence } from '../types.js';

// Shared with the 0.1 detector: broad security words qualify only in titles.
export const SECURITY_TITLE = /\b(?:security[\s-]+(?:incident|disclosure|advisory|notice|update)|(?:data[\s-]+)?breach|compromis(?:e|ed)|unauthori[sz]ed[\s-]+access|credentials?[\s-]+(?:leak|exposure))\b/i;
export const SECURITY_PHRASE = /\b(?:rotate[\s-]+(?:all|your)[\s-]+(?:environment[\s-]+variables|secrets|keys|credentials)|unauthori[sz]ed[\s-]+(?:third[\s-]+party|access)|(?:may[\s-]+have|have[\s-]+been)[\s-]+(?:accessed|exposed|compromised))\b/i;
export const HIGH_CONFIDENCE_TITLE = /\b(?:security[\s-]+(?:incident|disclosure)|breach)\b/i;

// Product names are case-sensitive; domains cannot match another domain's label.
const HOST_MENTIONS: Record<HostId, RegExp[]> = {
  railway: [/(?<![\w-])railway\.(?:com|app)(?![\w-]|\.[\w-])/i, /(?<![\w.-])Railway(?![\w-]|\.[\w-])/],
  vercel: [/(?<![\w-])vercel\.com(?![\w-]|\.[\w-])/i, /(?<![\w.-])Vercel(?![\w-]|\.[\w-])/],
  render: [/(?<![\w-])render\.com(?![\w-]|\.[\w-])/i],
  fly: [/(?<![\w-])fly\.io(?![\w-]|\.[\w-])/i],
  'github-actions': [/(?<![\w-])github\.com(?![\w-]|\.[\w-])/i, /(?<![\w.-])GitHub(?![\w-]|\.[\w-])/],
  dotenv: [],
  netlify: [/(?<![\w-])netlify\.(?:com|app)(?![\w-]|\.[\w-])/i, /(?<![\w.-])Netlify(?![\w-]|\.[\w-])/],
  'cloudflare-workers': [/(?<![\w-])cloudflare\.com(?![\w-]|\.[\w-])/i, /(?<![\w.-])Cloudflare(?![\w-]|\.[\w-])/],
  'supabase-functions': [/(?<![\w-])supabase\.(?:com|co)(?![\w-]|\.[\w-])/i, /(?<![\w.-])Supabase(?![\w-]|\.[\w-])/],
  heroku: [/(?<![\w-])heroku\.com(?![\w-]|\.[\w-])/i, /(?<![\w.-])Heroku(?![\w-]|\.[\w-])/],
  digitalocean: [/(?<![\w-])digitalocean\.com(?![\w-]|\.[\w-])/i, /(?<![\w.-])DigitalOcean(?![\w-]|\.[\w-])/],
  // Self-hosted: an incident is in the operator's own infrastructure, not a platform advisory.
  coolify: [],
  zeabur: [/(?<![\w-])zeabur\.com(?![\w-]|\.[\w-])/i, /(?<![\w.-])Zeabur(?![\w-]|\.[\w-])/],
  kubernetes: [],
  'aws-secrets-manager': [],
  'vault-kv': [],
  doppler: [/(?<![\w-])doppler\.com(?![\w-]|\.[\w-])/i, /(?<![\w.-])Doppler(?![\w-]|\.[\w-])/],
  infisical: [/(?<![\w-])infisical\.com(?![\w-]|\.[\w-])/i, /(?<![\w.-])Infisical(?![\w-]|\.[\w-])/],
};

// Hosts whose names news coverage can mention. Phase 6 adds every host with a mention pattern above; self-hosted
// servers (Coolify, Kubernetes, Vault) and AWS Secrets Manager have none by design.
export const PLATFORM_HOSTS: readonly HostId[] = ['railway', 'vercel', 'render', 'fly', 'github-actions',
  'netlify', 'cloudflare-workers', 'supabase-functions', 'heroku', 'digitalocean', 'zeabur', 'doppler', 'infisical'];

export function mentionsHost(host: HostId, text: string): boolean {
  return HOST_MENTIONS[host].some(pattern => pattern.test(text));
}

export function isSecurityAdvisory(title: string, texts: readonly string[]): boolean {
  return SECURITY_TITLE.test(title) || texts.some(text => SECURITY_PHRASE.test(text));
}

const MiB = 1024 * 1024;
/** Reviewed URLs/ownership from notes/phase2-facts.md §§7–8; no feed discovers other destinations. */
export const DEFAULT_SOURCES: readonly FeedSource[] = [
  // §8 Railway blog and changelog: incident disclosures, plus follow-up recommendations.
  { id: 'railway-blog', kind: 'official', url: 'https://blog.railway.com/rss.xml', hosts: ['railway'], outlet: 'Railway blog', owner: 'Railway', maxBytes: 8 * MiB },
  { id: 'railway-changelog', kind: 'official', url: 'https://railway.com/changelog/rss.xml', hosts: ['railway'], outlet: 'Railway changelog', owner: 'Railway', maxBytes: 8 * MiB },
  // §8 Vercel Atom, status, and KB bulletins (the remaining KB entries are excluded).
  { id: 'vercel-blog', kind: 'official', url: 'https://vercel.com/atom', hosts: ['vercel'], outlet: 'Vercel blog and changelog', owner: 'Vercel', maxBytes: 8 * MiB },
  { id: 'vercel-status', kind: 'official', url: 'https://www.vercel-status.com/history.rss', hosts: ['vercel'], outlet: 'Vercel status', owner: 'Vercel', maxBytes: 8 * MiB },
  { id: 'vercel-bulletins', kind: 'official', url: 'https://vercel.com/kb/kb-feed', linkPrefix: 'https://vercel.com/kb/bulletin/', hosts: ['vercel'], outlet: 'Vercel security bulletins', owner: 'Vercel', maxBytes: 8 * MiB },
  // §8 Render's blog/changelog are Atom; status uses the same security qualification rules.
  { id: 'render-blog', kind: 'official', url: 'https://render.com/blog/feed.xml', hosts: ['render'], outlet: 'Render blog', owner: 'Render', maxBytes: 4 * MiB },
  { id: 'render-status', kind: 'official', url: 'https://status.render.com/history.rss', hosts: ['render'], outlet: 'Render status', owner: 'Render', maxBytes: 4 * MiB },
  { id: 'render-changelog', kind: 'official', url: 'https://render.com/changelog/feed.xml', hosts: ['render'], outlet: 'Render changelog', owner: 'Render', maxBytes: 4 * MiB },
  // §8 Fly blog/status and the verified Fresh Produce announcements category.
  { id: 'fly-blog', kind: 'official', url: 'https://fly.io/blog/feed.xml', hosts: ['fly'], outlet: 'Fly blog', owner: 'Fly.io', maxBytes: 4 * MiB },
  { id: 'fly-status', kind: 'official', url: 'https://status.flyio.net/history.rss', hosts: ['fly'], outlet: 'Fly status', owner: 'Fly.io', maxBytes: 4 * MiB },
  { id: 'fly-community', kind: 'official', url: 'https://community.fly.io/c/fresh-produce/27.rss', hosts: ['fly'], outlet: 'Fly community announcements', owner: 'Fly.io', maxBytes: 4 * MiB },
  // §8 GitHub changelog, security blog, and status. Empty Security Lab feed is omitted.
  { id: 'github-changelog', kind: 'official', url: 'https://github.blog/changelog/feed/', hosts: ['github-actions'], outlet: 'GitHub changelog', owner: 'GitHub', maxBytes: 4 * MiB },
  { id: 'github-security', kind: 'official', url: 'https://github.blog/security/feed/', hosts: ['github-actions'], outlet: 'GitHub security blog', owner: 'GitHub', maxBytes: 4 * MiB },
  { id: 'github-status', kind: 'official', url: 'https://www.githubstatus.com/history.rss', hosts: ['github-actions'], outlet: 'GitHub status', owner: 'GitHub', maxBytes: 4 * MiB },
  // Phase 6 official sources; each URL was fetched on 2026-10-28 (notes/hosts-a.md, notes/hosts-b.md).
  // Netlify: the Statuspage linked from netlify.com (channel "Netlify Status"); blog and changelog feeds advertised by
  // <link rel=alternate> on netlify.com/blog.
  { id: 'netlify-status', kind: 'official', url: 'https://www.netlifystatus.com/history.rss', hosts: ['netlify'], outlet: 'Netlify status', owner: 'Netlify', maxBytes: 4 * MiB },
  { id: 'netlify-blog', kind: 'official', url: 'https://www.netlify.com/feed.xml', hosts: ['netlify'], outlet: 'Netlify blog', owner: 'Netlify', maxBytes: 4 * MiB },
  { id: 'netlify-changelog', kind: 'official', url: 'https://www.netlify.com/changelog/feed.xml', hosts: ['netlify'], outlet: 'Netlify changelog', owner: 'Netlify', maxBytes: 4 * MiB },
  // Heroku: status on Heroku's own domain (Atom, author Heroku; its April 2022 OAuth token notice was published there),
  // the blog feed advertised on heroku.com/blog and the Dev Center changelog.
  { id: 'heroku-status', kind: 'official', url: 'https://status.heroku.com/feed', hosts: ['heroku'], outlet: 'Heroku status', owner: 'Heroku (Salesforce)', maxBytes: 4 * MiB },
  { id: 'heroku-blog', kind: 'official', url: 'https://www.heroku.com/feed/', hosts: ['heroku'], outlet: 'Heroku blog', owner: 'Heroku (Salesforce)', maxBytes: 4 * MiB },
  { id: 'heroku-changelog', kind: 'official', url: 'https://devcenter.heroku.com/changelog/feed', hosts: ['heroku'], outlet: 'Heroku changelog', owner: 'Heroku (Salesforce)', maxBytes: 4 * MiB },
  // DigitalOcean: its status subdomain and the blog feed advertised on digitalocean.com/blog.
  { id: 'digitalocean-status', kind: 'official', url: 'https://status.digitalocean.com/history.rss', hosts: ['digitalocean'], outlet: 'DigitalOcean status', owner: 'DigitalOcean', maxBytes: 4 * MiB },
  { id: 'digitalocean-blog', kind: 'official', url: 'https://www.digitalocean.com/rss/blog.atom', hosts: ['digitalocean'], outlet: 'DigitalOcean blog', owner: 'DigitalOcean', maxBytes: 4 * MiB },
  // Cloudflare: Statuspage incident history on Cloudflare's own status domain (noisy maintenance entries are filtered by
  // the security-title rules), and Cloudflare's blog, which publishes incident post-mortems and security disclosures.
  { id: 'cloudflare-status', kind: 'official', url: 'https://www.cloudflarestatus.com/history.atom', hosts: ['cloudflare-workers'], outlet: 'Cloudflare status', owner: 'Cloudflare', maxBytes: 4 * MiB },
  { id: 'cloudflare-blog', kind: 'official', url: 'https://blog.cloudflare.com/rss/', hosts: ['cloudflare-workers'], outlet: 'Cloudflare blog', owner: 'Cloudflare', maxBytes: 4 * MiB },
  // Supabase: Statuspage incident history on its own status domain, and its own blog on supabase.com.
  { id: 'supabase-status', kind: 'official', url: 'https://status.supabase.com/history.rss', hosts: ['supabase-functions'], outlet: 'Supabase status', owner: 'Supabase', maxBytes: 4 * MiB },
  { id: 'supabase-blog', kind: 'official', url: 'https://supabase.com/rss.xml', hosts: ['supabase-functions'], outlet: 'Supabase blog', owner: 'Supabase', maxBytes: 4 * MiB },
  // Zeabur: its Better Stack status page on its own domain (it carried the October 2026 unauthorized-access incident).
  { id: 'zeabur-status', kind: 'official', url: 'https://status.zeabur.com/feed.rss', hosts: ['zeabur'], outlet: 'Zeabur status', owner: 'Zeabur', maxBytes: 4 * MiB },
  // Coolify (self-hosted), Kubernetes, Vault and AWS Secrets Manager have no platform advisory feed; Doppler and
  // Infisical have no verified feed yet, so only news coverage mentions them.
  // §7 BleepingComputer: recorded independent incident coverage; validators supported.
  { id: 'bleepingcomputer', kind: 'news', url: 'https://www.bleepingcomputer.com/feed/', hosts: [...PLATFORM_HOSTS], outlet: 'BleepingComputer', owner: 'BleepingComputer LLC', maxBytes: 4 * MiB },
  // §7 The Record: security reporting, published by Recorded Future.
  { id: 'the-record', kind: 'news', url: 'https://therecord.media/feed', hosts: [...PLATFORM_HOSTS], outlet: 'The Record', owner: 'Recorded Future', maxBytes: 4 * MiB },
  // §7 SecurityWeek: security reporting with a distinct publishing owner.
  { id: 'securityweek', kind: 'news', url: 'https://www.securityweek.com/feed/', hosts: [...PLATFORM_HOSTS], outlet: 'SecurityWeek', owner: 'SecurityWeek / Wired Business Media', maxBytes: 4 * MiB },
  // §7 The Register: RSS despite .atom; guarded HTTP handles its reviewed same-owner redirect.
  { id: 'the-register', kind: 'news', url: 'https://www.theregister.com/security/headlines.atom', hosts: [...PLATFORM_HOSTS], outlet: 'The Register', owner: 'Situation Publishing', maxBytes: 4 * MiB },
  // §7 KrebsOnSecurity: independent reporting; XML is served with text/html.
  { id: 'krebs', kind: 'news', url: 'https://krebsonsecurity.com/feed/', hosts: [...PLATFORM_HOSTS], outlet: 'KrebsOnSecurity', owner: 'Brian Krebs', maxBytes: 4 * MiB },
  // §7 Dark Reading: security coverage, owner Informa TechTarget.
  { id: 'dark-reading', kind: 'news', url: 'https://www.darkreading.com/rss.xml', hosts: [...PLATFORM_HOSTS], outlet: 'Dark Reading', owner: 'Informa TechTarget', maxBytes: 4 * MiB },
  // §7 Ars Technica: verified current security feed (old feeds.arstechnica.com URL is 404).
  { id: 'ars-technica', kind: 'news', url: 'https://arstechnica.com/security/feed/', hosts: [...PLATFORM_HOSTS], outlet: 'Ars Technica', owner: 'Condé Nast', maxBytes: 4 * MiB },
  // §7 The Hacker News: recorded report independent of BleepingComputer.
  { id: 'the-hacker-news', kind: 'news', url: 'https://feeds.feedburner.com/TheHackersNews', hosts: [...PLATFORM_HOSTS], outlet: 'The Hacker News', owner: 'The Hacker News', maxBytes: 4 * MiB },
  // §7 CISA advisories: independent agency reporting, not a platform's official advisory; ~5.7 MB.
  { id: 'cisa-advisories', kind: 'news', url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml', hosts: [...PLATFORM_HOSTS], outlet: 'CISA advisories', owner: 'CISA', maxBytes: 8 * MiB },
  // §7 Help Net Security: another distinct security reporting owner.
  { id: 'help-net-security', kind: 'news', url: 'https://www.helpnetsecurity.com/feed/', hosts: [...PLATFORM_HOSTS], outlet: 'Help Net Security', owner: 'Help Net Security', maxBytes: 4 * MiB },
];

// Negative cues win even if the story also contains apparent exposure language.
const DECEPTIVE_CAMPAIGN = /\b(?:phishing|impersonat\w*|look[\s-]?alike|fake\s+(?:billing\s+)?emails?|scams?)\b/i;
const DENIAL = /\b(?:was|were|is|are)\s+not\s+(?:involved|breached|affected|impacted)\b|\bnot\s+(?:affected|impacted)\b|\b(?:denies|denied|no)\s+(?:a\s+)?(?:data\s+)?breach\b|\bno\s+customer\s+data\s+was\s+affected\b|\bneither\b[^.!?]{0,100}\bsystems\s+were\s+breached\b/i;
const EXPOSURE_DENIAL = /\b(?:not|never|none|(?:was|were|has|have|had|is|are|did|does|do)n['’]t)\b[^.!?]{0,60}\b(?:accessed|exposed|stolen|decrypted|compromised)\b|\bno\s+(?:customer\s+)?(?:data|secrets?|(?:API\s+)?keys?|tokens?|credentials?|environment\s+variables)\b[^.!?]{0,60}\b(?:accessed|exposed|stolen|decrypted|compromised)\b/i;
const CREDENTIAL = /\b(?:customer\s+)?(?:environment\s+variables|(?:API\s+)?keys?|tokens?|credentials?|secrets?)\b/i;
const EXPOSURE = /\b(?:accessed|gained\s+access|expos(?:ed|es|ure)|stol(?:e|en)|decrypted|obtained\s+the\s+decrypted\s+contents)\b/i;
const OWN_SYSTEM = /\b(?:own\s+systems|(?:its|their)\s+systems|systems\s+that\s+store\s+customer)\b/i;
const BREACH_CONTEXT = /\b(?:breach|security\s+incident|suspicious\s+activity|anomalous\s+activity)\b/i;
const ROTATION_REQUEST = /\b(?:urges?|warns?|asks?|advises?|recommends?)\b[^.!?]{0,100}\brotate\b/i;
const INSTRUCTIONAL_TITLE = /\b(?:tutorial|how\s+to|prepare|guides?|introducing|announcing|best\s+practices|checklist|webinar|tips\s+for|protect\b[^.!?]{0,60}\bfrom)\b/i;
const PRODUCT_FEATURE = /\b(?:features?|now\s+lets|authenticated\s+dashboard)\b/i;
// Capitalization keeps generic phrases ("potential breach") from becoming named-company subjects.
const NAMED_BREACHED_SUBJECT = /\b([A-Z][\w.-]*(?:\s+[A-Z][\w.-]*){0,4})(?:['’]s)?\s+(?:(?:was|were|has\s+been|have\s+been)\s+)?(?:[Dd]ata\s+)?(?:[Bb]reach(?:ed)?|[Cc]ompromised|[Ee]xposes?|[Ll]eaks?)\b/g;
const BREACH_AT_SUBJECT = /\b(?:[Bb]reach|[Ii]ncident|[Cc]ompromise)\s+(?:at|of|affecting|involving)\s+(?:(?:customer|company|tenant|client)\s+)?([A-Z][\w.-]*(?:\s+[A-Z][\w.-]*){0,4})/g;

function excludedAdvisory(title: string, summary: string): boolean {
  const text = `${title} ${summary}`;
  return DECEPTIVE_CAMPAIGN.test(text) || DENIAL.test(text) || EXPOSURE_DENIAL.test(text)
    || INSTRUCTIONAL_TITLE.test(title);
}

function thirdPartySubject(title: string): boolean {
  // "GitHub Actions" is the platform name; a singular Action or its workflows are components.
  const subjectText = title.replace(/\bGitHub Actions\b/g, 'GitHub');
  return /\b(?:actions?|workflows?|packages?|libraries|library|dependenc(?:y|ies)|extensions?|plugins?|apps?|integrations?|worms?|malware|campaigns?|user\s+accounts)\b/i.test(subjectText)
    || /\bcustomers?\s+(?:(?:was|were|has\s+been|have\s+been)\s+)?(?:breach(?:ed)?|compromised)\b/i.test(subjectText);
}

function credentialExposure(title: string, summary: string, hosts: readonly HostId[]): boolean {
  // A single boolean cannot express different exposure claims for multiple named platforms.
  if (hosts.length !== 1) return false;
  const text = `${title} ${summary}`;
  if (excludedAdvisory(title, summary) || thirdPartySubject(title)
    || (thirdPartySubject(summary) && /\b(?:third[\s-]party|supply[\s-]chain|malicious)\b/i.test(summary))) return false;
  if (PRODUCT_FEATURE.test(text) && !BREACH_CONTEXT.test(text)) return false;
  for (const subjectRule of [NAMED_BREACHED_SUBJECT, BREACH_AT_SUBJECT]) {
    for (const match of text.matchAll(subjectRule)) {
      if (!mentionsHost(hosts[0]!, match[1]!)) return false;
    }
  }
  // A different subject precedes the breach in headlines like "Acme Analytics breach ... hosted on Railway".
  const subject = title.match(/^(.*?)\b(?:breach(?:ed)?|compromised|exposes?|leaks?)\b/i)?.[1];
  if (subject !== undefined && !mentionsHost(hosts[0]!, subject)) return false;
  // Claims must occur in the same bounded clause; separate topics cannot invent an exposure claim.
  const clauses = text.split(/[.!?;](?!\w)/);
  if (clauses.some(clause => CREDENTIAL.test(clause) && EXPOSURE.test(clause)
    && Math.abs(clause.search(CREDENTIAL) - clause.search(EXPOSURE)) <= 100)) return true;
  if (clauses.some(clause => OWN_SYSTEM.test(clause) && EXPOSURE.test(clause)
    && Math.abs(clause.search(OWN_SYSTEM) - clause.search(EXPOSURE)) <= 100)) return true;
  return CREDENTIAL.test(text) && BREACH_CONTEXT.test(text) && ROTATION_REQUEST.test(text);
}

/** Return sanitized evidence only; the caller supplies its keyed item-identity function. */
export function classifyItem(item: FeedItem, source: FeedSource, itemKey: (id: string) => string): IncidentEvidence | null {
  if (source.linkPrefix && !item.link?.startsWith(source.linkPrefix)) return null;
  const title = sanitizeFeedText(item.title, 200);
  const summary = sanitizeFeedText(item.summary, 600);
  const mentioned = PLATFORM_HOSTS.filter(host => mentionsHost(host, title));
  const covered = mentioned.some(host => source.hosts.includes(host));
  const texts = feedItemTexts(item).map(text => sanitizeFeedText(text, 600));
  const security = isSecurityAdvisory(title, texts);
  // News mentions can alert (including an outage); they still need explicit exposure to corroborate.
  if (source.kind === 'news' ? !covered : !security) return null;
  // Official feeds also discuss other platforms; those titles cannot speak officially for their owner.
  if (source.kind === 'official' && mentioned.some(host => !source.hosts.includes(host))) return null;
  // Excluded posts cannot supply the official half of a corroboration either.
  if (source.kind === 'official' && excludedAdvisory(title, summary)) return null;
  const exposure = credentialExposure(title, summary, source.kind === 'official' ? source.hosts : mentioned);
  return {
    sourceId: source.id, kind: source.kind, outlet: source.outlet, owner: source.owner,
    itemKey: itemKey(item.id), title, link: item.link, publishedAt: item.publishedAt,
    credentialExposure: exposure,
    confidence: source.kind === 'official' && HIGH_CONFIDENCE_TITLE.test(title) && exposure ? 'high' : security || exposure ? 'medium' : 'low',
  };
}
