import type { Exposure, Severity } from '../types.js';

export interface RuleMatch {
  /** The matched credential value. */
  value: string;
  /** Up to ~200 characters of surrounding text, for context gates. */
  context: string;
  /** Shannon entropy of `value`. */
  entropy: number;
}

export interface RuleOverride {
  /** Discard the match entirely: the shape matched but the content did not. */
  discard?: true;
  exposure?: Exposure;
  severity?: Severity;
  rationale?: string;
  nextStep?: string;
  provider?: string;
  title?: string;
}

export interface SecretRule {
  id: string;
  title: string;
  provider?: string;
  /** Must be sticky-safe: the scanner adds the global flag itself. */
  pattern: RegExp;
  /** Capture group holding the credential; 0 means the whole match. */
  group?: number;
  classification: 'confirmed-shape' | 'heuristic';
  exposure: Exposure;
  severity: Severity;
  /** Why the tool believes this is a credential, and how to read the exposure. */
  rationale: string;
  nextStep?: string;
  /** Minimum entropy (bits/char) for the value to be reported. */
  minEntropy?: number;
  /** The match is only reported when the surrounding text matches this. */
  requireContext?: RegExp;
  /**
   * Last word on a match. Return `null` to accept the rule's defaults, fields
   * to override them, or `{ discard: true }` to reject the match outright.
   */
  refine?: (match: RuleMatch) => RuleOverride | null;
}

/** Base64url-decode a JWT segment without throwing. */
export function decodeJwtSegment(segment: string): Record<string, unknown> | null {
  try {
    const normalised = segment.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalised + '='.repeat((4 - (normalised.length % 4)) % 4);
    const json = Buffer.from(padded, 'base64').toString('utf8');
    const parsed: unknown = JSON.parse(json);
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

const PUBLIC_BY_DESIGN =
  'Published in client code by design. Not a vulnerability on its own; recorded because it identifies the project and its enabled services.';

/**
 * Database URI schemes, shared by the two rules that reason about them.
 *
 * It was written out twice, and the two copies drifted: `basic-auth-url`'s
 * exclusion list was missing `mongodb+srv` while `database-connection-string`
 * matched it, so a `mongodb+srv://user:pass@...` URI produced both findings --
 * exactly the double-report the exclusion exists to prevent. One list, two
 * patterns built from it.
 */
const DB_SCHEMES = 'postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis|rediss|amqps?|clickhouse';

export const SECRET_RULES: readonly SecretRule[] = [
  // ---------------------------------------------------------------- AWS -----
  {
    id: 'aws-access-key-id',
    title: 'AWS access key ID',
    provider: 'AWS',
    pattern: /(?<![A-Z0-9])((?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16})(?![A-Z0-9])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'high',
    rationale:
      'AWS access key IDs have a fixed vendor prefix and length. No AWS workflow requires one in browser-delivered code; the browser path is Cognito or a signed-request backend.',
    nextStep:
      'Look for the matching 40-character secret key in the same asset. An ID alone is not usable, but it names the account and makes the pair worth hunting.',
    refine: (match) => {
      if (match.value.startsWith('ASIA')) {
        return {
          title: 'AWS temporary (STS) access key ID',
          rationale:
            'An ASIA-prefixed ID is a short-lived STS credential. Still never belongs in a bundle, but it expires, so impact depends on how fresh the build is.',
        };
      }
      return null;
    },
  },
  {
    id: 'aws-secret-access-key',
    title: 'AWS secret access key (contextual)',
    provider: 'AWS',
    pattern: /(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/g,
    group: 1,
    classification: 'heuristic',
    exposure: 'secret',
    severity: 'critical',
    minEntropy: 4.0,
    requireContext: /aws|secret[_-]?access[_-]?key|SECRET_?ACCESS/i,
    rationale:
      'A 40-character base64 value next to AWS wording. The shape alone is far too common to report, so this rule only fires with AWS context nearby.',
    nextStep: 'Pair with any AKIA/ASIA ID found in the same asset and verify with sts:GetCallerIdentity.',
  },

  // ------------------------------------------------------------- Google -----
  {
    id: 'google-api-key',
    title: 'Google API key',
    provider: 'Google',
    pattern: /(?<![A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'depends',
    severity: 'medium',
    rationale:
      'Google browser API keys (Maps, Firebase) are meant to ship to clients and are protected by HTTP-referrer and API restrictions, not by secrecy. The same format is also used for server keys, which are not.',
    nextStep:
      'Check whether the key is restricted: an unrestricted key can be billed against from any origin, and a key that also enables a server-side API is a real finding.',
  },
  {
    id: 'google-oauth-client-id',
    title: 'Google OAuth client ID',
    provider: 'Google',
    pattern: /(?<![A-Za-z0-9-])([0-9]{8,}-[a-z0-9]{32}\.apps\.googleusercontent\.com)(?![A-Za-z0-9-])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'public',
    severity: 'info',
    rationale: `OAuth client IDs are public parameters of the authorization flow. ${PUBLIC_BY_DESIGN}`,
    nextStep: 'Review the allowed redirect URIs instead — that is where this flow actually breaks.',
  },
  {
    id: 'gcp-service-account-json',
    title: 'GCP service account key material',
    provider: 'Google',
    pattern: /"type"\s*:\s*"service_account"/g,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'critical',
    rationale:
      'A service account JSON block is a server credential. Its presence in client-delivered code is a direct compromise of that identity.',
    nextStep: 'Extract client_email and private_key_id and report for immediate rotation.',
  },

  // ------------------------------------------------------------- Stripe -----
  {
    id: 'stripe-secret-key',
    title: 'Stripe live secret / restricted key',
    provider: 'Stripe',
    pattern: /(?<![A-Za-z0-9_])((?:sk|rk)_live_[0-9a-zA-Z]{16,99})(?![A-Za-z0-9_])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'critical',
    rationale:
      'sk_live_ and rk_live_ are server-side Stripe credentials. Unlike pk_live_, they are never part of a browser integration.',
    nextStep: 'Report for immediate rotation. Do not call the Stripe API with it.',
  },
  {
    id: 'stripe-test-secret-key',
    title: 'Stripe test secret key',
    provider: 'Stripe',
    pattern: /(?<![A-Za-z0-9_])((?:sk|rk)_test_[0-9a-zA-Z]{16,99})(?![A-Za-z0-9_])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'low',
    rationale:
      'A test-mode secret key. It cannot move real money, so the impact is limited to test data — but it shows secret keys reaching the client build at all, which is the underlying bug.',
    nextStep: 'Report as hygiene, and check whether the same build path ever carries a live key.',
  },
  {
    id: 'stripe-publishable-key',
    title: 'Stripe publishable key',
    provider: 'Stripe',
    pattern: /(?<![A-Za-z0-9_])(pk_(?:live|test)_[0-9a-zA-Z]{16,99})(?![A-Za-z0-9_])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'public',
    severity: 'info',
    rationale: `Stripe publishable keys exist to be embedded in client code — Stripe.js cannot work without one. ${PUBLIC_BY_DESIGN}`,
    nextStep: 'Nothing to report. Reporting a pk_live_ key as a leak is the classic false positive.',
  },

  // ------------------------------------------------------------- GitHub -----
  {
    id: 'github-token',
    title: 'GitHub access token',
    provider: 'GitHub',
    pattern: /(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{36,255})(?![A-Za-z0-9_])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'critical',
    rationale:
      'GitHub prefixes every token type (ghp_ personal, gho_ OAuth, ghu_ user-to-server, ghs_ server-to-server, ghr_ refresh). None are public.',
    nextStep: 'Report for revocation. Scope can be confirmed with an unauthenticated-to-you /user call only with the owner’s permission.',
  },
  {
    id: 'github-fine-grained-pat',
    title: 'GitHub fine-grained personal access token',
    provider: 'GitHub',
    pattern: /(?<![A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{36,255})(?![A-Za-z0-9_])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'critical',
    rationale: 'Fine-grained PATs carry repository-scoped write access and are never client-side artefacts.',
    nextStep: 'Report for revocation.',
  },
  {
    id: 'gitlab-token',
    title: 'GitLab personal access token',
    provider: 'GitLab',
    pattern: /(?<![A-Za-z0-9-])(glpat-[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'critical',
    rationale: 'glpat- is the GitLab PAT prefix; these are server credentials.',
  },

  // -------------------------------------------------------------- Slack -----
  {
    id: 'slack-token',
    title: 'Slack API token',
    provider: 'Slack',
    pattern: /(?<![A-Za-z0-9-])(xox[baprse]-[A-Za-z0-9-]{10,})(?![A-Za-z0-9-])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'critical',
    rationale:
      'Slack bot (xoxb), app (xoxa), user (xoxp), refresh (xoxe), legacy (xoxr/xoxs) tokens all grant workspace API access.',
    nextStep: 'Report for revocation; auth.test confirms the workspace without reading messages.',
  },
  {
    id: 'slack-webhook',
    title: 'Slack incoming webhook URL',
    provider: 'Slack',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9]{20,}/g,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'high',
    rationale:
      'A webhook URL is a bearer credential: anyone holding it can post into the channel it targets.',
    nextStep: 'Report as message-injection / phishing surface into an internal channel.',
  },

  // ------------------------------------------------------------- Twilio -----
  {
    id: 'twilio-api-key-sid',
    title: 'Twilio API key SID',
    provider: 'Twilio',
    pattern: /(?<![A-Za-z0-9])(SK[0-9a-fA-F]{32})(?![A-Za-z0-9])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'depends',
    severity: 'medium',
    rationale:
      'An SK SID is the public half of a Twilio API key pair. On its own it authenticates nothing; with the matching secret it is full account access.',
    nextStep: 'Search the same assets for the paired 32-character secret before reporting.',
  },
  {
    id: 'twilio-account-sid',
    title: 'Twilio account SID',
    provider: 'Twilio',
    pattern: /(?<![A-Za-z0-9])(AC[0-9a-f]{32})(?![A-Za-z0-9])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'public',
    severity: 'info',
    rationale: `An account SID is an identifier, not a credential, and client SDKs legitimately carry it. ${PUBLIC_BY_DESIGN}`,
  },
  {
    id: 'twilio-auth-token',
    title: 'Twilio auth token (contextual)',
    provider: 'Twilio',
    pattern: /(?<![A-Za-z0-9])([0-9a-f]{32})(?![A-Za-z0-9])/g,
    group: 1,
    classification: 'heuristic',
    exposure: 'secret',
    severity: 'critical',
    minEntropy: 3.2,
    requireContext: /twilio|auth[_-]?token/i,
    rationale:
      'A 32-character hex value with Twilio context. Bare 32-char hex is usually an MD5 or build hash, so this rule requires the context to fire.',
  },

  // ----------------------------------------------------------- SendGrid -----
  {
    id: 'sendgrid-api-key',
    title: 'SendGrid API key',
    provider: 'SendGrid',
    pattern: /(?<![A-Za-z0-9._-])(SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{32,64})(?![A-Za-z0-9_-])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'critical',
    rationale: 'SendGrid keys are three dot-separated parts behind an SG. prefix and allow sending mail as the tenant.',
    nextStep: 'Report as an email-spoofing capability from the victim’s domain.',
  },

  // -------------------------------------------------------- LLM vendors -----
  {
    id: 'openai-api-key',
    title: 'OpenAI API key',
    provider: 'OpenAI',
    // `sk-ant-` must be excluded explicitly: the character class contains the
    // hyphen, so an Anthropic key matched this pattern too and was reported
    // twice, the second time naming the wrong vendor.
    pattern: /(?<![A-Za-z0-9_-])(sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,})(?![A-Za-z0-9_-])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'critical',
    minEntropy: 3.5,
    rationale:
      'OpenAI keys are billed per token and have no client-side restriction model. A key in a bundle is a direct financial loss.',
    nextStep: 'Report for rotation and note the billing-abuse impact.',
  },
  {
    id: 'anthropic-api-key',
    title: 'Anthropic API key',
    provider: 'Anthropic',
    pattern: /(?<![A-Za-z0-9_-])(sk-ant-(?:api|sid)[0-9]{2}-[A-Za-z0-9_-]{32,})(?![A-Za-z0-9_-])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'critical',
    rationale: 'Anthropic API keys are server credentials billed per token.',
    nextStep: 'Report for rotation and note the billing-abuse impact.',
  },

  // --------------------------------------------------------------- JWTs -----
  {
    id: 'jwt',
    title: 'JSON Web Token',
    pattern: /(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'depends',
    severity: 'medium',
    rationale:
      'A three-part JWT. Whether it matters depends entirely on its claims, which this tool decodes below.',
    refine: (match) => {
      const parts = match.value.split('.');
      const header = decodeJwtSegment(parts[0] ?? '');
      const payload = decodeJwtSegment(parts[1] ?? '');
      // Base64 that merely starts with `eyJ` is common; only a decodable
      // header *and* payload make this a JWT.
      if (!header || !payload) return { discard: true };

      const role = typeof payload['role'] === 'string' ? (payload['role'] as string) : null;
      const exp = typeof payload['exp'] === 'number' ? (payload['exp'] as number) : null;
      const issuer = typeof payload['iss'] === 'string' ? (payload['iss'] as string) : '';
      const algorithm = typeof header['alg'] === 'string' ? (header['alg'] as string) : '?';
      const expired = exp !== null && exp * 1000 < Date.now();
      const claims = Object.keys(payload).slice(0, 8).join(', ');

      if (role === 'service_role') {
        return {
          title: 'Supabase service_role JWT',
          provider: 'Supabase',
          exposure: 'secret',
          severity: 'critical',
          rationale:
            'The payload carries role=service_role. That key bypasses every row-level security policy on the project; it is the Supabase equivalent of a database superuser and must never reach a client.',
          nextStep:
            'Report immediately. The anon key looks almost identical, so state the decoded role claim as evidence.',
        };
      }
      if (role === 'anon') {
        return {
          title: 'Supabase anon JWT',
          provider: 'Supabase',
          exposure: 'public',
          severity: 'info',
          rationale: `The payload carries role=anon. Supabase clients require this key in the browser; it is only as powerful as the project’s row-level security policies. ${PUBLIC_BY_DESIGN}`,
          nextStep:
            'Not a leak. The real test is whether RLS is enabled on each table — use the key to check, not to report.',
        };
      }
      if (algorithm.toLowerCase() === 'none') {
        return {
          exposure: 'secret',
          severity: 'high',
          rationale:
            'The JWT header declares alg=none, meaning the signature is not verified by whatever issued it. That is a token-forgery primitive regardless of the claims.',
        };
      }
      const descriptor = [
        `alg=${algorithm}`,
        issuer ? `iss=${issuer}` : null,
        expired ? 'expired' : exp !== null ? 'unexpired' : 'no exp claim',
        claims ? `claims: ${claims}` : null,
      ]
        .filter((part): part is string => part !== null)
        .join(', ');

      return {
        severity: expired ? 'info' : 'medium',
        rationale: expired
          ? `Decoded JWT (${descriptor}). Already expired, so it is evidence of a token-handling habit rather than a live credential.`
          : `Decoded JWT (${descriptor}). A session or API token baked into a build is shared by every visitor; check whether it authenticates as a real principal.`,
        nextStep: expired
          ? 'Note the pattern; check whether a current build ships an unexpired one.'
          : 'Replay against the API with no other credential to establish whether it grants access.',
      };
    },
  },

  // ------------------------------------------------------- Private keys -----
  {
    id: 'private-key-pem',
    title: 'Private key (PEM header)',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'critical',
    rationale:
      'A PEM private-key header. There is no client-side use for a private key; signing and decryption belong on a server.',
    nextStep: 'Recover the full block from the asset and report for rotation of whatever it signs.',
  },

  // ---------------------------------------------------------- Platforms -----
  {
    id: 'npm-token',
    title: 'npm access token',
    provider: 'npm',
    pattern: /(?<![A-Za-z0-9_])(npm_[A-Za-z0-9]{36})(?![A-Za-z0-9])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'critical',
    rationale: 'An npm token can publish packages under the owning account.',
    nextStep: 'Report for revocation; note the supply-chain impact on anything the account publishes.',
  },
  {
    id: 'shopify-access-token',
    title: 'Shopify access token',
    provider: 'Shopify',
    pattern: /(?<![A-Za-z0-9_])(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})(?![A-Za-z0-9])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'critical',
    rationale: 'Shopify admin/private app tokens grant store-level API access.',
  },
  {
    id: 'mapbox-token',
    title: 'Mapbox access token',
    provider: 'Mapbox',
    pattern: /(?<![A-Za-z0-9._-])((?:pk|sk|tk)\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'depends',
    severity: 'medium',
    rationale: 'Mapbox tokens are prefixed by scope: pk is public, sk is secret.',
    refine: (match) =>
      match.value.startsWith('sk.')
        ? {
            exposure: 'secret',
            severity: 'high',
            rationale:
              'An sk. Mapbox token carries account-management scopes and is explicitly documented as server-only.',
          }
        : {
            exposure: 'public',
            severity: 'info',
            rationale: `A pk. Mapbox token is designed for browser use and is restricted by URL allowlist. ${PUBLIC_BY_DESIGN}`,
          },
  },
  {
    id: 'algolia-api-key',
    title: 'Algolia API key (contextual)',
    provider: 'Algolia',
    pattern: /(?<![A-Za-z0-9])([a-f0-9]{32})(?![A-Za-z0-9])/g,
    group: 1,
    classification: 'heuristic',
    exposure: 'depends',
    severity: 'low',
    minEntropy: 3.2,
    requireContext: /algolia|searchKey|searchOnlyApiKey|ALGOLIA_/i,
    rationale:
      'A 32-character hex key with Algolia context. Search-only keys ship to browsers by design; admin keys do not.',
    refine: (match) =>
      /admin/i.test(match.context)
        ? {
            exposure: 'secret',
            severity: 'critical',
            rationale:
              'Algolia context mentions an admin key. Admin keys can rewrite and delete indices.',
            nextStep: 'Report for rotation; admin keys allow index destruction.',
          }
        : {
            exposure: 'public',
            severity: 'info',
            rationale: `Algolia search-only keys are embedded in browser code by design. ${PUBLIC_BY_DESIGN}`,
          },
  },
  {
    id: 'fcm-server-key',
    title: 'Firebase Cloud Messaging server key',
    provider: 'Firebase',
    pattern: /(?<![A-Za-z0-9_-])(AAAA[A-Za-z0-9_-]{5,12}:[A-Za-z0-9_-]{100,})(?![A-Za-z0-9_-])/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'high',
    rationale:
      'An FCM legacy server key lets anyone send push notifications to every device registered to the project. Distinct from the public web config.',
    nextStep: 'Report as arbitrary push-notification injection to the app’s install base.',
  },
  {
    id: 'azure-storage-key',
    title: 'Azure Storage account key',
    provider: 'Azure',
    pattern: /AccountKey=([A-Za-z0-9+/=]{64,100})/g,
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'critical',
    rationale: 'An Azure Storage connection string AccountKey grants full control of the storage account.',
  },

  // -------------------------------------------------------- Credentials -----
  {
    id: 'basic-auth-url',
    title: 'URL with embedded credentials',
    // Database URIs are covered by their own rule, which reasons about
    // whether a password is present; excluding them here avoids two findings
    // for one credential.
    pattern: new RegExp(
      String.raw`(?<![A-Za-z0-9+.-])(?!(?:${DB_SCHEMES}):)` +
        String.raw`[a-z][a-z0-9+.-]*:\/\/[^\s:@/"'` +
        '`' +
        String.raw`<>]{1,64}:[^\s:@/"'` +
        '`' +
        String.raw`<>]{3,64}@[A-Za-z0-9._-]+\.[A-Za-z]{2,}[^\s"'` +
        '`' +
        String.raw`<>]*`,
      'g',
    ),
    classification: 'confirmed-shape',
    exposure: 'secret',
    severity: 'high',
    rationale: 'A URL of the form scheme://user:password@host carries a usable credential inline.',
    nextStep: 'Identify the service and report the credential pair.',
  },
  {
    id: 'database-connection-string',
    title: 'Database connection string',
    pattern: new RegExp(
      String.raw`(?<![A-Za-z0-9+.-])((?:${DB_SCHEMES}):\/\/[^\s"'` + '`' + String.raw`<>]{8,200})`,
      'g',
    ),
    group: 1,
    classification: 'confirmed-shape',
    exposure: 'depends',
    severity: 'medium',
    rationale:
      'A database URI in client code names an internal host, and often a port and database name, even when no password is present.',
    refine: (match) => {
      const hasPassword = /:\/\/[^:@/\s]+:[^@/\s]+@/.test(match.value);
      // Match a loopback host whether or not userinfo precedes it: both
      // postgres://localhost/db and postgres://user@localhost/db are local.
      const localOnly = /(?:@|\/\/)(localhost|127\.0\.0\.1|\[::1\]|::1)(:|\/|$)/.test(match.value);
      if (hasPassword) {
        return {
          exposure: 'secret',
          severity: 'critical',
          rationale:
            'The URI includes a password. This is a direct database credential in a client-delivered asset.',
          nextStep: 'Report for rotation. Do not connect.',
        };
      }
      if (localOnly) {
        return {
          exposure: 'public',
          severity: 'info',
          rationale:
            'A localhost database URI, almost always a development default left in the build. No credential, no reachable host.',
        };
      }
      return {
        rationale:
          'A database URI with no password. Useful recon — it names an internal hostname and database — but not a credential by itself.',
        nextStep: 'Record the hostname for the internal-surface section of the report; check it against SSRF sinks.',
      };
    },
  },
  {
    id: 'generic-assigned-secret',
    title: 'High-entropy value assigned to a secret-looking name',
    pattern:
      /["'`]?\b(?:api[_-]?key|apikey|secret|secret[_-]?key|client[_-]?secret|password|passwd|pwd|auth[_-]?token|access[_-]?token|refresh[_-]?token|private[_-]?key|bearer[_-]?token|session[_-]?secret|encryption[_-]?key)\b["'`]?\s*[:=]\s*["'`]([^"'`\s]{14,200})["'`]/gi,
    group: 1,
    classification: 'heuristic',
    exposure: 'depends',
    severity: 'medium',
    minEntropy: 3.4,
    rationale:
      'A high-entropy string literal assigned to a name that claims to be a credential. The name is the only evidence of purpose, so treat this as a lead, not a conclusion.',
    nextStep:
      'Read the surrounding code to see what consumes it. Public client keys are frequently stored under names like apiKey.',
  },
];

/**
 * Values that are documentation examples or scaffolding, not live credentials.
 *
 * A match downgrades the finding to informational rather than suppressing it,
 * because a placeholder in production code is still worth a line in a report.
 * The `EXAMPLE`/`SAMPLE` patterns are deliberately uppercase and anchored:
 * AWS writes its documentation key as `AKIAIOSFODNN7EXAMPLE`, but
 * `db.prod.example.net` is a hostname and must not be downgraded.
 */
export const PLACEHOLDER_PATTERNS: readonly RegExp[] = [
  /^(.)\1{5,}$/, // aaaaaaaa, 00000000
  /\b(?:YOUR|MY|SOME)[_-]?(?:KEY|TOKEN|SECRET|API|PASSWORD|VALUE)/i,
  /(?:REPLACE[_-]?ME|CHANGE[_-]?ME|PLACEHOLDER|INSERT[_-]?YOUR|XXXXXX)/i,
  /(?:EXAMPLE|SAMPLE|DUMMY|NOTREAL|FAKEKEY)$/,
  /^(?:test|demo|foo|bar|baz|abc)(?:[_-]?(?:key|token|secret|value))?$/i,
  /^(?:0123456789|1234567890|abcdef0123|deadbeef)/i,
  /^<.*>$/,
];
