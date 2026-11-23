import type { AutofillSecurityVerdictDto, SecurityRiskLevel } from "../shared/messages.js";

const MIXED_NON_LATIN_REGEX = /[\u0370-\u05FF\u0600-\u06FF\u1F00-\u1FFF]/;
const LATIN_REGEX = /[A-Za-z\u00C0-\u024F\u1E00-\u1EFF]/;

function extractRawHost(rawUrl: string): string | null {
  const trimmed = rawUrl.trim();
  const afterScheme = trimmed.includes("://") ? trimmed.split("://")[1] ?? "" : trimmed;
  const authority = afterScheme.split(/[/?#]/)[0] ?? "";
  const hostPort = authority.includes("@") ? authority.split("@").pop() ?? "" : authority;
  if (!hostPort) return null;
  if (hostPort.startsWith("[")) {
    const close = hostPort.indexOf("]");
    return close > 0 ? hostPort.slice(1, close) : null;
  }
  return hostPort.split(":")[0] ?? null;
}

export function isLoopbackHostname(host: string): boolean {
  const clean = host.replace(/^\[|\]$/g, "").toLowerCase();
  return clean === "localhost" || clean === "127.0.0.1" || clean === "::1";
}

export function normalizeHttpOrigin(rawUrl: string): string | null {
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      return null;
    }
    return url.origin.toLowerCase();
  } catch {
    return null;
  }
}

export function detectHostScriptSpoof(rawUrl: string): { punycode: boolean; mixedScript: boolean } {
  const rawHost = extractRawHost(rawUrl) ?? "";
  const mixedScript = rawHost
    .split(".")
    .some((label) => LATIN_REGEX.test(label) && MIXED_NON_LATIN_REGEX.test(label));

  let punycode = false;
  try {
    const parsed = new URL(rawUrl);
    punycode = parsed.hostname
      .toLowerCase()
      .split(".")
      .some((label) => label.startsWith("xn--"));
  } catch {
    punycode = false;
  }

  return { punycode, mixedScript };
}

/**
 * Synchronous content-script gate verifying scheme, TLS, IDN homographs, and cross-origin iframes.
 * Never replaces the authoritative Rust/WASM `psl` check performed inside the background worker.
 */
export function assessPageContext(
  topFrameUrl: string,
  activeFrameUrl: string,
  isIframe: boolean,
  approvedOrigins: string[] = [],
): AutofillSecurityVerdictDto {
  const origin = normalizeHttpOrigin(activeFrameUrl);
  if (!origin) {
    return {
      allowed: false,
      silent_autofill_allowed: false,
      risk_level: "blocked_invalid_url",
      host: null,
      registrable_domain: null,
      origin: null,
      is_secure_context: false,
      is_idn_punycode: false,
      is_mixed_script: false,
      reasons: ["URL ou protocole non pris en charge par Anvil"],
    };
  }

  const parsed = new URL(activeFrameUrl);
  const host = parsed.hostname.toLowerCase();
  const isSecure = parsed.protocol === "https:" || isLoopbackHostname(host);
  const activeSpoof = detectHostScriptSpoof(activeFrameUrl);
  const topSpoof = detectHostScriptSpoof(topFrameUrl);

  if (activeSpoof.mixedScript || topSpoof.mixedScript) {
    return {
      allowed: false,
      silent_autofill_allowed: false,
      risk_level: "blocked_idn_homograph",
      host,
      registrable_domain: null,
      origin,
      is_secure_context: isSecure,
      is_idn_punycode: activeSpoof.punycode || topSpoof.punycode,
      is_mixed_script: true,
      reasons: ["Nom de domaine homographe multi-scripts bloqué (protection anti-phishing)"],
    };
  }

  if (isIframe) {
    const topOrigin = normalizeHttpOrigin(topFrameUrl);
    const approvedSet = new Set(
      approvedOrigins.map((entry) => normalizeHttpOrigin(entry)).filter(Boolean),
    );
    if (!topOrigin || (topOrigin !== origin && !approvedSet.has(origin))) {
      return {
        allowed: false,
        silent_autofill_allowed: false,
        risk_level: "blocked_cross_origin_iframe",
        host,
        registrable_domain: null,
        origin,
        is_secure_context: isSecure,
        is_idn_punycode: activeSpoof.punycode,
        is_mixed_script: false,
        reasons: [`Iframe cross-origin bloquée (${origin})`],
      };
    }
  }

  const reasons: string[] = [];
  let riskLevel: SecurityRiskLevel = "safe";
  let silentAllowed = true;

  if (!isSecure) {
    riskLevel = "warn_http";
    silentAllowed = false;
    reasons.push("Connexion HTTP non chiffrée : vérifiez l'URL avant de remplir");
  }
  if (activeSpoof.punycode) {
    silentAllowed = false;
    reasons.push("Domaine internationalisé Punycode (xn--) : confirmation requise");
  }

  return {
    allowed: true,
    silent_autofill_allowed: silentAllowed,
    risk_level: riskLevel,
    host,
    registrable_domain: null,
    origin,
    is_secure_context: isSecure,
    is_idn_punycode: activeSpoof.punycode,
    is_mixed_script: false,
    reasons,
  };
}

/** Injects text using native property descriptor setters so React/Vue/Svelte inputs update cleanly. */
export function setNativeInputValue(input: HTMLInputElement, value: string): void {
  const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
  if (descriptor && typeof descriptor.set === "function") {
    descriptor.set.call(input, value);
  } else {
    input.value = value;
  }
  input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}
