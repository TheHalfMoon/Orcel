import assert from "node:assert/strict";
import test from "node:test";
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  generateDeviceKeyPair,
  publicDeviceIdentity,
  revokeDevice,
  revokePrincipal,
  rotateDeviceKeyPair,
  signDeviceChallenge,
  emergencyRevoke,
  type DeviceKeyPair
} from "./device_identity.js";
import {
  ACCESS_TOKEN_LIFETIME_SECONDS,
  ACCESS_TOKEN_MAX_CHARS,
  AUTHORIZATION_CODE_LIFETIME_SECONDS,
  LOCAL_ONLY_TOOL_NAMES,
  OAUTH_LOCAL_AUTHORITY_GRANTED,
  OAUTH_PROFILE_TOOL_CEILINGS,
  OAUTH_SCOPE_TOOL_MATRIX,
  OAUTH_SCOPES,
  REFRESH_FAMILY_MAX_LIFETIME_SECONDS,
  UNMAPPED_REMOTE_PROFILES,
  applyTokenRevocation,
  authorizeToolByScopes,
  buildAuthorizationResponseUrl,
  buildAuthorizationServerMetadata,
  buildProtectedResourceMetadata,
  createRefreshFamily,
  createRefreshProofChallenge,
  generatePkceVerifier,
  generateRemoteConnectionId,
  generateRemotePrincipalId,
  generateTokenSigningKey,
  isAcceptableRedirectUri,
  redirectUriMatches,
  isClientIdMetadataDocumentUrl,
  isIssuerIdentifier,
  isResourceIdentifier,
  issueAuthorizationCode,
  mintAccessTokenClaims,
  oauthFailuresAreFrozenSubset,
  parseScopeString,
  pkceS256Challenge,
  redactedIdentitySummary,
  redeemAuthorizationCode,
  redeemRefreshToken,
  revokeRefreshFamily,
  signAccessToken,
  validateAuthorizationRequest,
  validateAuthorizationServerMetadata,
  validateClientRegistration,
  validateProtectedResourceMetadata,
  verificationKeyOf,
  verifyAccessToken,
  verifyAuthorizationResponse,
  verifyClientIdentification,
  verifyPkceS256,
  type AccessTokenClaims,
  type AccessTokenVerificationContext,
  type AuthorizationCodeRecord,
  type ClientIdentificationHook,
  type ClientIdentificationMethod,
  type ClientRegistration,
  type RefreshFamily,
  type RemoteBinding,
  type TokenSigningKey
} from "./oauth_authorization.js";
import { RELAY_FAILURE_CODES } from "./relay_contract.js";
import { CANONICAL_TOOL_NAMES } from "./server.js";

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, "..", "src");

function readSource(rel: string): string {
  try {
    return readFileSync(join(srcDir, rel), "utf8");
  } catch {
    return readFileSync(join(here, rel), "utf8");
  }
}

const NOW = 1798765432100;
const ISSUER = "https://auth.orcel.example";
const RESOURCE = "https://relay.orcel.example/mcp";
const REDIRECT = "https://provider.example/oauth/callback";
const CLIENT_ID = "https://provider.example/oauth/client.json";
const DEVICE_ID = "dev-" + "ab".repeat(16);

const CLIENT: ClientRegistration = {
  clientId: CLIENT_ID,
  providerKind: "generic",
  redirectUris: [REDIRECT],
  identification: "client_id_metadata_document",
  allowedScopes: ["orcel.read", "orcel.write"]
};

const CLIENTS = new Map<string, ClientRegistration>([[CLIENT_ID, CLIENT]]);

interface Harness {
  readonly device: DeviceKeyPair;
  readonly binding: RemoteBinding;
  readonly key: TokenSigningKey;
  readonly verifier: string;
}

function harness(): Harness {
  const device = generateDeviceKeyPair(DEVICE_ID, NOW, 1);
  return {
    device,
    binding: {
      principal: generateRemotePrincipalId(),
      connection: generateRemoteConnectionId(),
      deviceId: DEVICE_ID,
      epoch: 1
    },
    key: generateTokenSigningKey(),
    verifier: generatePkceVerifier()
  };
}

function authorize(h: Harness, scope = "orcel.read orcel.write") {
  const result = validateAuthorizationRequest(
    {
      response_type: "code",
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT,
      code_challenge: pkceS256Challenge(h.verifier),
      code_challenge_method: "S256",
      resource: RESOURCE,
      scope,
      state: "state-" + "x".repeat(24)
    },
    { issuer: ISSUER, resource: RESOURCE },
    CLIENTS,
    NOW
  );
  assert.ok(result.ok, "authorization request must validate");
  return result.transaction;
}

function redeemed(h: Harness): AuthorizationCodeRecord {
  const tx = authorize(h);
  const { code, record } = issueAuthorizationCode(tx, h.binding, NOW);
  const result = redeemAuthorizationCode(
    record,
    {
      grant_type: "authorization_code",
      code,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT,
      code_verifier: h.verifier,
      resource: RESOURCE
    },
    NOW + 1000
  );
  assert.ok(result.check.ok);
  return result.next;
}

function family(h: Harness): { refreshToken: string; family: RefreshFamily } {
  return createRefreshFamily(redeemed(h), NOW + 2000);
}

function context(h: Harness, overrides: Partial<AccessTokenVerificationContext> = {}): AccessTokenVerificationContext {
  return {
    issuer: ISSUER,
    resource: RESOURCE,
    keys: [verificationKeyOf(h.key)],
    nowMs: NOW + 5000,
    revokedTokenIds: new Set(),
    revokedFamilyIds: new Set(),
    revocations: [],
    deviceEpochs: new Map([[DEVICE_ID, 1]]),
    ...overrides
  };
}

function tokenFor(h: Harness, mutate: (claims: AccessTokenClaims) => AccessTokenClaims = (c) => c): {
  token: string;
  claims: AccessTokenClaims;
} {
  const fam = family(h).family;
  const claims = mutate(mintAccessTokenClaims(ISSUER, RESOURCE, fam, fam.scopes, NOW + 3000));
  return { token: signAccessToken(claims, h.key), claims };
}

function b64(value: object): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function expectDenied(
  result: { ok: boolean; failure?: string; reason?: string },
  failure: string,
  reason: string
): void {
  assert.equal(result.ok, false);
  assert.equal(result.failure, failure);
  assert.equal(result.reason, reason);
}

// ---------------------------------------------------------------------------

test("oauth failures are a strict subset of the frozen relay vocabulary", () => {
  assert.ok(oauthFailuresAreFrozenSubset());
  assert.equal(RELAY_FAILURE_CODES.length, 17);
});

test("scope vocabulary is exactly read, write, execute and parsing denies unknown scopes", () => {
  assert.deepEqual([...OAUTH_SCOPES], ["orcel.read", "orcel.write", "orcel.execute"]);
  const ok = parseScopeString("orcel.read orcel.write");
  assert.ok(ok.ok);
  expectDenied(parseScopeString("orcel.read orcel.admin") as never, "REMOTE_SCOPE_DENIED", "scope_unknown");
  expectDenied(parseScopeString("orcel.read  orcel.write") as never, "REMOTE_SCOPE_DENIED", "scope_unknown");
  expectDenied(parseScopeString("orcel.read orcel.read") as never, "REMOTE_SCOPE_DENIED", "scope_unknown");
  expectDenied(parseScopeString("") as never, "REMOTE_SCOPE_DENIED", "scope_missing");
  expectDenied(parseScopeString(undefined) as never, "REMOTE_SCOPE_DENIED", "scope_missing");
});

test("issuer, resource, redirect, and client metadata URL shapes are strict", () => {
  assert.ok(isIssuerIdentifier(ISSUER));
  assert.ok(isIssuerIdentifier("https://auth.orcel.example/tenant"));
  assert.ok(!isIssuerIdentifier("http://auth.orcel.example"));
  assert.ok(!isIssuerIdentifier("https://auth.orcel.example/"));
  assert.ok(!isIssuerIdentifier("https://auth.orcel.example?x=1"));
  assert.ok(!isIssuerIdentifier("https://user:pw@auth.orcel.example"));
  assert.ok(!isIssuerIdentifier("HTTPS://Auth.Orcel.Example"));
  assert.ok(isResourceIdentifier(RESOURCE));
  assert.ok(!isResourceIdentifier("https://relay.orcel.example/mcp#x"));
  assert.ok(!isResourceIdentifier("http://relay.orcel.example/mcp"));
  assert.ok(isResourceIdentifier("http://127.0.0.1:8787/mcp"), "exact loopback self-host");
  assert.ok(isIssuerIdentifier("http://127.0.0.1:8787"));
  assert.ok(isIssuerIdentifier("http://[::1]:8787"));
  for (const notLoopback of ["http://localhost:8787", "http://127.0.0.2:8787", "http://10.0.0.1:8787", "http://127.0.0.1.nip.io:8787"]) {
    assert.ok(!isIssuerIdentifier(notLoopback), notLoopback);
    assert.ok(!isResourceIdentifier(notLoopback + "/mcp"), notLoopback);
  }
  assert.ok(isAcceptableRedirectUri(REDIRECT));
  assert.ok(isAcceptableRedirectUri("http://127.0.0.1:43123/callback"));
  // SG-000068: native clients (Claude Code) redirect to localhost; accepted
  // for redirect URIs only, never for issuer or resource identifiers.
  assert.ok(isAcceptableRedirectUri("http://localhost:43123/callback"));
  assert.ok(!isAcceptableRedirectUri("http://localhost.evil.example:43123/callback"));
  assert.ok(!isAcceptableRedirectUri("http://user@localhost:43123/callback"));
  assert.ok(!isAcceptableRedirectUri("http://provider.example/callback"));
  assert.ok(!isAcceptableRedirectUri("https://provider.example/callback#frag"));
  assert.ok(isClientIdMetadataDocumentUrl(CLIENT_ID));
  assert.ok(!isClientIdMetadataDocumentUrl("https://provider.example/"));
  assert.ok(!isClientIdMetadataDocumentUrl("https://provider.example/a/../client.json"));
  assert.ok(!isClientIdMetadataDocumentUrl("http://provider.example/client.json"));
});

test("authorization-server and protected-resource metadata are standards-shaped and validated", () => {
  const as = buildAuthorizationServerMetadata(ISSUER);
  assert.equal(as.issuer, ISSUER);
  assert.deepEqual(as.code_challenge_methods_supported, ["S256"]);
  assert.deepEqual(as.response_types_supported, ["code"]);
  assert.deepEqual(as.grant_types_supported, ["authorization_code", "refresh_token"]);
  assert.equal(as.authorization_response_iss_parameter_supported, true);
  assert.equal(as.token_endpoint, ISSUER + "/oauth/token");
  assert.ok(validateAuthorizationServerMetadata(as, ISSUER).ok);
  expectDenied(
    validateAuthorizationServerMetadata(as, "https://evil.example") as never,
    "REMOTE_AUTH_INVALID",
    "wrong_issuer"
  );
  expectDenied(
    validateAuthorizationServerMetadata({ ...as, code_challenge_methods_supported: ["plain", "S256"] }, ISSUER) as never,
    "REMOTE_AUTH_INVALID",
    "metadata_invalid"
  );
  expectDenied(
    validateAuthorizationServerMetadata({ ...as, response_types_supported: ["code", "token"] }, ISSUER) as never,
    "REMOTE_AUTH_INVALID",
    "metadata_invalid"
  );
  expectDenied(
    validateAuthorizationServerMetadata({ ...as, grant_types_supported: ["authorization_code", "password"] }, ISSUER) as never,
    "REMOTE_AUTH_INVALID",
    "metadata_invalid"
  );
  expectDenied(
    validateAuthorizationServerMetadata({ ...as, token_endpoint: "https://evil.example/token" }, ISSUER) as never,
    "REMOTE_AUTH_INVALID",
    "metadata_invalid"
  );
  expectDenied(
    validateAuthorizationServerMetadata({ ...as, authorization_response_iss_parameter_supported: false }, ISSUER) as never,
    "REMOTE_AUTH_INVALID",
    "metadata_invalid"
  );
  expectDenied(validateAuthorizationServerMetadata("nope", ISSUER) as never, "REMOTE_AUTH_INVALID", "metadata_invalid");

  const pr = buildProtectedResourceMetadata(RESOURCE, ISSUER);
  assert.equal(pr.resource, RESOURCE);
  assert.deepEqual(pr.authorization_servers, [ISSUER]);
  assert.deepEqual(pr.bearer_methods_supported, ["header"]);
  assert.ok(validateProtectedResourceMetadata(pr, RESOURCE, ISSUER).ok);
  expectDenied(
    validateProtectedResourceMetadata(pr, "https://other.example/mcp", ISSUER) as never,
    "REMOTE_AUTH_INVALID",
    "wrong_resource"
  );
  expectDenied(
    validateProtectedResourceMetadata({ ...pr, authorization_servers: [ISSUER, "https://evil.example"] }, RESOURCE, ISSUER) as never,
    "REMOTE_AUTH_INVALID",
    "wrong_issuer"
  );
  expectDenied(
    validateProtectedResourceMetadata({ ...pr, bearer_methods_supported: ["header", "query"] }, RESOURCE, ISSUER) as never,
    "REMOTE_AUTH_INVALID",
    "metadata_invalid"
  );
  assert.throws(() => buildAuthorizationServerMetadata("http://auth.orcel.example"));
  assert.throws(() => buildProtectedResourceMetadata("http://relay.orcel.example/mcp", ISSUER));
});

test("PKCE accepts only S256 with a matching verifier", () => {
  const verifier = generatePkceVerifier();
  const challenge = pkceS256Challenge(verifier);
  assert.ok(verifyPkceS256(verifier, challenge, "S256").ok);
  // RFC 7636 appendix B test vector.
  assert.equal(
    pkceS256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  );
  expectDenied(verifyPkceS256(verifier, challenge, "plain") as never, "REMOTE_AUTH_INVALID", "pkce_method_unsupported");
  expectDenied(
    verifyPkceS256(generatePkceVerifier(), challenge, "S256") as never,
    "REMOTE_AUTH_INVALID",
    "pkce_mismatch"
  );
  expectDenied(verifyPkceS256("short", challenge, "S256") as never, "REMOTE_AUTH_INVALID", "pkce_verifier_invalid");
  expectDenied(verifyPkceS256(verifier, "bad", "S256") as never, "REMOTE_AUTH_INVALID", "pkce_challenge_invalid");
});

test("authorization requests bind client, exact redirect, PKCE S256, exact resource, scopes, and state", () => {
  const h = harness();
  const base = {
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT,
    code_challenge: pkceS256Challenge(h.verifier),
    code_challenge_method: "S256",
    resource: RESOURCE,
    scope: "orcel.read",
    state: "s".repeat(32)
  };
  const config = { issuer: ISSUER, resource: RESOURCE };
  const ok = validateAuthorizationRequest(base, config, CLIENTS, NOW);
  assert.ok(ok.ok);
  if (ok.ok) {
    assert.match(ok.transaction.transactionId, /^tx-[0-9a-f]{32}$/);
    assert.deepEqual(ok.transaction.scopes, ["orcel.read"]);
  }
  const cases: Array<[Record<string, unknown>, string, string]> = [
    [{ client_id: "https://unknown.example/c.json" }, "REMOTE_AUTH_INVALID", "client_unknown"],
    [{ redirect_uri: REDIRECT + "/extra" }, "REMOTE_AUTH_INVALID", "redirect_mismatch"],
    [{ response_type: "token" }, "REMOTE_AUTH_INVALID", "unsupported_response_type"],
    [{ code_challenge_method: "plain" }, "REMOTE_AUTH_INVALID", "pkce_method_unsupported"],
    [{ code_challenge: undefined }, "REMOTE_AUTH_INVALID", "pkce_challenge_invalid"],
    [{ resource: "https://other.example/mcp" }, "REMOTE_AUTH_INVALID", "wrong_resource"],
    [{ resource: undefined }, "REMOTE_AUTH_INVALID", "wrong_resource"],
    [{ scope: "orcel.read orcel.root" }, "REMOTE_SCOPE_DENIED", "scope_unknown"],
    [{ scope: "orcel.execute" }, "REMOTE_SCOPE_DENIED", "scope_not_permitted"],
    [{ scope: undefined }, "REMOTE_SCOPE_DENIED", "scope_missing"],
    [{ state: "short" }, "REMOTE_AUTH_INVALID", "state_missing"],
    [{ state: undefined }, "REMOTE_AUTH_INVALID", "state_missing"]
  ];
  for (const [patch, failure, reason] of cases) {
    const result = validateAuthorizationRequest({ ...base, ...patch } as never, config, CLIENTS, NOW);
    expectDenied(result as never, failure, reason);
  }
});

test("authorization codes are short-lived, one-shot, and bound to client, redirect, resource, and PKCE", () => {
  const h = harness();
  const tx = authorize(h);
  const { code, record } = issueAuthorizationCode(tx, h.binding, NOW);
  assert.ok(!JSON.stringify(record).includes(code), "only the code hash is stored");
  const request = {
    grant_type: "authorization_code",
    code,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT,
    code_verifier: h.verifier,
    resource: RESOURCE
  };
  const first = redeemAuthorizationCode(record, request, NOW + 1000);
  assert.ok(first.check.ok);
  assert.equal(first.next.consumed, true);
  const replay = redeemAuthorizationCode(first.next, request, NOW + 2000);
  expectDenied(replay.check as never, "REMOTE_AUTH_INVALID", "code_replayed");
  assert.equal(replay.revokeIssuedFamily, true);

  const expired = redeemAuthorizationCode(record, request, NOW + AUTHORIZATION_CODE_LIFETIME_SECONDS * 1000 + 1);
  expectDenied(expired.check as never, "REMOTE_AUTH_INVALID", "code_expired");
  assert.equal(expired.next.consumed, true);

  const cases: Array<[Record<string, unknown>, string]> = [
    [{ grant_type: "password" }, "unsupported_grant_type"],
    [{ code: "A".repeat(43) }, "code_invalid"],
    [{ code: "not a code" }, "code_invalid"],
    [{ client_id: "https://other.example/c.json" }, "client_mismatch"],
    [{ redirect_uri: "https://provider.example/other" }, "redirect_mismatch"],
    [{ resource: "https://other.example/mcp" }, "wrong_resource"],
    [{ code_verifier: generatePkceVerifier() }, "pkce_mismatch"],
    [{ code_verifier: undefined }, "pkce_verifier_invalid"]
  ];
  for (const [patch, reason] of cases) {
    const result = redeemAuthorizationCode(record, { ...request, ...patch } as never, NOW + 1000);
    expectDenied(result.check as never, "REMOTE_AUTH_INVALID", reason);
  }
  assert.throws(() => issueAuthorizationCode(tx, { ...h.binding, principal: "alice" }, NOW));
  assert.throws(() => issueAuthorizationCode(tx, h.binding, tx.expiresAtMs + 1));
});

test("authorization response carries RFC 9207 issuer and rejects mix-up and CSRF", () => {
  const h = harness();
  const tx = authorize(h);
  const { code } = issueAuthorizationCode(tx, h.binding, NOW);
  const url = new URL(buildAuthorizationResponseUrl(tx, code, ISSUER));
  assert.equal(url.origin + url.pathname, REDIRECT);
  const params = {
    iss: url.searchParams.get("iss"),
    state: url.searchParams.get("state"),
    code: url.searchParams.get("code")
  };
  assert.ok(verifyAuthorizationResponse(params, ISSUER, tx.state).ok);
  expectDenied(
    verifyAuthorizationResponse({ ...params, iss: "https://evil.example" }, ISSUER, tx.state) as never,
    "REMOTE_AUTH_INVALID",
    "wrong_issuer"
  );
  expectDenied(
    verifyAuthorizationResponse(params, ISSUER, "s".repeat(32)) as never,
    "REMOTE_AUTH_INVALID",
    "state_missing"
  );
  expectDenied(
    verifyAuthorizationResponse({ ...params, code: "x" }, ISSUER, tx.state) as never,
    "REMOTE_AUTH_INVALID",
    "code_invalid"
  );
});

test("a valid access token yields remote principal identity only", () => {
  const h = harness();
  const { token, claims } = tokenFor(h);
  assert.equal(claims.exp - claims.iat, ACCESS_TOKEN_LIFETIME_SECONDS);
  const result = verifyAccessToken(token, context(h));
  assert.ok(result.ok);
  if (result.ok) {
    assert.equal(result.identity.authority, "remote_identity_only");
    assert.equal(result.identity.principal, h.binding.principal);
    assert.equal(result.identity.deviceId, DEVICE_ID);
    assert.deepEqual(result.identity.scopes, ["orcel.read", "orcel.write"]);
    const summary = JSON.stringify(redactedIdentitySummary(result.identity));
    assert.ok(!summary.includes(token));
    assert.ok(!summary.includes(claims.jti));
    for (const field of ["workspace", "trust", "approval", "presence", "capability", "lease"]) {
      assert.ok(!Object.keys(result.identity).some((key) => key.toLowerCase().includes(field)));
    }
  }
});

test("minting refuses a foreign resource, widened or empty scopes, and revoked families", () => {
  const h = harness();
  const fam = family(h).family;
  assert.throws(() => mintAccessTokenClaims(ISSUER, "https://other.example/mcp", fam, fam.scopes, NOW));
  assert.throws(() => mintAccessTokenClaims(ISSUER, RESOURCE, fam, ["orcel.read", "orcel.execute"], NOW));
  assert.throws(() => mintAccessTokenClaims(ISSUER, RESOURCE, fam, [], NOW));
  assert.throws(() => mintAccessTokenClaims(ISSUER, RESOURCE, revokeRefreshFamily(fam), fam.scopes, NOW));
  assert.throws(() => mintAccessTokenClaims(ISSUER, RESOURCE, fam, fam.scopes, -1));
  assert.ok(mintAccessTokenClaims(ISSUER, RESOURCE, fam, ["orcel.read"], NOW).scope === "orcel.read");
});

test("negative: expired, not-yet-valid, and over-long tokens fail closed", () => {
  const h = harness();
  const { token, claims } = tokenFor(h);
  expectDenied(
    verifyAccessToken(token, context(h, { nowMs: (claims.exp + 31) * 1000 })) as never,
    "REMOTE_AUTH_INVALID",
    "token_expired"
  );
  const future = tokenFor(h, (c) => ({ ...c, nbf: c.iat + 120 }));
  expectDenied(verifyAccessToken(future.token, context(h)) as never, "REMOTE_AUTH_INVALID", "token_not_yet_valid");
  const long = tokenFor(h, (c) => ({ ...c, exp: c.iat + 3600 }));
  expectDenied(verifyAccessToken(long.token, context(h)) as never, "REMOTE_AUTH_INVALID", "lifetime_exceeded");
  const issuedLater = tokenFor(h, (c) => ({ ...c, iat: c.iat + 600, nbf: c.iat, exp: c.iat + 700 }));
  expectDenied(verifyAccessToken(issuedLater.token, context(h)) as never, "REMOTE_AUTH_INVALID", "token_not_yet_valid");
});

test("negative: revoked token, revoked family, and revoked route fail closed", () => {
  const h = harness();
  const { token, claims } = tokenFor(h);
  const tokenRevoked = applyTokenRevocation(
    { tokenIds: new Set(), familyIds: new Set() },
    { kind: "access_token", tokenId: claims.jti, familyId: claims.orcel_family }
  );
  expectDenied(
    verifyAccessToken(token, context(h, { revokedTokenIds: tokenRevoked.tokenIds })) as never,
    "REMOTE_AUTH_INVALID",
    "token_revoked"
  );
  expectDenied(
    verifyAccessToken(token, context(h, { revokedFamilyIds: new Set([claims.orcel_family]) })) as never,
    "REMOTE_AUTH_INVALID",
    "family_revoked"
  );
  for (const revocation of [
    revokeDevice(DEVICE_ID, 1, NOW, "lost"),
    revokePrincipal(h.binding.principal, 1, NOW, "user"),
    emergencyRevoke(2, NOW, "emergency")
  ]) {
    expectDenied(
      verifyAccessToken(token, context(h, { revocations: [revocation] })) as never,
      "DEVICE_REVOKED",
      "route_revoked"
    );
  }
});

test("negative: wrong issuer, wrong audience, and wrong resource fail closed", () => {
  const h = harness();
  const wrongIssuer = tokenFor(h, (c) => ({ ...c, iss: "https://evil.example" }));
  expectDenied(verifyAccessToken(wrongIssuer.token, context(h)) as never, "REMOTE_AUTH_INVALID", "wrong_issuer");
  const wrongAudience = tokenFor(h, (c) => ({ ...c, aud: "https://other.example/mcp" }));
  expectDenied(verifyAccessToken(wrongAudience.token, context(h)) as never, "REMOTE_AUTH_INVALID", "wrong_audience");
  const arrayAudience = tokenFor(h, (c) => ({ ...c, aud: [RESOURCE, "https://other.example/mcp"] as never }));
  expectDenied(verifyAccessToken(arrayAudience.token, context(h)) as never, "REMOTE_AUTH_INVALID", "wrong_audience");
  const { token } = tokenFor(h);
  expectDenied(
    verifyAccessToken(token, context(h, { resource: "https://other.example/mcp" })) as never,
    "REMOTE_AUTH_INVALID",
    "wrong_audience"
  );
  // Wrong resource at the token endpoint is covered by code and refresh redemption tests.
});

test("negative: unknown scope and missing scope fail closed", () => {
  const h = harness();
  const unknown = tokenFor(h, (c) => ({ ...c, scope: "orcel.read orcel.admin" }));
  expectDenied(verifyAccessToken(unknown.token, context(h)) as never, "REMOTE_SCOPE_DENIED", "scope_unknown");
  const empty = tokenFor(h, (c) => ({ ...c, scope: "" }));
  expectDenied(verifyAccessToken(empty.token, context(h)) as never, "REMOTE_SCOPE_DENIED", "scope_missing");
  expectDenied(
    authorizeToolByScopes("fs_write", "core", ["orcel.read"], ["orcel.read", "orcel.write"]) as never,
    "REMOTE_SCOPE_DENIED",
    "scope_missing"
  );
});

test("negative: stale device epoch fails closed", () => {
  const h = harness();
  const { token } = tokenFor(h);
  expectDenied(
    verifyAccessToken(token, context(h, { deviceEpochs: new Map([[DEVICE_ID, 2]]) })) as never,
    "REMOTE_AUTH_INVALID",
    "stale_epoch"
  );
  expectDenied(
    verifyAccessToken(token, context(h, { deviceEpochs: new Map() })) as never,
    "REMOTE_AUTH_INVALID",
    "stale_epoch"
  );
});

test("negative: malformed tokens, forged signatures, and algorithm confusion fail closed", () => {
  const h = harness();
  const { token, claims } = tokenFor(h);
  const [header, payload, signature] = token.split(".") as [string, string, string];
  expectDenied(verifyAccessToken(undefined, context(h)) as never, "REMOTE_AUTH_REQUIRED", "token_missing");
  expectDenied(verifyAccessToken("", context(h)) as never, "REMOTE_AUTH_REQUIRED", "token_missing");
  expectDenied(verifyAccessToken(42, context(h)) as never, "REMOTE_AUTH_INVALID", "token_malformed");
  expectDenied(verifyAccessToken("a.b", context(h)) as never, "REMOTE_AUTH_INVALID", "token_malformed");
  expectDenied(verifyAccessToken("a.b.c.d", context(h)) as never, "REMOTE_AUTH_INVALID", "token_malformed");
  expectDenied(verifyAccessToken(`${header}.${payload}.***`, context(h)) as never, "REMOTE_AUTH_INVALID", "token_malformed");
  expectDenied(verifyAccessToken(`${header}=.${payload}.${signature}`, context(h)) as never, "REMOTE_AUTH_INVALID", "token_malformed");
  expectDenied(
    verifyAccessToken("x".repeat(ACCESS_TOKEN_MAX_CHARS + 1), context(h)) as never,
    "REMOTE_AUTH_INVALID",
    "token_oversized"
  );
  expectDenied(
    verifyAccessToken(`${b64(["array"])}.${payload}.${signature}`, context(h)) as never,
    "REMOTE_AUTH_INVALID",
    "token_malformed"
  );
  const tamperedPayload = b64({ ...claims, scope: "orcel.read orcel.write orcel.execute" });
  expectDenied(
    verifyAccessToken(`${header}.${tamperedPayload}.${signature}`, context(h)) as never,
    "REMOTE_AUTH_INVALID",
    "signature_invalid"
  );
  const none = `${b64({ alg: "none", typ: "at+jwt", kid: h.key.kid })}.${payload}.`;
  expectDenied(verifyAccessToken(none, context(h)) as never, "REMOTE_AUTH_INVALID", "token_malformed");
  const noneSigned = `${b64({ alg: "none", typ: "at+jwt", kid: h.key.kid })}.${payload}.${signature}`;
  expectDenied(verifyAccessToken(noneSigned, context(h)) as never, "REMOTE_AUTH_INVALID", "unsupported_algorithm");
  const hsHeader = b64({ alg: "HS256", typ: "at+jwt", kid: h.key.kid });
  const hsSig = createHmac("sha256", JSON.stringify(verificationKeyOf(h.key).publicJwk))
    .update(`${hsHeader}.${payload}`)
    .digest("base64url");
  expectDenied(
    verifyAccessToken(`${hsHeader}.${payload}.${hsSig}`, context(h)) as never,
    "REMOTE_AUTH_INVALID",
    "unsupported_algorithm"
  );
  for (const extra of [
    { jwk: verificationKeyOf(h.key).publicJwk },
    { jku: "https://evil.example/jwks" },
    { crit: ["exp"] }
  ]) {
    const forged = `${b64({ alg: "EdDSA", typ: "at+jwt", kid: h.key.kid, ...extra })}.${payload}.${signature}`;
    expectDenied(verifyAccessToken(forged, context(h)) as never, "REMOTE_AUTH_INVALID", "unsupported_header");
  }
  const wrongTyp = `${b64({ alg: "EdDSA", typ: "JWT", kid: h.key.kid })}.${payload}.${signature}`;
  expectDenied(verifyAccessToken(wrongTyp, context(h)) as never, "REMOTE_AUTH_INVALID", "unsupported_header");
  const otherKey = generateTokenSigningKey();
  expectDenied(
    verifyAccessToken(signAccessToken(claims, otherKey), context(h)) as never,
    "REMOTE_AUTH_INVALID",
    "unknown_key"
  );
  const forgedWithKnownKid = signAccessToken(claims, { ...otherKey, kid: h.key.kid });
  expectDenied(verifyAccessToken(forgedWithKnownKid, context(h)) as never, "REMOTE_AUTH_INVALID", "signature_invalid");
  const extraClaim = signAccessToken({ ...claims, workspace_trust: true } as never, h.key);
  expectDenied(verifyAccessToken(extraClaim, context(h)) as never, "REMOTE_AUTH_INVALID", "claims_invalid");
  const badSub = signAccessToken({ ...claims, sub: "alice@example.com" }, h.key);
  expectDenied(verifyAccessToken(badSub, context(h)) as never, "REMOTE_AUTH_INVALID", "claims_invalid");
  const badExp = signAccessToken({ ...claims, exp: "never" as never }, h.key);
  expectDenied(verifyAccessToken(badExp, context(h)) as never, "REMOTE_AUTH_INVALID", "claims_invalid");
  const privateKeyLeak = { ...verificationKeyOf(h.key), publicJwk: h.key.privateJwk };
  expectDenied(
    verifyAccessToken(token, context(h, { keys: [privateKeyLeak] })) as never,
    "REMOTE_AUTH_INVALID",
    "unknown_key"
  );
});

function proofFor(h: Harness, fam: RefreshFamily, nowMs: number, pair: DeviceKeyPair = h.device) {
  const challenge = createRefreshProofChallenge(fam, nowMs);
  return { challenge, response: signDeviceChallenge(pair.privateKeyJwkBase64, challenge.challenge) };
}

function refreshRequest(refreshToken: string, scope?: string) {
  return {
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: CLIENT_ID,
    resource: RESOURCE,
    scope
  };
}

test("refresh rotates the token, requires fresh device proof, and keeps scope from widening", () => {
  const h = harness();
  const { refreshToken, family: fam } = family(h);
  assert.ok(!JSON.stringify(fam).includes(refreshToken), "only refresh token hashes are stored");
  const now = NOW + 10_000;
  const identity = publicDeviceIdentity(h.device);
  const first = redeemRefreshToken(fam, refreshRequest(refreshToken), proofFor(h, fam, now), {
    nowMs: now,
    device: identity,
    revocations: []
  });
  assert.ok(first.check.ok);
  assert.ok(first.refreshToken !== null && first.refreshToken !== refreshToken);
  assert.equal(first.next.generation, 2);
  assert.deepEqual(first.scopes, ["orcel.read", "orcel.write"]);

  const narrowed = redeemRefreshToken(
    first.next,
    refreshRequest(first.refreshToken ?? "", "orcel.read"),
    proofFor(h, first.next, now),
    { nowMs: now, device: identity, revocations: [] }
  );
  assert.ok(narrowed.check.ok);
  assert.deepEqual(narrowed.scopes, ["orcel.read"]);
  assert.deepEqual(narrowed.next.scopes, ["orcel.read", "orcel.write"]);

  const widened = redeemRefreshToken(
    narrowed.next,
    refreshRequest(narrowed.refreshToken ?? "", "orcel.read orcel.execute"),
    proofFor(h, narrowed.next, now),
    { nowMs: now, device: identity, revocations: [] }
  );
  expectDenied(widened.check as never, "REMOTE_SCOPE_DENIED", "scope_widening");
  const unknown = redeemRefreshToken(
    narrowed.next,
    refreshRequest(narrowed.refreshToken ?? "", "orcel.everything"),
    proofFor(h, narrowed.next, now),
    { nowMs: now, device: identity, revocations: [] }
  );
  expectDenied(unknown.check as never, "REMOTE_SCOPE_DENIED", "scope_unknown");
});

test("negative: stolen refresh token cannot renew while the bound device is offline", () => {
  const h = harness();
  const { refreshToken, family: fam } = family(h);
  const identity = publicDeviceIdentity(h.device);
  // The attacker holds the refresh token but cannot obtain a device proof.
  let current = fam;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const result = redeemRefreshToken(current, refreshRequest(refreshToken), null, {
      nowMs: NOW + 10_000 + attempt * 60_000,
      device: identity,
      revocations: []
    });
    expectDenied(result.check as never, "REMOTE_AUTH_INVALID", "device_proof_missing");
    assert.equal(result.refreshToken, null);
    current = result.next;
  }
  // A proof signed by a different key (attacker device) fails.
  const attackerPair = generateDeviceKeyPair(DEVICE_ID, NOW, 1);
  const forged = redeemRefreshToken(fam, refreshRequest(refreshToken), proofFor(h, fam, NOW + 10_000, attackerPair), {
    nowMs: NOW + 10_000,
    device: identity,
    revocations: []
  });
  expectDenied(forged.check as never, "REMOTE_AUTH_INVALID", "device_proof_invalid");
  // The family cannot outlive its absolute lifetime even with a device proof.
  const late = NOW + 2000 + REFRESH_FAMILY_MAX_LIFETIME_SECONDS * 1000 + 1;
  const expired = redeemRefreshToken(fam, refreshRequest(refreshToken), proofFor(h, fam, late), {
    nowMs: late,
    device: identity,
    revocations: []
  });
  expectDenied(expired.check as never, "REMOTE_AUTH_INVALID", "family_expired");
  assert.equal(expired.next.revoked, true);
});

test("negative: missing, mismatched, replayed, and expired device proofs fail closed", () => {
  const h = harness();
  const { refreshToken, family: fam } = family(h);
  const identity = publicDeviceIdentity(h.device);
  const now = NOW + 10_000;
  const ctx = { nowMs: now, device: identity, revocations: [] };
  expectDenied(
    redeemRefreshToken(fam, refreshRequest(refreshToken), null, ctx).check as never,
    "REMOTE_AUTH_INVALID",
    "device_proof_missing"
  );
  const proof = proofFor(h, fam, now);
  const wrongFamily = { ...proof, challenge: { ...proof.challenge, familyId: "rf-" + "0".repeat(32) } };
  expectDenied(
    redeemRefreshToken(fam, refreshRequest(refreshToken), wrongFamily, ctx).check as never,
    "REMOTE_AUTH_INVALID",
    "device_proof_mismatch"
  );
  const stale = proofFor(h, fam, now - 121_000);
  expectDenied(
    redeemRefreshToken(fam, refreshRequest(refreshToken), stale, ctx).check as never,
    "REMOTE_AUTH_INVALID",
    "device_proof_invalid"
  );
  const ok = redeemRefreshToken(fam, refreshRequest(refreshToken), proof, ctx);
  assert.ok(ok.check.ok);
  const replay = redeemRefreshToken(ok.next, refreshRequest(ok.refreshToken ?? ""), proof, ctx);
  expectDenied(replay.check as never, "RELAY_REPLAY_DETECTED", "device_proof_replayed");
  expectDenied(
    redeemRefreshToken(fam, refreshRequest(refreshToken), proof, { ...ctx, device: null }).check as never,
    "ROUTE_MISMATCH",
    "device_proof_invalid"
  );
});

test("negative: stale device epoch after key rotation blocks refresh and revokes the family", () => {
  const h = harness();
  const { refreshToken, family: fam } = family(h);
  const rotated = rotateDeviceKeyPair(h.device, NOW + 5000);
  const now = NOW + 10_000;
  const result = redeemRefreshToken(fam, refreshRequest(refreshToken), proofFor(h, fam, now, rotated), {
    nowMs: now,
    device: publicDeviceIdentity(rotated),
    revocations: []
  });
  expectDenied(result.check as never, "REMOTE_AUTH_INVALID", "stale_epoch");
  assert.equal(result.next.revoked, true);
});

test("negative: refresh token replay after rotation revokes the whole family", () => {
  const h = harness();
  const { refreshToken, family: fam } = family(h);
  const identity = publicDeviceIdentity(h.device);
  const now = NOW + 10_000;
  const ctx = { nowMs: now, device: identity, revocations: [] };
  const rotated = redeemRefreshToken(fam, refreshRequest(refreshToken), proofFor(h, fam, now), ctx);
  assert.ok(rotated.check.ok);
  const replay = redeemRefreshToken(rotated.next, refreshRequest(refreshToken), proofFor(h, rotated.next, now), ctx);
  expectDenied(replay.check as never, "REMOTE_AUTH_INVALID", "refresh_replayed");
  assert.equal(replay.next.revoked, true);
  const legit = redeemRefreshToken(
    replay.next,
    refreshRequest(rotated.refreshToken ?? ""),
    proofFor(h, replay.next, now),
    ctx
  );
  expectDenied(legit.check as never, "REMOTE_AUTH_INVALID", "family_revoked");
});

test("negative: revoked device, principal, and family block refresh", () => {
  const h = harness();
  const { refreshToken, family: fam } = family(h);
  const identity = publicDeviceIdentity(h.device);
  const now = NOW + 10_000;
  for (const revocation of [
    revokeDevice(DEVICE_ID, 1, now, "lost"),
    revokePrincipal(fam.binding.principal, 1, now, "user")
  ]) {
    const result = redeemRefreshToken(fam, refreshRequest(refreshToken), proofFor(h, fam, now), {
      nowMs: now,
      device: identity,
      revocations: [revocation]
    });
    expectDenied(result.check as never, "DEVICE_REVOKED", "route_revoked");
    assert.equal(result.next.revoked, true);
  }
  const revoked = redeemRefreshToken(revokeRefreshFamily(fam), refreshRequest(refreshToken), proofFor(h, fam, now), {
    nowMs: now,
    device: identity,
    revocations: []
  });
  expectDenied(revoked.check as never, "REMOTE_AUTH_INVALID", "family_revoked");
  const list = applyTokenRevocation({ tokenIds: new Set(), familyIds: new Set() }, { kind: "refresh_token", refreshToken });
  assert.ok(list.familyIds.has(fam.familyId));
  const unchanged = applyTokenRevocation(list, { kind: "refresh_token", refreshToken: "garbage" });
  assert.equal(unchanged, list);
});

test("negative: refresh binding to client, resource, family, and grant type", () => {
  const h = harness();
  const { refreshToken, family: fam } = family(h);
  const identity = publicDeviceIdentity(h.device);
  const now = NOW + 10_000;
  const ctx = { nowMs: now, device: identity, revocations: [] };
  const cases: Array<[Record<string, unknown>, string]> = [
    [{ grant_type: "client_credentials" }, "unsupported_grant_type"],
    [{ refresh_token: "garbage" }, "refresh_invalid"],
    [{ refresh_token: `crt.rf-${"0".repeat(32)}.${"A".repeat(43)}` }, "family_mismatch"],
    [{ refresh_token: `crt.${fam.familyId}.${"A".repeat(43)}` }, "refresh_invalid"],
    [{ client_id: "https://other.example/c.json" }, "client_mismatch"],
    [{ resource: "https://other.example/mcp" }, "wrong_resource"]
  ];
  for (const [patch, reason] of cases) {
    const result = redeemRefreshToken(fam, { ...refreshRequest(refreshToken), ...patch } as never, proofFor(h, fam, now), ctx);
    expectDenied(result.check as never, "REMOTE_AUTH_INVALID", reason);
    assert.equal(result.next.revoked, false);
  }
});

test("provider client-identification hooks default-deny", () => {
  assert.ok(validateClientRegistration(CLIENT).ok);
  expectDenied(
    validateClientRegistration({ ...CLIENT, clientId: "not-a-url" }) as never,
    "REMOTE_AUTH_INVALID",
    "client_unknown"
  );
  expectDenied(
    validateClientRegistration({ ...CLIENT, redirectUris: ["http://provider.example/cb"] }) as never,
    "REMOTE_AUTH_INVALID",
    "redirect_invalid"
  );
  expectDenied(
    validateClientRegistration({ ...CLIENT, allowedScopes: ["orcel.root" as never] }) as never,
    "REMOTE_SCOPE_DENIED",
    "scope_unknown"
  );
  const evidence = { method: "client_id_metadata_document" as const, clientId: CLIENT_ID, assertion: null };
  const accept: ClientIdentificationHook = () => true;
  const hooks = new Map<ClientIdentificationMethod, ClientIdentificationHook>([["client_id_metadata_document", accept]]);
  assert.ok(verifyClientIdentification(CLIENT, evidence, hooks).ok);
  expectDenied(
    verifyClientIdentification(CLIENT, evidence, new Map()) as never,
    "REMOTE_AUTH_INVALID",
    "client_identification_unavailable"
  );
  expectDenied(
    verifyClientIdentification(CLIENT, { ...evidence, method: "preregistered" }, hooks) as never,
    "REMOTE_AUTH_INVALID",
    "client_identification_failed"
  );
  expectDenied(
    verifyClientIdentification(CLIENT, { ...evidence, clientId: "https://other.example/c.json" }, hooks) as never,
    "REMOTE_AUTH_INVALID",
    "client_mismatch"
  );
  const throwing = new Map<ClientIdentificationMethod, ClientIdentificationHook>([
    [
      "client_id_metadata_document",
      () => {
        throw new Error("provider outage");
      }
    ]
  ]);
  expectDenied(
    verifyClientIdentification(CLIENT, evidence, throwing) as never,
    "REMOTE_AUTH_INVALID",
    "client_identification_failed"
  );
  const truthy = new Map<ClientIdentificationMethod, ClientIdentificationHook>([
    ["client_id_metadata_document", () => "yes" as never]
  ]);
  expectDenied(
    verifyClientIdentification(CLIENT, evidence, truthy) as never,
    "REMOTE_AUTH_INVALID",
    "client_identification_failed"
  );
});

test("scope to tool matrix covers exactly the canonical catalog with default deny", () => {
  assert.deepEqual(
    Object.keys(OAUTH_SCOPE_TOOL_MATRIX).sort(),
    CANONICAL_TOOL_NAMES.filter((tool) => !LOCAL_ONLY_TOOL_NAMES.includes(tool)).sort()
  );
  assert.deepEqual([...LOCAL_ONLY_TOOL_NAMES].sort(), [
    "browser_click",
    "browser_download",
    "browser_download_preview",
    "browser_navigate",
    "browser_observe",
    "browser_page_open",
    "clipboard_read",
    "clipboard_write",
    "desktop_cursor_get",
    "desktop_element_invoke",
    "desktop_element_scroll",
    "desktop_element_select",
    "desktop_element_set_value",
    "desktop_element_toggle",
    "desktop_input_execute",
    "desktop_window_action",
    "desktop_window_capture",
    "desktop_window_list",
    "desktop_window_tree",
    "web_fetch",
    "web_search"
  ]);
  for (const tool of LOCAL_ONLY_TOOL_NAMES) {
    assert.ok(CANONICAL_TOOL_NAMES.includes(tool), `${tool} is canonical`);
    const all = ["orcel.read", "orcel.write", "orcel.execute"];
    assert.deepEqual(authorizeToolByScopes(tool, "core", all, all), {
      ok: false,
      failure: "TOOL_SURFACE_DENIED",
      reason: "tool_unmapped"
    });
  }
  for (const [tool, scopes] of Object.entries(OAUTH_SCOPE_TOOL_MATRIX)) {
    assert.ok(scopes.length > 0, `${tool} must state required scopes`);
  }
  assert.deepEqual(Object.keys(OAUTH_PROFILE_TOOL_CEILINGS), ["core"]);
  const readOnly = ["system_status", "workspace_get", "fs_stat", "fs_list", "fs_read", "fs_search", "git_status", "git_diff", "git_log", "fs_read_range", "fs_find"];
  for (const tool of CANONICAL_TOOL_NAMES) {
    if (LOCAL_ONLY_TOOL_NAMES.includes(tool)) continue;
    const readResult = authorizeToolByScopes(tool, "core", ["orcel.read"], ["orcel.read"]);
    assert.equal(readResult.ok, readOnly.includes(tool), `${tool} read-scope decision`);
  }
  assert.ok(authorizeToolByScopes("fs_write", "core", ["orcel.write"], ["orcel.write"]).ok);
  assert.ok(authorizeToolByScopes("process_spawn", "core", ["orcel.execute"], ["orcel.execute"]).ok);
  expectDenied(
    authorizeToolByScopes("process_spawn", "core", ["orcel.read", "orcel.write"], OAUTH_SCOPES) as never,
    "REMOTE_SCOPE_DENIED",
    "scope_missing"
  );
  expectDenied(
    authorizeToolByScopes("fs_write", "core", ["orcel.write"], ["orcel.read"]) as never,
    "REMOTE_SCOPE_DENIED",
    "scope_missing"
  );
  expectDenied(
    authorizeToolByScopes("run_anything", "core", OAUTH_SCOPES, OAUTH_SCOPES) as never,
    "TOOL_SURFACE_DENIED",
    "tool_unmapped"
  );
  expectDenied(
    authorizeToolByScopes("fs_read", "core", ["orcel.read", "orcel.admin"], ["orcel.read"]) as never,
    "REMOTE_SCOPE_DENIED",
    "scope_unknown"
  );
  for (const profile of [...UNMAPPED_REMOTE_PROFILES, "unknown", "__proto__", "constructor"]) {
    expectDenied(
      authorizeToolByScopes("fs_read", profile, OAUTH_SCOPES, OAUTH_SCOPES) as never,
      "TOOL_SURFACE_DENIED",
      "profile_unmapped"
    );
  }
  for (const tool of ["__proto__", "constructor", "toString"]) {
    expectDenied(
      authorizeToolByScopes(tool, "core", OAUTH_SCOPES, OAUTH_SCOPES) as never,
      "TOOL_SURFACE_DENIED",
      "tool_unmapped"
    );
  }
});

test("OAuth grants no local authority", () => {
  for (const [authority, granted] of Object.entries(OAUTH_LOCAL_AUTHORITY_GRANTED)) {
    assert.equal(granted, false, `${authority} must never be granted by OAuth`);
  }
  assert.deepEqual(Object.keys(OAUTH_LOCAL_AUTHORITY_GRANTED).sort(), [
    "browser",
    "capability",
    "filesystem",
    "localApproval",
    "process",
    "remoteSessionLease",
    "strongPresence",
    "ui",
    "workspaceTrust"
  ]);
});

test("oauth module carries no network, tool, kernel, approval, or transport authority", () => {
  const text = readSource("oauth_authorization.ts");
  for (const forbidden of [
    "registerTool(",
    "node:net",
    "node:http",
    "node:https",
    "node:child_process",
    "node:fs",
    "fetch(",
    "WebSocket",
    "./kernel.js",
    "./server.js",
    "./process.js",
    "./transports/"
  ]) {
    assert.ok(!text.includes(forbidden), `oauth module must not reference ${forbidden}`);
  }
  for (const rel of ["transports/relay_device.ts", "entrypoints/relay_device.ts"]) {
    assert.ok(!readSource(rel).includes("oauth_authorization"), `${rel} must not import OAuth yet`);
  }
});

test("SG-000068 loopback redirects match port-agnostically and nothing else widens", () => {
  const registered = ["http://localhost/callback", "http://127.0.0.1:5000/cb", "https://claude.ai/api/mcp/auth_callback"];
  for (const ok of [
    "http://localhost/callback",
    "http://localhost:61264/callback",
    "http://localhost:3118/callback",
    "http://127.0.0.1:5000/cb",
    "http://127.0.0.1:49152/cb",
    "https://claude.ai/api/mcp/auth_callback"
  ]) {
    assert.ok(redirectUriMatches(registered, ok), ok);
  }
  for (const bad of [
    "http://127.0.0.1:61264/callback",
    "http://localhost:61264/cb",
    "http://localhost:61264/callback/extra",
    "http://localhost:61264/callback?x=1",
    "https://localhost:61264/callback",
    "http://localhost.evil.example:61264/callback",
    "http://[::1]:61264/callback",
    "https://claude.ai:8443/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "https://claude.ai/api/mcp/auth_callback?x=1",
    "http://localhost:61264/callback#f",
    "",
    42,
    null
  ]) {
    assert.equal(redirectUriMatches(registered, bad), false, String(bad));
  }
  // Port-agnostic matching applies only to loopback http registrations.
  assert.equal(redirectUriMatches(["https://app.example/cb"], "https://app.example:444/cb"), false);
  assert.equal(redirectUriMatches([], "http://localhost:1/callback"), false);
});
