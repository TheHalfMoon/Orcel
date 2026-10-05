import assert from "node:assert/strict";
import test from "node:test";

import { kafIdentity, kafPathToken } from "./kaf-identity-patterns.mjs";

function identityMatches(value) {
  kafIdentity.lastIndex = 0;
  const matches = [...value.matchAll(kafIdentity)].map((match) => match[0]);
  kafIdentity.lastIndex = 0;
  return matches;
}

test("Kafka identifiers are not classified as historical Kaf identity", () => {
  for (const value of [
    "Kafka",
    "kafka",
    "KAFKA",
    "messaging.kafka.client_id",
    "SEMATTRS_MESSAGING_KAFKA_CLIENT_ID",
    "prefix_KAFKA_SUFFIX",
    "%3AKAFKA",
    "%20KAFKA",
    String.raw`\u1234KAFKA`,
  ]) {
    assert.deepEqual(identityMatches(value), [], value);
  }
});

test("real historical Kaf identity tokens remain rejected", () => {
  for (const value of [
    "Kaf",
    "KAF",
    "kaf",
    "KafAgent",
    "kafAgent",
    "KAF_AGENT",
    "prefix_KafAgent",
    "prefix_KAF_AGENT",
    "%3AKafAgent",
    "%20KAF_AGENT",
    String.raw`\u1234KafAgent`,
  ]) {
    assert.ok(identityMatches(value).length > 0, value);
  }
});

test("path token matching keeps Kaf project paths without treating Kafka as Kaf", () => {
  for (const value of ["Kaf", "kaf-agent", "KAF_agent", "KafAgent", "kafAgent", "KAF_Agent"]) {
    assert.equal(kafPathToken.test(value), true, value);
  }
  for (const value of ["Kafka", "kafka", "KAFKA", "KAFKA_CLIENT", "kafka-client"]) {
    assert.equal(kafPathToken.test(value), false, value);
  }
});
