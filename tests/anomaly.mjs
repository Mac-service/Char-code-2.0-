// Copyright (c) 2026 D-o-M-Pl. All Rights Reserved.

// Testy detekcji anomalii uwierzytelniania (NIS2 art. 21).
// Uruchomienie: node tests/anomaly.mjs  (wymaga wczeœniejszego `npm run build`)

import assert from "node:assert/strict";
import { AuthAnomalyDetector, clientIp } from "../apps/api/dist/anomaly.js";

let failures = 0;
function test(name, fn) {
  try {
    fn();
    console.log(`  ok  ${name}`);
  } catch (error) {
    failures += 1;
    console.error(`FAIL  ${name}\n      ${error.message}`);
  }
}

console.log("auth anomaly detection");

test("blokuje konto po 5 nieudanych próbach", () => {
  const detector = new AuthAnomalyDetector();
  for (let i = 0; i < 5; i += 1) {
    assert.equal(detector.check("user@ngo.test", "10.0.0.1").allowed, true);
    detector.record("user@ngo.test", "10.0.0.1", false);
  }
  const decision = detector.check("user@ngo.test", "10.0.0.1");
  assert.equal(decision.allowed, false);
  assert.ok(decision.retryAfterSeconds > 0);
});

test("udane logowanie czyœci licznik nieudanych prób", () => {
  const detector = new AuthAnomalyDetector();
  for (let i = 0; i < 3; i += 1) detector.record("user@ngo.test", "10.0.0.1", false);
  detector.record("user@ngo.test", "10.0.0.1", true);
  assert.equal(detector.check("user@ngo.test", "10.0.0.1").allowed, true);
});

test("blokada wygasa po up³ywie okna czasowego", () => {
  let now = 1_000_000;
  const detector = new AuthAnomalyDetector(() => now);
  for (let i = 0; i < 5; i += 1) detector.record("user@ngo.test", "10.0.0.1", false);
  assert.equal(detector.check("user@ngo.test", "10.0.0.1").allowed, false);
  now += 15 * 60_000 + 1_000;
  assert.equal(detector.check("user@ngo.test", "10.0.0.1").allowed, true);
});

test("wykrywa password spraying z jednego IP", () => {
  const detector = new AuthAnomalyDetector();
  let signals = [];
  for (let i = 0; i < 10; i += 1) {
    signals = detector.record(`user${i}@ngo.test`, "10.0.0.9", false);
  }
  assert.ok(signals.includes("PASSWORD_SPRAYING"));
});

test("wykrywa credential stuffing z wielu IP na jedno konto", () => {
  const detector = new AuthAnomalyDetector();
  let signals = [];
  for (let i = 0; i < 5; i += 1) {
    signals = detector.record("ceo@ngo.test", `10.0.1.${i}`, false);
  }
  assert.ok(signals.includes("CREDENTIAL_STUFFING"));
});

test("blokuje IP po 20 nieudanych próbach na ró¿ne konta", () => {
  const detector = new AuthAnomalyDetector();
  for (let i = 0; i < 20; i += 1) detector.record(`u${i}@ngo.test`, "10.0.0.5", false);
  assert.equal(detector.check("nowy@ngo.test", "10.0.0.5").allowed, false);
});

test("adres e-mail normalizowany — wielkoœæ liter nie omija limitu", () => {
  const detector = new AuthAnomalyDetector();
  for (let i = 0; i < 5; i += 1) detector.record("User@NGO.test", "10.0.0.1", false);
  assert.equal(detector.check("user@ngo.test", "10.0.0.1").allowed, false);
});

test("X-Forwarded-For ignorowany bez TRUST_PROXY", () => {
  delete process.env.TRUST_PROXY;
  assert.equal(clientIp({ "x-forwarded-for": "1.2.3.4" }, "10.0.0.1"), "10.0.0.1");
});

test("X-Forwarded-For honorowany przy TRUST_PROXY=true", () => {
  process.env.TRUST_PROXY = "true";
  assert.equal(clientIp({ "x-forwarded-for": "1.2.3.4, 10.0.0.1" }, "10.0.0.1"), "1.2.3.4");
  delete process.env.TRUST_PROXY;
});

test("alert o tym samym sygnale nie powtarza sie w oknie wyciszenia", () => {
  const detector = new AuthAnomalyDetector();
  const first = detector.alertable(["CREDENTIAL_STUFFING"], "ceo@ngo.test", "10.0.0.1");
  const second = detector.alertable(["CREDENTIAL_STUFFING"], "ceo@ngo.test", "10.0.0.2");
  assert.deepEqual(first, ["CREDENTIAL_STUFFING"]);
  assert.deepEqual(second, []);
});

test("alert powtarza sie po uplywie okna wyciszenia", () => {
  let now = 1_000_000;
  const detector = new AuthAnomalyDetector(() => now);
  assert.deepEqual(detector.alertable(["CREDENTIAL_STUFFING"], "ceo@ngo.test", "10.0.0.1"), ["CREDENTIAL_STUFFING"]);
  now += 60 * 60_000 + 1_000;
  assert.deepEqual(detector.alertable(["CREDENTIAL_STUFFING"], "ceo@ngo.test", "10.0.0.1"), ["CREDENTIAL_STUFFING"]);
});

test("spraying wyciszany per IP, stuffing per konto", () => {
  const detector = new AuthAnomalyDetector();
  // Spraying z tego samego IP na inne konto - wyciszony.
  detector.alertable(["PASSWORD_SPRAYING"], "a@ngo.test", "10.0.0.7");
  assert.deepEqual(detector.alertable(["PASSWORD_SPRAYING"], "b@ngo.test", "10.0.0.7"), []);
  // Stuffing na inne konto - alert przechodzi.
  detector.alertable(["CREDENTIAL_STUFFING"], "a@ngo.test", "10.0.0.1");
  assert.deepEqual(
    detector.alertable(["CREDENTIAL_STUFFING"], "b@ngo.test", "10.0.0.1"),
    ["CREDENTIAL_STUFFING"]
  );
});

if (failures > 0) {
  console.error(`\n${failures} test(ów) nie przesz³o.`);
  process.exit(1);
}
console.log("\nWszystkie testy detekcji anomalii przesz³y.");
