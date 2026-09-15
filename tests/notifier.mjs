// Copyright (c) 2026 D-o-M-Pl. All Rights Reserved.

// Testy budowy wiadomosci SMTP i konfiguracji kanalu powiadomien.
// Uruchomienie: node tests/notifier.mjs  (wymaga `npm run build`)

import assert from "node:assert/strict";
import {
  buildMessage,
  dotStuff,
  sanitizeHeader,
  smtpConfigFromEnv,
} from "../apps/api/dist/notifier.js";

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

const config = {
  host: "smtp.example.test",
  port: 587,
  secure: false,
  from: "alerty@ngo.test",
  rejectUnauthorized: true,
};

console.log("smtp notifier");

test("naglowek pozbawiony CR i LF", () => {
  assert.equal(sanitizeHeader("Alert\r\nBcc: atakujacy@zly.test"), "Alert Bcc: atakujacy@zly.test");
});

test("wstrzykniecie naglowka przez adres odbiorcy nie tworzy nowej linii", () => {
  const message = buildMessage(config, {
    to: "ofiara@ngo.test\r\nBcc: atakujacy@zly.test",
    subject: "Test",
    body: "tresc",
  });
  const headers = message.slice(0, message.indexOf("\r\n\r\n"));
  assert.equal(headers.split("\r\n").filter((line) => /^bcc:/i.test(line)).length, 0);
});

test("wstrzykniecie przez temat nie rozbija naglowkow", () => {
  const message = buildMessage(config, {
    to: "admin@ngo.test",
    subject: "Alert\r\nX-Injected: 1",
    body: "tresc",
  });
  const headers = message.slice(0, message.indexOf("\r\n\r\n")).split("\r\n");
  // Wstrzyknieta tresc musi pozostac czescia naglowka Subject,
  // a nie utworzyc osobnego naglowka.
  assert.equal(headers.filter((line) => line.startsWith("X-Injected")).length, 0);
  assert.ok(headers.some((line) => line === "Subject: Alert X-Injected: 1"));
});

test("kropka na poczatku linii jest podwajana", () => {
  assert.equal(dotStuff("linia\n.\nkoniec"), "linia\r\n..\r\nkoniec");
});

test("tresc z pojedyncza kropka nie konczy przedwczesnie sekcji DATA", () => {
  const message = buildMessage(config, {
    to: "admin@ngo.test",
    subject: "Test",
    body: "pierwsza\n.\ndruga",
  });
  const data = message.slice(message.indexOf("\r\n\r\n") + 4);
  assert.ok(!data.split("\r\n").includes("."));
});

test("odbiorca bez znaku @ odrzucony", () => {
  assert.throws(() => buildMessage(config, { to: "nieprawidlowy", subject: "T", body: "b" }));
});

test("wiadomosc zawiera wymagane naglowki", () => {
  const message = buildMessage(config, { to: "admin@ngo.test", subject: "Alert", body: "tresc" });
  for (const header of ["From:", "To:", "Subject:", "Date:", "MIME-Version:"]) {
    assert.ok(message.includes(header), `brak naglowka ${header}`);
  }
});

test("brak SMTP_HOST oznacza kanal nieskonfigurowany", () => {
  const saved = { ...process.env };
  delete process.env.SMTP_HOST;
  delete process.env.SMTP_FROM;
  assert.equal(smtpConfigFromEnv(), null);
  process.env = saved;
});

test("port 465 wlacza tryb SMTPS", () => {
  const saved = { ...process.env };
  process.env.SMTP_HOST = "smtp.example.test";
  process.env.SMTP_FROM = "alerty@ngo.test";
  process.env.SMTP_PORT = "465";
  assert.equal(smtpConfigFromEnv().secure, true);
  process.env = saved;
});

test("niepoprawny port odrzucony", () => {
  const saved = { ...process.env };
  process.env.SMTP_HOST = "smtp.example.test";
  process.env.SMTP_FROM = "alerty@ngo.test";
  process.env.SMTP_PORT = "nie-liczba";
  assert.throws(() => smtpConfigFromEnv());
  process.env = saved;
});

test("wylaczenie weryfikacji TLS zabronione w produkcji", () => {
  const saved = { ...process.env };
  process.env.SMTP_HOST = "smtp.example.test";
  process.env.SMTP_FROM = "alerty@ngo.test";
  process.env.SMTP_PORT = "587";
  process.env.SMTP_INSECURE_TLS = "true";
  process.env.NODE_ENV = "production";
  assert.throws(() => smtpConfigFromEnv(), /forbidden in production/);
  process.env = saved;
});

if (failures > 0) {
  console.error(`\n${failures} test(ow) nie przeszlo.`);
  process.exit(1);
}
console.log("\nWszystkie testy kanalu SMTP przeszly.");
