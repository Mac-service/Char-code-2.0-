// Copyright (c) 2026 D-o-M-Pl. All Rights Reserved.

// Testy rozmowy SMTP wobec atrapy serwera.
//
// Zakres: sekwencja polecen do momentu STARTTLS oraz odmowa wysylki
// kanalem nieszyfrowanym. Wlasciwa wymiana po nawiazaniu TLS nie jest tu
// pokryta - wymagalaby certyfikatu testowego. Patrz docs/THREAT-MODEL-NIS2.md.
//
// Uruchomienie: node tests/smtp-conversation.mjs  (wymaga `npm run build`)

import assert from "node:assert/strict";
import { createServer } from "node:net";
import { sendMail } from "../apps/api/dist/notifier.js";

let failures = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`  ok  ${name}`);
  } catch (error) {
    failures += 1;
    console.error(`FAIL  ${name}\n      ${error.message}`);
  }
}

/**
 * Atrapa serwera SMTP. Odpowiada wedlug skryptu i zapisuje otrzymane
 * polecenia, co pozwala zweryfikowac kolejnosc rozmowy.
 */
function fakeSmtp({ advertiseStartTls }) {
  const received = [];
  const server = createServer((socket) => {
    socket.setEncoding("utf8");
    socket.write("220 fake.test ESMTP\r\n");

    socket.on("data", (chunk) => {
      for (const line of chunk.split("\r\n").filter(Boolean)) {
        received.push(line);
        const command = line.toUpperCase();

        if (command.startsWith("EHLO")) {
          socket.write("250-fake.test\r\n");
          if (advertiseStartTls) socket.write("250-STARTTLS\r\n");
          socket.write("250 SIZE 10240000\r\n");
        } else if (command.startsWith("STARTTLS")) {
          // Potwierdzamy gotowosc, ale nie podnosimy TLS - klient przerwie
          // uscisk dloni, co wystarcza do sprawdzenia kolejnosci polecen.
          socket.write("220 Ready to start TLS\r\n");
        } else if (command.startsWith("QUIT")) {
          socket.write("221 Bye\r\n");
          socket.end();
        } else {
          socket.write("250 OK\r\n");
        }
      }
    });

    socket.on("error", () => undefined);
  });

  return {
    received,
    listen: () =>
      new Promise((resolve) => {
        server.listen(0, "127.0.0.1", () => resolve(server.address().port));
      }),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

const mail = { to: "admin@ngo.test", subject: "Alert", body: "tresc" };

function configFor(port) {
  return {
    host: "127.0.0.1",
    port,
    secure: false,
    from: "alerty@ngo.test",
    rejectUnauthorized: false,
  };
}

console.log("smtp conversation");

await test("odmawia wysylki gdy serwer nie oferuje STARTTLS", async () => {
  const server = fakeSmtp({ advertiseStartTls: false });
  const port = await server.listen();

  try {
    await assert.rejects(
      () => sendMail(configFor(port), mail),
      /does not advertise STARTTLS/,
      "wysylka powinna zostac przerwana"
    );

    // Kluczowe: zadne dane wiadomosci nie trafily na lacze jawne.
    const leaked = server.received.some((line) =>
      /MAIL FROM|RCPT TO|DATA|tresc/i.test(line)
    );
    assert.equal(leaked, false, "tresc nie moze trafic na polaczenie nieszyfrowane");
  } finally {
    await server.close();
  }
});

await test("wysyla EHLO przed jakimkolwiek innym poleceniem", async () => {
  const server = fakeSmtp({ advertiseStartTls: false });
  const port = await server.listen();

  try {
    await sendMail(configFor(port), mail).catch(() => undefined);
    assert.ok(server.received.length > 0, "serwer nie otrzymal zadnego polecenia");
    assert.match(server.received[0], /^EHLO /);
  } finally {
    await server.close();
  }
});

await test("zada STARTTLS gdy serwer je oferuje", async () => {
  const server = fakeSmtp({ advertiseStartTls: true });
  const port = await server.listen();

  try {
    // Atrapa nie podnosi realnego TLS, wiec uscisk dloni sie nie powiedzie.
    // Istotne jest, ze klient zazadal STARTTLS zamiast wysylac jawnie.
    await sendMail(configFor(port), mail).catch(() => undefined);
    assert.ok(
      server.received.some((line) => line.toUpperCase().startsWith("STARTTLS")),
      "klient powinien zazadac STARTTLS"
    );
    const leaked = server.received.some((line) => /MAIL FROM|RCPT TO|tresc/i.test(line));
    assert.equal(leaked, false, "tresc nie moze poprzedzac uscisku TLS");
  } finally {
    await server.close();
  }
});

await test("przerywa gdy serwer milczy zamiast powitania", async () => {
  const silent = createServer(() => undefined);
  const port = await new Promise((resolve) => {
    silent.listen(0, "127.0.0.1", () => resolve(silent.address().port));
  });

  try {
    await assert.rejects(() => sendMail(configFor(port), mail), /timeout/i);
  } finally {
    await new Promise((resolve) => silent.close(resolve));
  }
});

if (failures > 0) {
  console.error(`\n${failures} test(ow) nie przeszlo.`);
  process.exit(1);
}
console.log("\nWszystkie testy rozmowy SMTP przeszly.");
