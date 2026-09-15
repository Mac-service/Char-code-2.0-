// Copyright (c) 2026 D-o-M-Pl. All Rights Reserved.

/**
 * Dostarczanie powiadomien kanalem SMTP.
 *
 * Implementacja bez zaleznosci zewnetrznych, zgodnie z konwencja projektu
 * (API nie posiada zaleznosci runtime). Obsluguje wylacznie podzbior SMTP
 * potrzebny do wyslania wiadomosci tekstowej: EHLO, STARTTLS, AUTH LOGIN,
 * MAIL FROM, RCPT TO, DATA.
 *
 * Wymagania bezpieczenstwa:
 * - polaczenie musi byc szyfrowane (SMTPS lub STARTTLS) - inaczej blad;
 * - naglowki sa sanityzowane, aby zapobiec wstrzyknieciu CRLF;
 * - weryfikacja certyfikatu wlaczona domyslnie.
 */

import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";

export interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  user?: string;
  password?: string;
  from: string;
  rejectUnauthorized: boolean;
}

export interface Mail {
  to: string;
  subject: string;
  body: string;
}

const COMMAND_TIMEOUT_MS = 15_000;

export function smtpConfigFromEnv(): SmtpConfig | null {
  const host = process.env.SMTP_HOST;
  const from = process.env.SMTP_FROM;
  if (!host || !from) return null;

  const port = Number(process.env.SMTP_PORT ?? "587");
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid SMTP_PORT: ${process.env.SMTP_PORT}`);
  }

  // Domyslnie 465 = SMTPS, pozostale porty = STARTTLS.
  const secure = process.env.SMTP_SECURE === "true" || port === 465;

  const rejectUnauthorized = process.env.SMTP_INSECURE_TLS !== "true";
  if (!rejectUnauthorized && process.env.NODE_ENV === "production") {
    throw new Error("SMTP_INSECURE_TLS=true is forbidden in production.");
  }

  return {
    host,
    port,
    secure,
    from,
    rejectUnauthorized,
    ...(process.env.SMTP_USER ? { user: process.env.SMTP_USER } : {}),
    ...(process.env.SMTP_PASSWORD ? { password: process.env.SMTP_PASSWORD } : {}),
  };
}

/**
 * Usuwa znaki sterujace z wartosci naglowka.
 *
 * Bez tego tresc kontrolowana przez uzytkownika (np. adres e-mail) moglaby
 * wstrzyknac dodatkowe naglowki lub przedwczesnie zakonczyc sekcje DATA.
 */
export function sanitizeHeader(value: string): string {
  return value.replace(/[\r\n\u0000]+/g, " ").trim();
}

/** Kropka rozpoczynajaca linie jest w SMTP znacznikiem konca danych. */
export function dotStuff(body: string): string {
  return body.replace(/\r?\n/g, "\r\n").replace(/^\./gm, "..");
}

export function buildMessage(config: SmtpConfig, mail: Mail): string {
  const to = sanitizeHeader(mail.to);
  const from = sanitizeHeader(config.from);
  const subject = sanitizeHeader(mail.subject);

  if (!to.includes("@")) throw new Error("Invalid recipient address.");

  return [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    `Date: ${new Date().toUTCString()}`,
    "MIME-Version: 1.0",
    'Content-Type: text/plain; charset="utf-8"',
    "Content-Transfer-Encoding: 8bit",
    "",
    dotStuff(mail.body),
  ].join("\r\n");
}

class SmtpSession {
  private buffer = "";
  private pending: ((line: string) => void) | null = null;
  private failure: Error | null = null;

  constructor(private socket: Socket) {
    this.attach(socket);
  }

  private attach(socket: Socket): void {
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      this.buffer += chunk;
      this.drain();
    });
    socket.on("error", (error: Error) => {
      this.failure = error;
      this.pending?.("");
    });
  }

  private drain(): void {
    if (!this.pending) return;
    // Ostatnia linia odpowiedzi ma spacje po kodzie; myslnik oznacza kontynuacje.
    const match = this.buffer.match(/^\d{3} [^\r\n]*\r\n/m);
    if (!match) return;
    const response = this.buffer.slice(0, this.buffer.indexOf(match[0]) + match[0].length);
    this.buffer = this.buffer.slice(response.length);
    const resolve = this.pending;
    this.pending = null;
    resolve(response);
  }

  async expect(expected: number): Promise<string> {
    const response = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("SMTP timeout.")), COMMAND_TIMEOUT_MS);
      this.pending = (line) => {
        clearTimeout(timer);
        if (this.failure) reject(this.failure);
        else resolve(line);
      };
      this.drain();
    });

    const code = Number(response.slice(0, 3));
    if (code !== expected) {
      throw new Error(`SMTP expected ${expected}, received: ${response.trim().slice(0, 200)}`);
    }
    return response;
  }

  async send(command: string, expected: number): Promise<string> {
    this.socket.write(`${command}\r\n`);
    return this.expect(expected);
  }

  replaceSocket(socket: Socket): void {
    this.socket.removeAllListeners("data");
    this.socket.removeAllListeners("error");
    this.socket = socket;
    this.buffer = "";
    this.attach(socket);
  }

  get raw(): Socket {
    return this.socket;
  }
}

export async function sendMail(config: SmtpConfig, mail: Mail): Promise<void> {
  const message = buildMessage(config, mail);

  const socket: Socket = config.secure
    ? (tlsConnect({
        host: config.host,
        port: config.port,
        rejectUnauthorized: config.rejectUnauthorized,
      }) as unknown as Socket)
    : netConnect({ host: config.host, port: config.port });

  const session = new SmtpSession(socket);

  try {
    await session.expect(220);
    let greeting = await session.send(`EHLO ${hostname()}`, 250);

    if (!config.secure) {
      if (!/STARTTLS/i.test(greeting)) {
        throw new Error("SMTP server does not advertise STARTTLS; refusing to send in plaintext.");
      }
      await session.send("STARTTLS", 220);

      const upgraded = tlsConnect({
        socket: session.raw as never,
        host: config.host,
        rejectUnauthorized: config.rejectUnauthorized,
      }) as unknown as Socket;

      await new Promise<void>((resolve, reject) => {
        upgraded.once("secureConnect" as never, () => resolve());
        upgraded.once("error", reject);
      });

      session.replaceSocket(upgraded);
      greeting = await session.send(`EHLO ${hostname()}`, 250);
    }

    if (config.user && config.password) {
      await session.send("AUTH LOGIN", 334);
      await session.send(Buffer.from(config.user).toString("base64"), 334);
      await session.send(Buffer.from(config.password).toString("base64"), 235);
    }

    await session.send(`MAIL FROM:<${sanitizeHeader(config.from)}>`, 250);
    await session.send(`RCPT TO:<${sanitizeHeader(mail.to)}>`, 250);
    await session.send("DATA", 354);
    await session.send(`${message}\r\n.`, 250);
    await session.send("QUIT", 221).catch(() => undefined);
  } finally {
    session.raw.end();
    session.raw.destroy();
  }
}

function hostname(): string {
  return process.env.SMTP_EHLO_NAME ?? "char-code";
}
