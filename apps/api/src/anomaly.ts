// Copyright (c) 2026 D-o-M-Pl. All Rights Reserved.

/**
 * Detekcja nadu¿yæ i anomalii uwierzytelniania.
 *
 * Realizuje wymagania NIS2 w zakresie ograniczania nieuprawnionego dostêpu
 * oraz wykrywania podejrzanej aktywnoœci kont (art. 21 ust. 2 lit. d/i).
 *
 * Stan jest przechowywany w pamiêci procesu. Przy wielu instancjach API
 * ka¿da z nich utrzymuje w³asne liczniki, co zmniejsza skutecznoœæ progów.
 * Docelowo backend wspó³dzielony (Redis) — patrz docs/THREAT-MODEL-NIS2.md.
 */

export type AnomalySignal =
  | "CREDENTIAL_STUFFING"
  | "PASSWORD_SPRAYING"
  | "DISTRIBUTED_SOURCE";

export interface ThrottleDecision {
  allowed: boolean;
  retryAfterSeconds: number;
  signals: AnomalySignal[];
}

interface Attempt {
  at: number;
  ip: string;
  email: string;
  success: boolean;
}

const WINDOW_MS = 15 * 60_000;
const MAX_FAILURES_PER_ACCOUNT = 5;
const MAX_FAILURES_PER_IP = 20;
const SPRAY_DISTINCT_ACCOUNTS = 10;
const STUFFING_DISTINCT_IPS = 5;
const LOCKOUT_MS = 15 * 60_000;
const MAX_ATTEMPTS_RETAINED = 10_000;

/**
 * Minimalny odstêp miêdzy alertami o tym samym sygnale z tego samego Ÿród³a.
 *
 * Bez tego trwaj¹cy atak generowa³by alert przy ka¿dej próbie, zalewaj¹c
 * administratora i zacieraj¹c sygna³. Dziennik audytu pozostaje kompletny —
 * ograniczane s¹ wy³¹cznie powiadomienia.
 */
const ALERT_COOLDOWN_MS = 60 * 60_000;

export class AuthAnomalyDetector {
  private attempts: Attempt[] = [];
  private readonly lockouts = new Map<string, number>();
  private readonly alertedAt = new Map<string, number>();

  constructor(private readonly now: () => number = Date.now) {}

  /**
   * Zwraca sygna³y kwalifikuj¹ce siê do powiadomienia administratora,
   * z pominiêciem tych zg³oszonych niedawno dla tego samego Ÿród³a.
   */
  alertable(signals: AnomalySignal[], email: string, ip: string): AnomalySignal[] {
    const current = this.now();
    const fresh: AnomalySignal[] = [];

    for (const signal of signals) {
      const scope = signal === "PASSWORD_SPRAYING" ? `ip:${ip}` : this.accountKey(email);
      const key = `${signal}:${scope}`;
      const last = this.alertedAt.get(key);

      if (last === undefined || current - last >= ALERT_COOLDOWN_MS) {
        this.alertedAt.set(key, current);
        fresh.push(signal);
      }
    }

    return fresh;
  }

  /**
   * Sprawdza, czy próba logowania mo¿e zostaæ wykonana.
   * Wywo³ywaæ PRZED weryfikacj¹ has³a.
   */
  check(email: string, ip: string): ThrottleDecision {
    const current = this.now();
    this.prune(current);

    const key = this.accountKey(email);
    const signals: AnomalySignal[] = [];

    for (const lockKey of [key, this.ipKey(ip)]) {
      const until = this.lockouts.get(lockKey);
      if (until !== undefined && until > current) {
        return {
          allowed: false,
          retryAfterSeconds: Math.ceil((until - current) / 1000),
          signals
        };
      }
      if (until !== undefined) this.lockouts.delete(lockKey);
    }

    const accountFailures = this.attempts.filter(
      (attempt) => !attempt.success && attempt.email === key
    );
    const ipFailures = this.attempts.filter(
      (attempt) => !attempt.success && attempt.ip === ip
    );

    // Wiele Ÿród³owych IP atakuj¹cych jedno konto.
    if (new Set(accountFailures.map((attempt) => attempt.ip)).size >= STUFFING_DISTINCT_IPS) {
      signals.push("CREDENTIAL_STUFFING");
    }

    // Jedno IP próbuj¹ce wielu ró¿nych kont.
    if (new Set(ipFailures.map((attempt) => attempt.email)).size >= SPRAY_DISTINCT_ACCOUNTS) {
      signals.push("PASSWORD_SPRAYING");
    }

    if (accountFailures.length >= MAX_FAILURES_PER_ACCOUNT) {
      this.lockouts.set(key, current + LOCKOUT_MS);
      return { allowed: false, retryAfterSeconds: Math.ceil(LOCKOUT_MS / 1000), signals };
    }

    if (ipFailures.length >= MAX_FAILURES_PER_IP) {
      this.lockouts.set(this.ipKey(ip), current + LOCKOUT_MS);
      return { allowed: false, retryAfterSeconds: Math.ceil(LOCKOUT_MS / 1000), signals };
    }

    return { allowed: true, retryAfterSeconds: 0, signals };
  }

  /** Rejestruje wynik próby. Wywo³ywaæ PO weryfikacji has³a. */
  record(email: string, ip: string, success: boolean): AnomalySignal[] {
    const current = this.now();
    this.prune(current);

    const key = this.accountKey(email);
    this.attempts.push({ at: current, ip, email: key, success });

    if (this.attempts.length > MAX_ATTEMPTS_RETAINED) {
      this.attempts = this.attempts.slice(-MAX_ATTEMPTS_RETAINED);
    }

    if (success) {
      this.attempts = this.attempts.filter(
        (attempt) => attempt.success || attempt.email !== key
      );
      this.lockouts.delete(key);
      return [];
    }

    return this.check(email, ip).signals;
  }

  private prune(current: number): void {
    const cutoff = current - WINDOW_MS;
    if (this.attempts.length > 0 && this.attempts[0]!.at <= cutoff) {
      this.attempts = this.attempts.filter((attempt) => attempt.at > cutoff);
    }
    for (const [key, until] of this.lockouts) {
      if (until <= current) this.lockouts.delete(key);
    }
    for (const [key, at] of this.alertedAt) {
      if (current - at >= ALERT_COOLDOWN_MS) this.alertedAt.delete(key);
    }
  }

  private accountKey(email: string): string {
    return email.trim().toLowerCase();
  }

  private ipKey(ip: string): string {
    return `ip:${ip}`;
  }
}

/**
 * Ustala adres Ÿród³owy ¿¹dania.
 *
 * X-Forwarded-For honorowany wy³¹cznie przy TRUST_PROXY=true, poniewa¿
 * nag³ówek jest w pe³ni kontrolowany przez klienta — zaufanie mu bez
 * reverse proxy pozwala trywialnie obejœæ limity przez podmianê IP.
 */
export function clientIp(
  headers: Record<string, string | string[] | undefined>,
  socketAddress: string | undefined
): string {
  if (process.env.TRUST_PROXY === "true") {
    const forwarded = headers["x-forwarded-for"];
    const raw = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    const first = raw?.split(",")[0]?.trim();
    if (first) return first;
  }
  return socketAddress ?? "unknown";
}
