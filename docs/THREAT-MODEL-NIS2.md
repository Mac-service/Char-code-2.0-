# Model zagro¿eñ — uwierzytelnianie i dostêp (NIS2)

Dokument wspiera wykazanie zgodnoœci z art. 21 ust. 2 dyrektywy NIS2 oraz
ustaw¹ o krajowym systemie cyberbezpieczeñstwa (KSC) w zakresie kontroli
dostêpu, wykrywania incydentów i rozliczalnoœci.

Zakres: warstwa uwierzytelniania API (`apps/api/src/anomaly.ts`,
`apps/api/src/security.ts`, `apps/api/src/index.ts`).

## 1. Zasoby chronione

| Zasób | Wra¿liwoœæ | Uzasadnienie |
|---|---|---|
| Konta u¿ytkowników | Wysoka | Dostêp do danych osobowych wolontariuszy (RODO art. 9 — mo¿liwe dane szczególnej kategorii) |
| Sesje | Wysoka | Przejêcie sesji = pe³na personifikacja |
| Kody odzyskiwania MFA | Krytyczna | Omijaj¹ drugi sk³adnik uwierzytelniania |
| Dane organizacji (tenant) | Wysoka | Izolacja miêdzyorganizacyjna wymuszana przez RLS |
| Dziennik audytu | Wysoka | Dowód dla organu nadzoru; utrata = brak rozliczalnoœci |

## 2. Zagro¿enia i œrodki kontrolne

### T1 — Atak si³owy na has³o (STRIDE: Spoofing)

Napastnik odgaduje has³o jednego konta przez powtarzane próby.

**Kontrola:** blokada konta po 5 nieudanych próbach w oknie 15 minut.
OdpowiedŸ `429` z nag³ówkiem `Retry-After`.
**Weryfikacja:** `tests/anomaly.mjs` — „blokuje konto po 5 nieudanych próbach".
**Ryzyko szcz¹tkowe:** napastnik mo¿e celowo blokowaæ konto ofiary (DoS na
koncie). Zaakceptowane — blokada wygasa automatycznie po 15 minutach.

### T2 — Password spraying (Spoofing)

Jedno has³o (np. `Wiosna2026!`) testowane na wielu kontach, aby omin¹æ
limity per konto.

**Kontrola:** blokada IP po 20 nieudanych próbach; sygna³
`PASSWORD_SPRAYING` przy ?10 ró¿nych kontach z jednego IP.
**Weryfikacja:** `tests/anomaly.mjs` — „wykrywa password spraying".

### T3 — Credential stuffing (Spoofing)

Dane z cudzych wycieków testowane z botnetu na jedno konto.

**Kontrola:** sygna³ `CREDENTIAL_STUFFING` przy ?5 ró¿nych IP atakuj¹cych
to samo konto. Limit per konto (T1) dzia³a niezale¿nie od liczby IP.
**Weryfikacja:** `tests/anomaly.mjs` — „wykrywa credential stuffing".

### T4 — Bruteforce kodów odzyskiwania MFA (Elevation of Privilege)

Kody odzyskiwania omijaj¹ MFA, wiêc s¹ celem o wysokiej wartoœci.

**Kontrola:** limit per IP na `/api/account/mfa/recover`; ka¿da próba
trafia do dziennika audytu.
**Ryzyko szcz¹tkowe:** kody maj¹ 12 znaków alfanumerycznych (~62 bity);
bruteforce niewykonalny przy aktywnym limicie.

### T5 — Enumeracja kont (Information Disclosure)

Napastnik ustala, które adresy e-mail s¹ zarejestrowane.

**Kontrola:** `/api/account/password/forgot` zawsze zwraca `202`,
niezale¿nie od istnienia konta. Logowanie zwraca jednolite
`INVALID_CREDENTIALS`.
**Weryfikacja:** `tests/e2e.mjs` — „enumeration resistance".
**Ryzyko szcz¹tkowe:** ró¿nice czasowe odpowiedzi. Weryfikacja has³a u¿ywa
scrypt o sta³ym koszcie, co sp³aszcza sygna³ czasowy.

### T6 — Obejœcie limitów przez podmianê IP (Spoofing)

Nag³ówek `X-Forwarded-For` jest w pe³ni kontrolowany przez klienta.
Bezwarunkowe zaufanie mu pozwala napastnikowi zerowaæ licznik przy ka¿dym
¿¹daniu.

**Kontrola:** `X-Forwarded-For` honorowany **wy³¹cznie** przy
`TRUST_PROXY=true`. Domyœlnie u¿ywany adres gniazda TCP.
**Weryfikacja:** `tests/anomaly.mjs` — dwa testy `clientIp`.
**Wymóg wdro¿eniowy:** `TRUST_PROXY=true` ustawiaæ **tylko** wtedy, gdy API
jest nieosi¹galne bezpoœrednio, a ruch przechodzi przez Front Door/WAF.

### T7 — Wyczerpanie pamiêci detektora (Denial of Service)

Nieograniczony wzrost historii prób.

**Kontrola:** okno 15 minut, czyszczenie wpisów przeterminowanych oraz
twardy limit `MAX_ATTEMPTS_RETAINED` (10 000).
**Ryzyko szcz¹tkowe:** przy ataku rozproszonym przekraczaj¹cym limit
najstarsze wpisy s¹ odrzucane. Limity per konto dzia³aj¹ nadal.

### T8 — Zacieranie œladów (Repudiation)

**Kontrola:** zdarzenia `auth.login`, `auth.login.failed`,
`auth.login.throttled`, `security.anomaly.*` trafiaj¹ do dziennika audytu
z `correlationId`. Sygna³y anomalii dodatkowo do outboxu jako
`SecurityAnomalyDetected`.

## 3. Znane ograniczenia

### O1 — Stan w pamiêci procesu (istotne)

Liczniki i blokady s¹ lokalne dla instancji API. Przy N instancjach za
load balancerem napastnik uzyskuje efektywnie N-krotnoœæ progu.

**Wp³yw:** przy 3 instancjach limit 5 prób/konto dzia³a jak 15.
**Mitygacja:** wdro¿enie jednoinstancyjne lub sesje przypiête (sticky).
**Docelowo:** wspólny magazyn (Redis) z licznikami atomowymi przed
skalowaniem poziomym.

### O2 — Brak progresywnego opóŸnienia

Obecnie próg jest binarny (dozwolone/zablokowane). OpóŸnienie rosn¹ce
wyk³adniczo spowalnia³oby napastnika, nie blokuj¹c u¿ytkownika, który
pomyli³ has³o.

### O3 — Brak powiadomieñ o anomaliach

Sygna³y trafiaj¹ do outboxu, ale nie ma konsumenta wysy³aj¹cego alert do
administratora organizacji. Dla NIS2 istotne s¹ terminy zg³aszania
incydentów (wczesne ostrze¿enie w 24 h) — wymaga uzupe³nienia.

## 4. Mapowanie na wymagania

| Wymóg | Artyku³ | Pokrycie |
|---|---|---|
| Kontrola dostêpu | NIS2 21(2)(i) | T1, T2, T3, T4 |
| Wykrywanie incydentów | NIS2 21(2)(b) | T2, T3, sygna³y anomalii |
| Rozliczalnoœæ | NIS2 21(2)(d) | T8, dziennik audytu |
| Bezpieczeñstwo danych osobowych | RODO art. 32 | T1–T5, RLS |
| Zg³aszanie incydentów | NIS2 art. 23 | Czêœciowe — patrz O3 |

## 5. Historia przegl¹du

| Data | Zakres | Uwagi |
|---|---|---|
| 2026-09-15 | Wersja pierwotna | Wprowadzenie detekcji anomalii; T1–T8 |
