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

**Kontrola:** dwustopniowa. Od 3. nieudanej próby kolejne wymagaj¹ odczekania
— opóŸnienie roœnie wyk³adniczo (1 s, 2 s, 4 s … do 60 s). Twarda blokada
konta na 15 minut dopiero po 10 nieudanych próbach w oknie. OdpowiedŸ `429`
z nag³ówkiem `Retry-After`.

**Skutecznoœæ (zmierzona):** atakuj¹cy próbuj¹cy bez przerwy wykonuje
**40 prób na godzinê** zamiast 3600. U¿ytkownik, który pomyli³ has³o trzy
razy, czeka **1 sekundê**.

**Uzasadnienie:** wczeœniejszy próg binarny (5 prób ? 15 minut blokady) by³
zbyt dotkliwy dla wolontariuszy loguj¹cych siê sporadycznie. OpóŸnienie
progresywne ogranicza automat równie skutecznie, nie karz¹c cz³owieka.
**Weryfikacja:** `tests/anomaly.mjs` — piêæ testów progu i opóŸnienia.
**Ryzyko szcz¹tkowe:** napastnik mo¿e celowo doprowadziæ do blokady konta
ofiary (DoS na koncie), ale wymaga to 10 prób w oknie. Blokada wygasa
samoczynnie po 15 minutach.

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

### T9 — Wstrzykniêcie nag³ówków SMTP (Tampering)

Adres e-mail pochodzi z danych wejœciowych. Znaki CR/LF w wartoœci
nag³ówka pozwoli³yby dodaæ w³asne nag³ówki (np. `Bcc`) lub przedwczeœnie
zamkn¹æ sekcjê `DATA`.

**Kontrola:** `sanitizeHeader` zwija CR, LF i bajt zerowy do pojedynczej
spacji. Treœæ wiadomoœci przechodzi przez `dotStuff`, co zabezpiecza kropkê
rozpoczynaj¹c¹ liniê. Po³¹czenie musi byæ szyfrowane — brak STARTTLS
przerywa wysy³kê zamiast degradowaæ do postaci jawnej.
**Weryfikacja:** `tests/notifier.mjs` — budowa wiadomoœci i konfiguracja.
`tests/smtp-conversation.mjs` — rozmowa z atrap¹ serwera: odmowa wysy³ki bez
STARTTLS oraz potwierdzenie, ¿e treœæ nie trafia na ³¹cze przed TLS.

**Niepokryte:** wymiana po nawi¹zaniu TLS (AUTH, MAIL FROM, RCPT TO, DATA).
Wymaga³aby certyfikatu testowego. Ryzyko ograniczone — warstwa transportowa
pochodzi z `node:tls`, a nie z w³asnej implementacji.

## 3. Znane ograniczenia

### O1 — Stan w pamiêci procesu (istotne)

Liczniki i blokady s¹ lokalne dla instancji API. Przy N instancjach za
load balancerem napastnik uzyskuje efektywnie N-krotnoœæ progu.

**Wp³yw:** przy 3 instancjach limit 5 prób/konto dzia³a jak 15.
**Mitygacja:** wdro¿enie jednoinstancyjne lub sesje przypiête (sticky).
**Docelowo:** wspólny magazyn (Redis) z licznikami atomowymi przed
skalowaniem poziomym.

### O2 — Progresywne opóŸnienie (zrealizowane)

Próg nie jest ju¿ binarny. Od 3. nieudanej próby obowi¹zuje narastaj¹ce
opóŸnienie, a twarda blokada wchodzi dopiero przy 10 próbach w oknie.
Szczegó³y i pomiary — patrz T1.

### O3 — Powiadamianie o anomaliach (zrealizowane)

Sygna³y anomalii trafiaj¹ do outboxu jako `SecurityAnomalyDetected`.
Konsument (`apps/api/src/worker.ts`) ustala administratorów organizacji, do
której nale¿y zaatakowane konto, i tworzy dla nich rekordy `Notification`.
Osobna pêtla dostarcza je kana³em SMTP (`apps/api/src/notifier.ts`).

Alerty s¹ wyciszane przez 60 minut dla tej samej pary sygna³/Ÿród³o, aby
trwaj¹cy atak nie zala³ administratora. Dziennik audytu pozostaje kompletny —
ograniczane s¹ wy³¹cznie powiadomienia.

Dostarczanie: do 5 prób, status `PENDING` ? `SENDING` ? `SENT`/`FAILED`.
Przejœcie przez `SENDING` jest aktualizacj¹ warunkow¹, co zapobiega podwójnej
wysy³ce przy wielu instancjach workera.

**Warunek wdro¿eniowy:** bez `SMTP_HOST` i `SMTP_FROM` kana³ jest nieaktywny,
powiadomienia pozostaj¹ w statusie `PENDING`, a obowi¹zek wczesnego
ostrze¿enia z art. 23 NIS2 (24 h) **nie jest spe³niony**. Worker zapisuje
wtedy ostrze¿enie przy starcie.

**Przypadek brzegowy:** przy password sprayingu na nieistniej¹ce konta nie
ma organizacji, któr¹ mo¿na powiadomiæ. Zdarzenie jest wtedy zamykane bez
powiadomienia, ale pozostaje w dzienniku audytu.

## 4. Mapowanie na wymagania

| Wymóg | Artyku³ | Pokrycie |
|---|---|---|
| Kontrola dostêpu | NIS2 21(2)(i) | T1, T2, T3, T4 |
| Wykrywanie incydentów | NIS2 21(2)(b) | T2, T3, sygna³y anomalii |
| Rozliczalnoœæ | NIS2 21(2)(d) | T8, dziennik audytu |
| Bezpieczeñstwo danych osobowych | RODO art. 32 | T1–T5, RLS |
| Zg³aszanie incydentów | NIS2 art. 23 | Zrealizowane pod warunkiem konfiguracji SMTP (O3) |
| Bezpieczeñstwo komunikacji | NIS2 21(2)(j) | T9 — wymuszone TLS |

## 5. Historia przegl¹du

| Data | Zakres | Uwagi |
|---|---|---|
| 2026-09-15 | Wersja pierwotna | Wprowadzenie detekcji anomalii; T1–T8 |
| 2026-09-15 | Powiadomienia | Konsument outboxu, wyciszanie alertów; O3 czêœciowo |
| 2026-09-15 | Kana³ SMTP | Dostarczanie powiadomieñ, T9; O3 domkniête |
| 2026-09-15 | Testy SMTP | Rozmowa z atrap¹ serwera; weryfikacja mutacyjna |
| 2026-09-15 | Progi logowania | OpóŸnienie progresywne zamiast blokady; O2 |
