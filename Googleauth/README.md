# GoogleAuth for FOSSBilling

Google login and signup for the [FOSSBilling](https://fossbilling.org) client
area — OAuth 2.0 and OpenID Connect, with PKCE, single-use state, full ID token
verification and deliberately careful account linking.

It installs as an ordinary FOSSBilling extension. **No core file is modified**,
and normal email/password login, registration and password reset keep working
exactly as before — including when Google is unreachable.

Developed by **[Web Boomers](https://www.webboomers.in)** ·
[support@webboomers.in](mailto:support@webboomers.in) · MIT licensed.

---

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Google Cloud setup](#google-cloud-setup)
- [Configuration](#configuration)
- [How it works](#how-it-works)
- [Security](#security)
- [What is stored](#what-is-stored)
- [Customer experience](#customer-experience)
- [Branding the button](#branding-the-button)
- [Signup page placement](#signup-page-placement)
- [Troubleshooting](#troubleshooting)
- [Testing your installation](#testing-your-installation)
- [Updating](#updating)
- [Uninstallation](#uninstallation)
- [Developer documentation](#developer-documentation)
- [Contributing](#contributing)
- [Reporting security issues](#reporting-security-issues)
- [Support](#support)
- [Licence](#licence)

---

## Features

- **Google login** — customers sign in with a Google account they have connected.
- **Google signup** — optionally create new FOSSBilling customers from Google.
- **Three authentication modes**, chosen by the administrator:
  - **Login Only** — sign in only; no account is ever created. **This is the default.**
  - **Signup Only** — Google appears on the registration page only.
  - **Login & Signup** — both.
- **Off by default.** A fresh install is disabled *and* in Login Only mode, so
  the extension cannot create a single customer until you decide it should.
- **OAuth 2.0 authorization code flow** with **OpenID Connect**.
- **PKCE (`S256`)** on every request.
- **Cryptographically secure, single-use OAuth `state`**, session-bound,
  compared in constant time, expiring after ten minutes.
- **OIDC `nonce`** bound into the ID token and verified.
- **Full ID token verification** — RS256 signature against Google's published
  JWKS, plus `iss`, `aud`, `azp`, `exp`, `iat`, `nonce` and `sub`.
- **Google's stable `sub`** is the only identifier used to recognise a customer.
  An email address is metadata, never identity.
- **Safe account linking** — a Google identity is attached only to a customer
  who is signed in to FOSSBilling at that moment.
- **Account takeover protection** — a matching email address never links,
  claims or creates an account by itself.
- **Lock-out protection** — Google cannot be disconnected if it would leave the
  customer with no other way in.
- **Registration completion step** for installations that require profile fields
  Google cannot supply, so a Google signup is never an incomplete customer.
- **Administrator settings page** with live status, the exact redirect URI to
  copy into Google, and a maintenance action to delete all connections.
- **Native-looking, responsive, keyboard-accessible UI** that follows your
  theme's own button, focus and dark-mode styles.
- **FOSSBilling-native integration** through widget slots, the extension
  configuration store, the API layer, the event system, the logger, the rate
  limiter and the translation system.
- **No core modifications. No hard-coded domains. Fully open source.**

---

## Requirements

| Requirement | Version |
| --- | --- |
| FOSSBilling | **0.8.2 or newer** (developed and tested against **0.8.7** and current `main`) |
| PHP | **8.3 or newer** (tested on 8.3 and 8.4) |
| PHP extensions | `openssl`, `json`, `curl`, `intl`, `mbstring`, `pdo` |
| Database | Anything FOSSBilling supports (MySQL/MariaDB, PostgreSQL, SQLite) |
| Composer | Only for development and running the test suite — **not** needed to install the extension |
| Google | A Google Cloud project with an OAuth 2.0 **Web application** client |

### HTTPS is required in production

Google will not accept a redirect URI on `http://` for anything except
`http://localhost`, and the whole point of this extension is to move an
authenticated identity through the browser. Run your FOSSBilling install over
HTTPS with a valid certificate, and make sure `SYSTEM_URL` in
`src/config.php` uses `https://`. FOSSBilling's `security.force_https` setting
should be on, so the session cookie is marked `Secure`.

The extension has **no runtime Composer dependencies**. It uses only PHP itself
and the libraries FOSSBilling already ships (Symfony HTTP Client, Doctrine,
Pimple, Twig). `composer.json` exists for packaging metadata and to install
PHPUnit for development.

---

## Installation

### 1. Download the extension

Download the latest release archive from the
[releases page](https://github.com/webboomers/fossbilling-googleauth/releases),
or clone the repository.

### 2. Extract it

Extract the archive somewhere on your computer. You should see `manifest.json`,
`Service.php`, `Controller/`, `templates/` and so on at the top level.

### 3. Upload it to FOSSBilling

Copy the folder into your FOSSBilling installation's modules directory and name
it exactly **`Googleauth`**:

```
/path/to/fossbilling/src/modules/Googleauth/
```

> **The capitalisation matters.** FOSSBilling lowercases a module's name and then
> capitalises the first letter to find its classes, so the folder must be
> `Googleauth` — not `GoogleAuth`, not `googleauth`. If you rename it, the module
> will not load. The display name, "Google Authentication", is set in
> `manifest.json` and is what you will actually see in the admin area.

Using the shell:

```bash
cd /path/to/fossbilling/src/modules
unzip ~/Downloads/fossbilling-googleauth-1.0.0.zip
mv fossbilling-googleauth-1.0.0 Googleauth
chown -R www-data:www-data Googleauth   # match your web server's user
```

### 4. Log in to FOSSBilling as an administrator

Use an account that has the "manage extensions" permission.

### 5. Open the extensions list

Go to **Extensions → Overview**.

### 6. Find "Google Authentication"

It appears in the list of locally available modules.

### 7. Install and activate it

Click **Install** (or **Activate**). On installation the extension:

- checks that this FOSSBilling and PHP are new enough, and stops with a clear
  message if not;
- creates its own `googleauth_account` table;
- writes its default configuration — **disabled**, **Login Only**;
- registers its event listener and its widget templates.

Nothing is shown to customers yet, because the extension is still off.

### 8. Configure it

Go to **Settings → Google Authentication** (or the **Settings** link next to the
extension in the extensions list). Copy the **Authorized redirect URI** shown
there — you need it for the next section.

### 9. Enable it

After adding your Google credentials (below), switch **Enable Google
Authentication** on, choose your authentication mode, and save.

### 10. Test it

Sign out, open your client area's login page, and use **Continue with Google**.
See [Testing your installation](#testing-your-installation) for the full set of
scenarios worth walking through.

---

## Google Cloud setup

You need an OAuth 2.0 client ID and client secret from Google. This is free.

### Step 1 — Create or select a Google Cloud project

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Use the project picker in the top bar.
3. Either select an existing project or click **New project**, give it a name
   (for example "Client Area Login") and create it.

### Step 2 — Configure the OAuth consent screen

1. Go to **APIs & Services → OAuth consent screen** (in newer consoles this
   lives under **Google Auth Platform → Branding**).
2. Choose the audience:
   - **External** — anyone with a Google account can sign in. This is what you
     want for a hosting company's customers.
   - **Internal** — only accounts in your Google Workspace organisation.
3. Continue.

### Step 3 — Fill in the application information

1. **App name** — what your customers will see on Google's consent screen. Use
   your company or product name.
2. **User support email** — an address customers can contact.
3. **App logo** — optional, but it makes the consent screen look like yours.
4. **Application home page**, **Privacy policy** and **Terms of service** links —
   Google requires these before an External app can be published.
5. **Authorized domains** — add your domain, for example `example.com`.
6. **Developer contact information** — your email address.
7. **Scopes** — this extension only ever requests `openid`, `email` and
   `profile`, which are non-sensitive. You do not need to request anything else,
   and you do not need Google verification for these.
8. Save.

While your app is in **Testing** status, only the accounts you list as test
users can sign in. When you are ready for real customers, click **Publish app**.

### Step 4 — Create the OAuth credentials

1. Go to **APIs & Services → Credentials**.
2. Click **Create credentials → OAuth client ID**.
3. For **Application type**, choose **Web application**.
4. Give it a name, for example "FOSSBilling client area".

### Step 5 — Add the authorized redirect URI

This is the step people most often get wrong, so take it from the extension
rather than typing it by hand.

1. In FOSSBilling, go to **Settings → Google Authentication**.
2. Copy the value shown under **Authorized redirect URI** (there is a **Copy**
   button next to it). It looks like:

   ```
   https://billing.example.com/googleauth/callback
   ```

   On installations without URL rewriting it may instead look like:

   ```
   https://billing.example.com/index.php?_url=/googleauth/callback
   ```

   **Both examples above are only examples.** Use the exact string your own
   installation displays — it is generated from your configured system URL.

3. In the Google Cloud Console, under **Authorized redirect URIs**, click
   **Add URI** and paste it in. It must match character for character:
   scheme, host, port, path, trailing slash and all.
4. You do not need to add anything under **Authorized JavaScript origins** —
   this extension uses a server-side redirect flow, not Google's JavaScript
   library.
5. Click **Create**.

> If your site is reachable at both `example.com` and `www.example.com`, add
> only the one that matches `SYSTEM_URL` in your FOSSBilling configuration, and
> redirect the other at the web server level.

### Step 6 — Copy the client ID

Google shows it once the client is created; it looks like
`1234567890-abcdefghijklmnop.apps.googleusercontent.com`. It is not a secret.

### Step 7 — Copy the client secret

It looks like `GOCSPX-...`. **This one is a secret.** Never commit it, never
email it, never paste it into a support ticket or a chat. If it leaks, delete
the client in Google Cloud and create a new one.

### Step 8 — Paste them into FOSSBilling

1. Back in **Settings → Google Authentication**, paste the **Client ID** and
   **Client Secret**.
2. Choose your **Authentication Mode**.
3. Switch **Enable Google Authentication** on.
4. Click **Save settings**.

The status badge at the top of the page should now read **Enabled ·
Configuration: complete**.

---

## Configuration

Everything lives on one page: **Settings → Google Authentication**.

### Enable Google Authentication

A simple on/off switch. **Default: OFF.**

When off, no Google button is rendered anywhere in the client area and the
extension's OAuth routes refuse to start a flow. Existing connections are kept.

You cannot switch it on without both a client ID and a client secret — the
settings form refuses, rather than leaving a broken button on your login page.

### Authentication Mode

**Default: Login Only.**

| Mode | Login page | Registration page | Can create accounts? |
| --- | --- | --- | --- |
| **Login Only** | Google button shown | not shown | **No** |
| **Signup Only** | not shown | Google button shown | Yes |
| **Login & Signup** | Google button shown | Google button shown | Yes |

- **Login Only** — Google can sign in a customer whose Google account is already
  connected to a FOSSBilling account. If the Google account is not connected,
  the customer is told so and nothing is created. This is the safest mode and
  the default. Customers connect Google themselves from their profile page.
- **Signup Only** — Google is offered on the registration page and may create a
  new customer. An existing, connected Google account signing up simply gets
  signed in rather than duplicated.
- **Login & Signup** — both of the above. An unknown Google identity arriving at
  the login button is allowed to continue into the signup path.

Only the three values `login`, `signup` and `both` are accepted. Anything else
that somehow reaches the configuration — a hand-edited database row, a corrupted
value — is read back as **Login Only**.

### Google OAuth credentials

- **Client ID** — public, shown back to you in the form so you can check it.
- **Client Secret** — stored through FOSSBilling's encrypted extension
  configuration. It is **never** shown again after you save it, never sent to
  the client area, never placed in HTML or JavaScript, never returned by any API
  role, and never written to the log. Leave the field blank when saving to keep
  the stored secret; type a new one to replace it.

Clearing the client ID also clears the stored secret, so you never leave an
orphaned secret behind.

### Authorized redirect URI

Displayed read-only, with a copy button. Generated from your installation's own
configured URL — there is no hard-coded domain anywhere in this extension, which
is what makes it reusable by any FOSSBilling operator.

### Connected accounts

Shows how many customers have connected a Google account, and offers **Delete
all connections**. That action removes only the Google sign-in option; customer
accounts, invoices, orders and support tickets are never touched. It is guarded
by a confirmation dialog, the `googleauth.purge_links` staff permission and
FOSSBilling's CSRF protection.

### Staff permissions

The module exposes three permissions under **Staff → Roles**:

| Permission | Allows |
| --- | --- |
| `view` | Seeing the configuration and the number of connections |
| `manage_settings` | Opening and saving the settings page |
| `purge_links` | Deleting all Google account connections |

---

## How it works

```
Customer
   ↓
FOSSBilling login or registration page
   ↓
"Continue with Google" / "Sign up with Google"
   ↓
GoogleAuth creates PKCE verifier + challenge, state, nonce
   ↓
Stored server-side in the session; browser is redirected to Google
   ↓
Google authenticates the person and asks for consent
   ↓
Google redirects back to /googleauth/callback with code + state
   ↓
Validate state (single use, session-bound, constant time, 10-minute window)
   ↓
Exchange code + PKCE verifier + client secret for tokens (server to server)
   ↓
Verify the ID token: RS256 signature, iss, aud, azp, exp, iat, nonce, sub
   ↓
Require a verified email address
   ↓
Look up the Google "sub" in the googleauth_account table
   ↓
Find / create / link the FOSSBilling customer, according to the mode
   ↓
Regenerate the session ID and sign the customer in
   ↓
Redirect to a validated internal destination (the dashboard)
```

### Stage by stage

1. **The customer clicks the button.** It is a plain link to
   `/googleauth/login`, `/googleauth/signup` or `/googleauth/link` — no
   JavaScript required on the login page.
2. **A flow is created.** The extension generates a 32-byte PKCE code verifier
   and its `S256` challenge, a 32-byte `state` and a 32-byte `nonce`. All of it,
   plus the *intent* (login, signup or link) and the destination to return to,
   is stored in the server-side session. The browser only ever sees the opaque
   `state`.
3. **Redirect to Google.** The authorization URL carries the client ID, the
   redirect URI, `response_type=code`, the three scopes, the state, the nonce,
   the PKCE challenge and `prompt=select_account` (so a shared browser does not
   silently reuse whoever happens to be signed in).
4. **Google authenticates the person** and sends them back to the callback.
5. **State validation.** The pending flow is removed from the session *before*
   the comparison, so a replayed callback URL finds nothing to match. A missing,
   unknown, mismatched, replayed or expired state is rejected outright.
6. **Token exchange.** Server to server, over TLS, with the client secret and
   the PKCE verifier. The authorization code never has to be trusted on its own.
7. **ID token verification.** The signature is checked against Google's
   published JWKS (cached for an hour), and the issuer, audience, authorized
   party, expiry, issued-at, nonce and subject claims are all checked.
8. **Email verification.** If Google reports the address as unverified, or does
   not supply one, the flow stops.
9. **Identity resolution.** The Google `sub` is looked up in the extension's own
   table. What happens next depends on the intent and the configured mode —
   see the three flows below.
10. **Session.** On success the session ID is regenerated and `client_id` is set
    the same way FOSSBilling's own login sets it, and the same login events are
    fired so anything else listening still works.
11. **Redirect.** To a destination that has been validated as internal.

### Login Only

```
Google identity verified
   ↓
Is this "sub" connected to a customer?
   ├── Yes → sign that customer in
   └── No  → stop. Nothing is created.
             "No account here is linked to that Google account.
              Sign in with your usual details and connect Google
              from your profile, or create an account first."
```

### Signup Only

```
Google identity verified
   ↓
Is this "sub" already connected?      → Yes: just sign them in
   ↓ No
Are registrations enabled in FOSSBilling? → No: stop
   ↓ Yes
Does a customer already use this email?   → Yes: stop, and say so
   ↓ No                                       (never silently linked,
Does this install require extra fields?      never duplicated)
   ├── Yes → ask for them, then create
   └── No  → create the customer through FOSSBilling's own
             guest signup service, connect the Google identity,
             sign them in
```

### Login & Signup

Both of the above. An unknown Google identity that arrives via the login button
continues into the signup path; a known one always signs in.

### Connecting Google to an existing account

This is the safe linking model, and it is available in **every** mode:

```
Customer signs in to FOSSBilling normally
   ↓
Profile page → "Connect Google Account" (CSRF-protected link)
   ↓
Google OAuth
   ↓
Verify the Google identity
   ↓
Confirm the same customer is still signed in
   ↓
Store the mapping: Google "sub" → customer ID
```

---

## Security

Each protection below exists because of a specific attack.

### OAuth `state`

**What:** every authorization request carries a 32-byte random value
(`bin2hex(random_bytes(32))`) stored server-side in the session. The callback
must return it. The stored value is deleted *before* the comparison, and the
comparison uses `hash_equals()`.

**Why:** without it, an attacker can complete a Google login themselves and then
trick your customer's browser into visiting the resulting callback URL, silently
signing the customer into the *attacker's* account (login CSRF), or capture a
callback URL and replay it. Missing, mismatched, replayed and expired states are
all rejected, and a state is good for ten minutes at most.

### PKCE (`S256`)

**What:** a fresh 43-character random verifier per flow; only its SHA-256 hash
goes to Google; the verifier is sent only in the back-channel token exchange.

**Why:** an authorization code that is intercepted — through a leaky referrer,
a shared device, a proxy, a logged URL — is useless without the verifier.
The `plain` method is deliberately not implemented; offering it would only ever
weaken the flow.

### OIDC `nonce`

**What:** a second 32-byte random value, sent with the authorization request and
required to appear inside the signed ID token.

**Why:** it binds the token to *this* authorization request, so an ID token
obtained elsewhere cannot be injected into someone else's session.

### ID token verification

**What:** RS256 signature verified against Google's JWKS (with the key selected
by `kid`), plus `iss` ∈ {`https://accounts.google.com`, `accounts.google.com`},
`aud` equal to your client ID, `azp` when multiple audiences are present, `exp`
and `iat` within a two-minute skew allowance, the `nonce`, and a non-empty `sub`.
`alg: none` and symmetric algorithms are refused.

**Why:** the token is what asserts who the person is. The exchange already
happens over an authenticated TLS connection straight to Google — which OpenID
Connect Core §3.1.3.7 considers sufficient on its own — but verifying the
signature as well costs one cached request and removes any reliance on the
transport being the only thing in the way.

### Verified email required

**What:** `email_verified` must be true, and an email address must be present.

**Why:** some Google accounts can carry an email address the owner has not
proved control of. Acting on one would let an attacker aim a flow at somebody
else's address.

### Google `sub` as the identifier

**What:** the mapping table is keyed on Google's subject identifier, with a
unique index. The email address is stored as metadata for display only.

**Why:** email addresses change hands. A Google Workspace address released by
one employee and reissued to another is the same string and a different person.
`sub` is stable and unique per Google account, forever.

### Account takeover protection

**What:** a Google identity whose email matches an existing FOSSBilling customer
is **never** automatically linked to that customer and never creates a duplicate.
The signup is refused with an explanation. Linking happens only for a customer
who is authenticated in FOSSBilling during that same request, and the extension
re-checks at the end of the flow that the signed-in customer has not changed.

**Why:** this is the classic single-sign-on takeover. If "the Google email
matches the account email" were enough, anyone able to obtain a Google account
carrying a victim's address — a re-registered domain, a Workspace tenant they
control, an unverified alias — could walk into that customer's billing account.
Additionally, one Google identity maps to at most one customer and one customer
to at most one Google identity, enforced by unique indexes as well as by code,
so a race between two concurrent requests ends in a database error rather than a
duplicate link.

### Session fixation

**What:** `regenerateId()` is called before the session becomes an authenticated
one, exactly as FOSSBilling's own login does. There is no parallel "Google
session" — the same `client_id` session value is set, and the same events fire.

**Why:** an attacker who can plant a known session ID in a victim's browser must
not end up holding an authenticated session.

### CSRF

**What:** administrator settings, the purge action and customer disconnect all
go through FOSSBilling's API layer, which enforces its own CSRF token. The two
browser-initiated endpoints the framework does not cover — "Connect Google"
(a GET link) and the signup completion form (a guest API call) — validate the
same core CSRF token explicitly. No home-grown token scheme is introduced.

**Why:** so a third-party page cannot make a logged-in administrator change your
OAuth credentials, or make a customer connect *the attacker's* Google account to
their billing account.

### Open redirect protection

**What:** the post-login destination is accepted only when it is an ordinary
relative path on this site. Absolute URLs, protocol-relative `//host`, schemes,
backslashes, userinfo `@`, traversal segments and encoded control characters all
fall back to a safe default. The result is a path, handed to FOSSBilling's own
URL builder.

**Why:** a login link that can bounce the customer to an attacker-controlled
site immediately after signing in is a ready-made phishing tool.

### Secret protection

**What:** the client secret is stored via FOSSBilling's encrypted extension
configuration. It is not returned by the admin, client or guest API, not
rendered into any template, not exposed to JavaScript, and not logged. The
settings form shows a placeholder rather than the value.

### Token handling

**What:** no access token, refresh token, ID token or authorization code is ever
stored. `access_type=online` is requested, so Google does not even issue a
refresh token. This extension authenticates people; it does not call Google APIs
on their behalf, so keeping tokens would add risk and buy nothing.

### Logging

**What:** logged — authentication succeeded, authentication failed and why,
invalid or replayed state, configuration errors, linking failures, account
creation. Never logged — client secrets, access tokens, refresh tokens, ID
tokens, authorization codes. Failure messages name the failing step, not the
customer's details.

### Rate limiting

**What:** the OAuth endpoints consume FOSSBilling's existing `api_guest` policy,
and account creation additionally consumes `client_signup` and
`client_signup_email`. Signing up through Google therefore cannot be used to
bypass the quotas that protect the ordinary signup form.

### Lock-out protection

**What:** a customer cannot disconnect Google unless the account still has a
usable password hash and email address — that is, unless "forgot password" would
still get them back in.

### SQL injection and XSS

**What:** every database access goes through Doctrine with parameterised
queries; no value from Google or from a request is ever concatenated into SQL.
All output is rendered through Twig with its default auto-escaping.

---

## What is stored

The extension owns exactly one table, `googleauth_account`:

| Column | Purpose |
| --- | --- |
| `id` | primary key |
| `client_id` | the FOSSBilling customer, unique — one connection each |
| `google_sub` | Google's stable subject identifier, unique |
| `google_email` | metadata, shown on the profile and admin screens |
| `created_at` | when the connection was made |
| `updated_at` | when it last changed |
| `last_login_at` | when Google was last used to sign in |

That is all. **Not** stored: access tokens, refresh tokens, ID tokens,
authorization codes, Google profile pictures, contacts, Drive data or anything
else. The customer's name and email are held by FOSSBilling itself, in its own
customer record, exactly as they would be after a form signup.

Accounts created through Google get a 32-character cryptographically random
password, generated and hashed by FOSSBilling's own client service. It is never
derived from the Google identity, never displayed and never emailed. A customer
who later wants to stop using Google uses the normal "forgot password" flow.
Because Google has verified the address, such accounts are marked as having a
confirmed email.

---

## Customer experience

**On the login page** (Login Only or Login & Signup) a separator and a
**Continue with Google** button appear below the login form.

**On the registration page** (Signup Only or Login & Signup) a **Sign up with
Google** button appears beside the registration form.

**On the profile page** a "Google Account" card shows whether Google is
connected, which Google address is connected, and offers **Connect Google
Account** or **Disconnect**. A fuller page lives at `/googleauth/account`.

The buttons are ordinary links styled with your theme's own button classes, so
they inherit its spacing, focus ring and dark-mode colours. They are keyboard
accessible, have real text labels (never icon-only), work at phone width without
horizontal overflow, and do not disturb the existing forms.

---

## Branding the button

The button ships with a neutral sign-in glyph rather than Google's "G" mark.
Google's brand guidelines require their official asset to be used unmodified and
under their terms, so the choice of whether to display it is left to you, the
operator.

To use Google's official mark, download it from Google's
[Sign-In branding guidelines](https://developers.google.com/identity/branding-guidelines)
and override the button template in your theme:

```
src/themes/<your-theme>/client/html_custom/partial_googleauth_button.html.twig
```

Copy `templates/client/partial_googleauth_button.html.twig` from this extension
as your starting point and replace the inline `<svg>`. Theme `html_custom/` files
take priority over module templates, so nothing in the extension needs editing
and your change survives updates.

---

## Signup page placement

FOSSBilling's login page provides a widget slot inside the form
(`client.page.login.form.after`), so the login button is injected there with no
JavaScript at all.

The stock registration page has no equivalent slot inside its form. The signup
button therefore uses the page-level `client.theme.body.end` slot and is moved
next to the registration form by a few lines of progressive enhancement. **With
JavaScript disabled the button still renders and still works** — it simply sits
below the card instead of beside the form.

If you would rather have no script at all, override the registration template in
your theme and place the button yourself:

```twig
{# src/themes/<your-theme>/client/html_custom/mod_page_signup.html.twig #}
{% set googleauth = guest.googleauth_button_context %}
{% if googleauth.show_on_signup %}
    {{ include('partial_googleauth_button.html.twig', {
        googleauth_url: googleauth.signup_url,
        googleauth_label: 'Sign up with Google'|trans
    }) }}
{% endif %}
```

Then the page-level widget can be left as it is — it only renders when it does
not find the form, or you can remove the slot entry from `Service::getWidgets()`
in a fork.

---

## Troubleshooting

### "Error 400: redirect_uri_mismatch"

The redirect URI in Google does not match the one FOSSBilling sends, exactly.

1. Open **Settings → Google Authentication** and copy the **Authorized redirect
   URI** with the copy button — do not retype it.
2. In the Google Cloud Console, open **APIs & Services → Credentials**, click
   your OAuth client, and compare it against every entry under **Authorized
   redirect URIs**.
3. Check each of these, which are the usual culprits:
   - `http://` versus `https://`
   - `example.com` versus `www.example.com`
   - a trailing slash on one and not the other
   - a port number
   - a subdirectory install (`/billing/googleauth/callback`)
4. Save in Google. Changes can take a few minutes to propagate.
5. Make sure `SYSTEM_URL` in `src/config.php` is the URL customers actually use.

### "Error 401: invalid_client" / "Unauthorized"

The client ID or client secret is wrong, or the OAuth client was deleted.

- Re-copy both from **APIs & Services → Credentials**. The client secret is only
  shown in full when it is created; if you no longer have it, add a new secret
  (or create a new client) and paste the new one in.
- Check you copied from the right project.
- Make sure you pasted the **Web application** client, not an Android, iOS or
  service-account credential.
- Re-save the settings page; a blank secret field keeps the old secret, so if
  you are *replacing* a secret you must type the new one.

### "Access blocked: this app has not completed the Google verification process"

Your consent screen is in **Testing** status and the person signing in is not a
listed test user. Either add them as a test user, or click **Publish app** on the
OAuth consent screen. With only `openid`, `email` and `profile` requested, no
Google verification review is required to publish.

### The Google button does not appear

Check, in order:

1. **Extensions → Overview** — is "Google Authentication" *activated*?
2. **Settings → Google Authentication** — does the status badge say **Enabled**?
   If it says "Enabled · Configuration: incomplete", the credentials are missing.
3. **Authentication Mode** — Login Only hides the button on the *registration*
   page; Signup Only hides it on the *login* page. That is by design.
4. **Cache** — FOSSBilling caches the widget registry. Deactivating and
   reactivating the extension rebuilds it; **System → Settings → Clear cache**
   also works.
5. **Custom theme** — if your theme overrides `mod_page_login.html.twig`, make
   sure it still contains `{{ render_widgets('client.page.login.form.after') }}`.
   Themes forked from an older FOSSBilling may predate the widget slots.
6. **FOSSBilling version** — the login form's widget slot was added in
   **0.8.2**. On an older release the extension installs and everything else
   works, but the login button has nowhere to go; installation logs a warning
   saying exactly this. Upgrade FOSSBilling, or place the button yourself by
   overriding the login template in your theme, the same way as for the signup
   page (see [Signup page placement](#signup-page-placement) — use
   `googleauth.login_url` and `show_on_login` instead).

### "No account here is linked to that Google account"

This is **Login Only** working as intended: the Google account has never been
connected to a customer here, and Login Only never creates accounts.

The customer should sign in with their email and password and then use
**Connect Google Account** on their profile page. After that, Google sign-in
works for them.

If you want Google to be able to create accounts, change the mode to **Signup
Only** or **Login & Signup**.

### "An account with that email address already exists here"

A customer record already uses that address, but it has never been connected to
this Google identity. The extension refuses to link them automatically, because
control of an email address at Google is not proof of ownership of an account
created here with that address — see
[account takeover protection](#account-takeover-protection).

The customer should sign in normally (using "forgot password" if needed) and
connect Google from their profile page.

### "Google sign-in was cancelled"

The customer pressed **Cancel** on Google's consent screen, or chose "deny".
Nothing went wrong; they can try again or use their password.

### "This Google sign-in link has expired or was already used"

Normal and expected if the customer:

- left the Google screen open for more than ten minutes,
- pressed the browser's back button and re-submitted an old callback URL,
- or has cookies blocked for your site.

**You do not need to change `security.mode`.** Pending sign-ins are not kept in
the PHP session, precisely because FOSSBilling's default
`security.mode = 'strict'` marks the session cookie `SameSite=Strict`, and
browsers correctly withhold Strict cookies on the top-level navigation back from
`accounts.google.com`. The flow is stored server-side in the extension's
`googleauth_flow` table and bound to the browser by a separate, short-lived
`SameSite=Lax` cookie named `googleauth_flow` — Lax being exactly the level that
*is* sent on that return navigation. Leave `security.mode` set to `strict`.

If it happens to everyone, check that the `googleauth_flow` cookie is reaching
the browser (developer tools → Application → Cookies) and that the
`googleauth_flow` table exists. A proxy or security plugin that strips unknown
cookies will break this flow.

### "This Google sign-in could not be verified in this browser"

The callback arrived without the `googleauth_flow` correlation cookie, or with
one that does not match. Either the customer has cookies blocked, or the sign-in
was started in one browser and finished in another — which is exactly what this
check is designed to refuse, since it is how an attacker would try to sign a
victim into the attacker's account.

### Callback errors, or something else entirely

Look at the FOSSBilling log. Everything this extension logs goes to the
`googleauth` channel, and the messages are written for administrators: they name
the failing step and the Google error code. They deliberately contain **no**
client secrets, tokens or authorization codes, so log excerpts are safe to
share when asking for help.

You will find them in FOSSBilling's configured log destination — by default
`data/log/` (and **Activity → Logs** in the admin area).

The customer, meanwhile, sees a short, neutral message. That asymmetry is
deliberate: detailed errors on the login page tell an attacker which accounts
exist.

### Google is down, or the network is blocked

Normal FOSSBilling login keeps working. The extension times out after ten
seconds, shows "Google could not be reached right now", and leaves the client
area entirely functional. Discovery and JWKS documents are cached, and the
extension falls back to Google's documented endpoint URLs if discovery itself is
unreachable.

---

## Testing your installation

Walk these ten scenarios after setting it up. They are the same scenarios the
extension was built against.

| # | Scenario | Expected |
| --- | --- | --- |
| 1 | Fresh install, before configuring | Disabled; mode is Login Only; no buttons anywhere |
| 2 | Enable with valid credentials, mode Login Only | "Continue with Google" appears on the login page only |
| 3 | A customer who has connected Google signs in with it | Signed in, landed on the dashboard |
| 4 | An unconnected Google account, mode Login Only | Refused with the "no linked account" message; **no customer is created** |
| 5 | A new Google account, mode Signup Only | A new customer is created, connected and signed in |
| 6 | A new Google account, mode Login & Signup | Same as 5 |
| 7 | A Google account whose email matches an existing customer | Refused with the "already exists" message; **nothing is linked or duplicated** |
| 8 | Tamper with `state` in the callback URL | Rejected; "could not be verified"; no sign-in |
| 9 | Press Cancel on Google's consent screen | Friendly message, back at the login page |
| 10 | Block `accounts.google.com` in your hosts file and try | Google fails gracefully; **email/password login still works** |

Also worth checking: connect Google from a profile page, then disconnect it and
confirm the customer can still sign in with their password; and confirm that a
second customer cannot connect a Google account that is already connected to
someone else.

### Running the automated tests

The unit suite covers the security-critical logic and runs standalone:

```bash
cd src/modules/Googleauth
composer install
composer test
```

It exercises configuration defaults and validation, authentication-mode parsing,
PKCE (including the RFC 7636 reference vector), state generation, matching,
replay and expiry, ID token verification against real RSA signatures — including
tampered claims, wrong audience, wrong nonce, expired tokens, `alg: none` and
foreign signing keys — open redirect handling, and Google identity parsing.

---

## Updating

1. **Back up** your database and your FOSSBilling directory. Always.
2. **Download** the new release.
3. **Replace the files** in `src/modules/Googleauth/`. Delete the old directory
   contents rather than merging them, so removed files do not linger:

   ```bash
   cd /path/to/fossbilling/src/modules
   mv Googleauth Googleauth.old
   unzip ~/Downloads/fossbilling-googleauth-x.y.z.zip
   mv fossbilling-googleauth-x.y.z Googleauth
   chown -R www-data:www-data Googleauth
   ```

4. **Run the update.** In the admin area, open **Extensions → Overview** and use
   the update action for the module. This re-checks requirements, brings the
   table up to date additively, re-registers the event listener and clears the
   cached Google metadata. There is never any manual SQL to run.
5. **Check the settings page.** The status badge should still read Enabled, with
   your mode and client ID intact.
6. **Test login** with a connected Google account.
7. **Test signup** if your mode allows it.
8. **Test normal FOSSBilling login** with email and password.
9. Remove `Googleauth.old` once you are satisfied.

**Your data is preserved.** Updating keeps your settings (enabled state, mode,
client ID, client secret) and every Google account connection. Schema changes,
if any future version needs them, are applied additively at update time.

---

## Uninstallation

1. **Optional but recommended for a clean removal:** on **Settings → Google
   Authentication**, click **Delete all connections**. This removes the Google
   sign-in option from every customer. Their accounts are untouched.
2. In **Extensions → Overview**, **Deactivate** the module. Google buttons
   disappear immediately; connections are kept.
3. Then **Uninstall** it. FOSSBilling removes the module's files.

What happens to each thing:

| Item | On uninstall |
| --- | --- |
| **Customer accounts** | **Never deleted.** Nor are invoices, orders, services or support tickets. |
| Customer passwords | Untouched; email/password login continues to work |
| Extension configuration | Removed with the extension's configuration row |
| The `googleauth_account` table | **Kept**, with its rows |
| Google account connections | **Kept** in that table unless you purged them in step 1 |

The table is deliberately *not* dropped on uninstall. It contains connections
that cannot be reconstructed, and an accidental uninstall that silently deleted
them would lock customers out of a sign-in method they rely on. Reinstalling the
extension picks the existing connections straight back up.

If you are certain you will never reinstall and want the table gone, purge the
connections first (step 1), then drop it by hand:

```sql
DROP TABLE googleauth_account;
```

---

## Developer documentation

### Architecture

The module follows FOSSBilling's own conventions — a service class, controllers
for admin and client areas, API classes per role, Doctrine entity and repository
— with the security-critical logic pulled out into small, dependency-free
classes that can be unit tested without booting the application.

| Layer | Where | What it does |
| --- | --- | --- |
| **Entry point** | `Service.php` | Install/uninstall/update, configuration, widget registration, and the two halves of the OAuth flow |
| **Controllers** | `Controller/Client.php`, `Controller/Admin.php` | Routes, redirects and rendering. Thin; no business logic |
| **APIs** | `Api/Admin.php`, `Api/Client.php`, `Api/Guest.php` | Everything reachable over the API, each with its own authorization |
| **Flow logic** | `Auth/` | Who this identity is, what may be done with it, and signing them in |
| **Google** | `Google/` | Discovery, the token exchange, JWKS, ID token verification, the identity value object |
| **OAuth primitives** | `OAuth/` | PKCE and state/nonce tokens |
| **Security** | `Security/` | Flow state storage, the session adapter, open redirect protection |
| **Configuration** | `Config/` | Typed configuration with safe defaults, and validation of administrator input |
| **Persistence** | `Entity/`, `Repository/` | The one table this extension owns |

### Project tree

```
Googleauth/
├── README.md
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── composer.json
├── phpunit.xml.dist
├── manifest.json
├── icon.svg
├── .gitignore
│
├── Service.php                       # module service: lifecycle, config, widgets, flow entry points
│
├── Api/
│   ├── Admin.php                     # status, redirect_uri, config_update, purge_links
│   ├── Client.php                    # status, disconnect
│   └── Guest.php                     # button_context, complete_signup
│
├── Controller/
│   ├── Admin.php                     # /googleauth (settings page) + navigation entry
│   └── Client.php                    # /googleauth/{login,signup,link,callback,complete,account}
│
├── Auth/
│   ├── AuthenticationFlow.php        # the login / signup / link decisions
│   ├── AccountLinker.php             # the Google sub <-> customer mapping
│   ├── CustomerProvisioner.php       # customer creation via FOSSBilling's own service
│   ├── SessionAuthenticator.php      # session regeneration and sign-in
│   ├── PendingSignupStore.php        # verified identity held for the completion form
│   ├── PendingSignup.php
│   └── FlowResult.php                # where to go next, and what to say
│
├── Google/
│   ├── GoogleOAuthClient.php         # discovery, authorization URL, token exchange, JWKS
│   ├── IdTokenVerifier.php           # RS256 signature + claim validation
│   ├── GoogleIdentity.php            # verified identity value object
│   ├── GoogleEndpoints.php           # endpoints, with trusted-host checks
│   └── Jwk.php                       # JWK -> OpenSSL public key
│
├── OAuth/
│   ├── Pkce.php                      # S256 verifier/challenge
│   └── StateToken.php                # state and nonce, constant-time comparison
│
├── Security/
│   ├── FlowStateStore.php            # single-use, session-bound flow state
│   ├── FlowState.php
│   ├── FossBillingSession.php        # adapter over FOSSBilling's session
│   ├── SessionStorageInterface.php
│   └── ReturnUrlGuard.php            # open redirect protection
│
├── Config/
│   ├── ExtensionConfig.php           # typed config; defaults to disabled + Login Only
│   └── ConfigValidator.php           # validates administrator input
│
├── Enum/
│   ├── AuthMode.php                  # login | signup | both
│   └── FlowIntent.php                # login | signup | link
│
├── Exception/
│   ├── GoogleAuthException.php       # log message + neutral customer message
│   └── ConfigurationException.php
│
├── Entity/
│   └── GoogleAccount.php             # the googleauth_account table
│
├── Repository/
│   └── GoogleAccountRepository.php
│
├── templates/
│   ├── admin/
│   │   └── mod_googleauth_settings.html.twig
│   └── client/
│       ├── mod_googleauth_account.html.twig
│       ├── mod_googleauth_complete.html.twig
│       ├── partial_googleauth_button.html.twig
│       └── widgets/
│           ├── mod_googleauth_login_button.html.twig
│           ├── mod_googleauth_signup_button.html.twig
│           └── mod_googleauth_profile_card.html.twig
│
├── locale/
│   └── googleauth.pot
│
├── tests/
│   ├── bootstrap.php
│   ├── Support/
│   │   ├── ArraySession.php
│   │   └── JwtFactory.php
│   └── Unit/
│       ├── AuthModeTest.php
│       ├── ConfigValidatorTest.php
│       ├── ExtensionConfigTest.php
│       ├── FlowStateStoreTest.php
│       ├── GoogleEndpointsTest.php
│       ├── GoogleIdentityTest.php
│       ├── IdTokenVerifierTest.php
│       ├── PkceTest.php
│       ├── ReturnUrlGuardTest.php
│       └── StateTokenTest.php
│
└── .github/workflows/ci.yml
```

### Routes

Client area (`Controller/Client.php`):

| Route | Purpose |
| --- | --- |
| `GET /googleauth/login` | Start a sign-in |
| `GET /googleauth/signup` | Start a registration |
| `GET /googleauth/link` | Connect Google to the signed-in customer (CSRF token required) |
| `GET /googleauth/callback` | Google redirects back here |
| `GET /googleauth/complete` | Finish a registration that needs more profile fields |
| `GET /googleauth/account` | The customer's Google connection page |

Admin area (`Controller/Admin.php`):

| Route | Purpose |
| --- | --- |
| `GET /{admin}/googleauth` | The settings page |

FOSSBilling also serves the same settings template at
`/{admin}/extension/settings/googleauth`, because
`templates/admin/mod_googleauth_settings.html.twig` exists.

### API methods

| Role | Method | Notes |
| --- | --- | --- |
| admin | `googleauth_status` | Configuration and status. Never includes the secret |
| admin | `googleauth_redirect_uri` | The generated redirect URI |
| admin | `googleauth_config_update` | Validates and saves. Requires `manage_settings` |
| admin | `googleauth_purge_links` | Deletes all connections. Requires `purge_links` |
| client | `googleauth_status` | The signed-in customer's connection state |
| client | `googleauth_disconnect` | Disconnects, unless it would lock them out |
| guest | `googleauth_button_context` | Drives the button widgets |
| guest | `googleauth_complete_signup` | Finishes a registration; CSRF token required |

### Widget slots used

| Slot | Template | Renders |
| --- | --- | --- |
| `client.page.login.form.after` | `mod_googleauth_login_button` | The login button |
| `client.theme.body.end` | `mod_googleauth_signup_button` | The signup button (signup page only) |
| `client.theme.content.before` | `mod_googleauth_profile_card` | The profile card (profile page only) |

Registered by `Service::getWidgets()` via FOSSBilling's
`WidgetProviderInterface`. This is how the extension reaches the login and
signup pages without touching a single core template.

### Events

The service exposes `onAfterAdminClientDelete(\Box_Event $event)`, registered
automatically by FOSSBilling's hook system. It removes the orphaned connection
when an administrator deletes a customer, and does nothing else.

### Configuration storage

Configuration is stored under the extension key `mod_googleauth` through
FOSSBilling's extension service, which encrypts the whole blob. Read it with
`$di['mod_config']('googleauth')`, or — typed, with safe defaults —
`$di['mod_service']('googleauth')->getConfig()`.

### Database

One table, created from the Doctrine entity at install time using only that
entity's metadata, so it works identically on MySQL, PostgreSQL and SQLite and
never touches the rest of the schema. `client_id` is a plain indexed column
rather than a Doctrine association, which keeps the extension decoupled from the
core `Client` entity.

### Extending it

- **Change the button's look:** override
  `partial_googleauth_button.html.twig` in your theme's `html_custom/`.
- **Move the buttons:** override the page templates in your theme and include
  the partial where you want it, using `guest.googleauth_button_context`.
- **React to Google logins:** listen for `onAfterClientLogin`; the extension
  fires it with `auth: 'google'` in the parameters.
- **Read a customer's connection state in your own code:**
  `$di['mod_service']('googleauth')->getClientLinkStatus($clientId)`.

### Running the tests

```bash
composer install
composer test      # PHPUnit
composer lint      # php -l over every file
```

The suite has no FOSSBilling dependency by design. The same files are also
picked up by FOSSBilling's own `composer test` when the module is installed at
`src/modules/Googleauth`, because Pest runs PHPUnit test classes as they are.

---

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the full
guide. In short:

1. **Fork** the repository on GitHub.
2. **Clone** your fork.
3. **Create a branch**: `git checkout -b fix/state-replay`.
4. **Make your changes**, with tests.
5. **Run the tests**: `composer test`.
6. **Check coding standards**: `composer lint`; PHP 8.3+, `strict_types`,
   PSR-12, no core modifications, no hard-coded URLs.
7. **Submit a pull request** against `main`, explaining what changed, why, and
   how you verified it.

Security-conscious contributions are especially welcome. If you touch `Auth/`,
`Google/`, `OAuth/` or `Security/`, please say in the pull request what an
attacker could try against the new code and why it fails.

---

## Reporting security issues

**Please do not report security vulnerabilities through public GitHub issues,
pull requests or discussions.** Doing so tells attackers about the flaw before
administrators can update.

Email **[support@webboomers.in](mailto:support@webboomers.in)** with the subject
`GoogleAuth security report`. Include the versions involved, the impact, and
steps to reproduce — and please redact any real credentials or customer data.

You will get an acknowledgement within 3 business days and an assessment within
10. Full policy: [SECURITY.md](SECURITY.md).

---

## Support

For support, contact:

**support@webboomers.in**

Website:

**www.webboomers.in**

For bugs and feature requests that are *not* security issues, please open an
issue on GitHub.

---

## Licence

MIT — see [LICENSE](LICENSE). You are free to use, modify and redistribute this
extension, including commercially. It is deliberately built to be reusable by
any FOSSBilling operator: there is no Web Boomers domain, customer ID, API key
or URL anywhere in the authentication logic, and nothing in the customer-facing
interface advertises us. The attribution below is the original-developer credit
and is not a requirement you have to pass on to your own customers.

FOSSBilling itself is licensed under Apache-2.0 and is a separate project; this
extension is not affiliated with or endorsed by the FOSSBilling project, and
"Google" is a trademark of Google LLC, used here only to describe compatibility.

---

**Developed by Web Boomers**

Website: [https://www.webboomers.in](https://www.webboomers.in)
Support: [support@webboomers.in](mailto:support@webboomers.in)
