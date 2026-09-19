# Contributing to GoogleAuth for FOSSBilling

Thanks for considering a contribution. Bug reports, documentation fixes,
translations and code are all welcome.

**Security problems are the exception: do not open an issue or pull request for
one.** Email <support@webboomers.in> instead — see [SECURITY.md](SECURITY.md).

## Getting set up

You need a working FOSSBilling installation (0.8.2 or newer) to run the
extension, and PHP 8.3+ with the `openssl`, `json`, `curl`, `intl` and `mbstring`
extensions.

```bash
# 1. Fork the repository on GitHub, then clone your fork
git clone https://github.com/<your-username>/fossbilling-googleauth.git
cd fossbilling-googleauth

# 2. Install the dev dependencies (PHPUnit only - the module itself has none)
composer install

# 3. Run the tests
composer test
```

To try your changes against a real FOSSBilling, symlink or copy the checkout
into the modules directory under the name `Googleauth` (the capitalisation
matters — see "Naming" below):

```bash
ln -s "$(pwd)" /path/to/fossbilling/src/modules/Googleauth
```

Then activate the extension in **Extensions → Overview** and configure it in
**Settings → Google Authentication**.

For a Google OAuth client you can point at a local install, create a test client
in the [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
and add your local redirect URI to it. Keep test credentials out of the
repository — `.gitignore` already excludes the usual filenames, but check your
diffs.

## Naming

FOSSBilling lowercases module names and then `ucfirst()`s them to resolve
classes, so the directory must be `Googleauth` and the namespace
`Box\Mod\Googleauth`. A directory called `GoogleAuth` will not load. The
human-readable name ("Google Authentication") lives in `manifest.json`.

## Coding standards

- PHP 8.3+, `declare(strict_types=1)` in every file.
- Type declarations on parameters, properties and return types.
- PSR-12 formatting and PSR-4 autoloading.
- Follow the conventions already in this repository and in FOSSBilling core:
  services take the Pimple container, controllers stay thin, and business logic
  lives in `Auth/`, `Config/`, `Google/`, `OAuth/` and `Security/`.
- No raw SQL string concatenation. Use Doctrine and parameterised queries.
- No hard-coded URLs, domains or credentials. The redirect URI is derived from
  the installation's own configured URL.
- Never modify FOSSBilling core files, and never ask users to.
- Customer-facing strings go through `__trans()` in PHP and `|trans` in Twig.

A quick syntax check over the whole tree:

```bash
composer lint
```

If you have FOSSBilling's dev tooling available, running its `php-cs-fixer`
configuration over your changes keeps formatting consistent with core.

## Security-conscious contributions

This extension guards a login. When you change anything under `Auth/`, `Google/`,
`OAuth/` or `Security/`, please also explain in the pull request:

- what an attacker could try against the new code, and why it fails;
- whether the change affects state, PKCE, nonce, ID token validation, session
  handling or account linking;
- which tests cover it.

Rules of thumb that must keep holding:

- A Google identity is identified by `sub`, never by an email address.
- A matching email address never links, claims or creates an account by itself.
- Linking only ever happens for a customer who is signed in during that request.
- OAuth state is single-use, session-bound and compared in constant time.
- The session ID is regenerated on every successful sign-in.
- Client secrets, tokens and authorization codes never reach the log, the
  browser or any API response.

## Tests

Add tests for anything you change. The suite in `tests/Unit/` runs standalone
with PHPUnit and deliberately avoids FOSSBilling dependencies, so keep new
security-critical logic in classes that can be tested that way.

```bash
composer test
```

The same files are also picked up by FOSSBilling's own test run when the module
is installed at `src/modules/Googleauth`.

## Commits

- One logical change per commit.
- Present-tense, imperative subject lines, ideally under 72 characters:
  `Reject ID tokens whose azp does not match the client`.
- Reference an issue in the body where one exists (`Refs #12`, `Fixes #12`).
- Sign off your commits if your employer requires it.

## Pull requests

1. Branch from `main`: `git checkout -b fix/state-replay`.
2. Make your change, with tests and documentation.
3. Run `composer test` and `composer lint`.
4. Push and open a pull request against `main`.
5. Describe **what** changed, **why**, and how you verified it. Include the
   FOSSBilling and PHP versions you tested on.

Pull requests that change behaviour should update `README.md` and add an entry
to `CHANGELOG.md` under an "Unreleased" heading.

## Translations

All customer-facing strings are translatable. `locale/googleauth.pot` is the
template; FOSSBilling itself loads translations from its own message catalogue,
so translated strings are contributed through the FOSSBilling translation
workflow. If you spot an untranslated string in this extension, that is a bug —
please report it.

## Licence

By contributing you agree that your contribution is licensed under the MIT
Licence, the same as the rest of this project.

---

Maintained by [Web Boomers](https://www.webboomers.in) ·
[support@webboomers.in](mailto:support@webboomers.in)
