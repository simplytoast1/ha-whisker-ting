# Security policy

## Supported versions

Security fixes go into the latest release only. Before you report a problem, check that it still happens on the latest release.

## Report a vulnerability

Don't describe security problems in public issues.

1. Report the problem privately with [GitHub private vulnerability reporting](https://github.com/simplytoast1/ha-whisker-ting/security/advisories/new).
2. If you can't use private reporting, open an issue that asks the maintainer to contact you. Don't include any details about the problem in the issue.

In your report, include:

- The versions of this integration and Home Assistant that you use.
- The steps to reproduce the problem.
- What an attacker could do with it.

You'll get a reply in the advisory. If the advisory is published, it credits you unless you ask not to be credited.

### Security contacts

Private reports go to the maintainer, @simplytoast1. @jasonjhofmann helps triage them.

## Scope

This integration signs in to your Ting account and receives your data from Whisker Labs' cloud service.

In scope:

- How the integration handles your Ting password, refresh token, and API key.
- What the integration writes to the Home Assistant log and includes in diagnostics downloads.
- Connections to Whisker Labs' API, its live voltage stream, and its Amazon Cognito sign-in, including certificate checks.
- Parsing of API responses and live stream messages.
- Notifications that the integration creates from Ting alerts.

Out of scope:

- Vulnerabilities in Whisker Labs' cloud service, the Ting app, or Ting sensors. Report them to Whisker Labs.
- Sending your API key to the live voltage stream. Whisker Labs' server accepts nothing else ([#2](https://github.com/simplytoast1/ha-whisker-ting/issues/2)). How the integration protects the key is still in scope.
- Vulnerabilities in Home Assistant itself. Report them through the [Home Assistant security policy](https://www.home-assistant.io/security/).
- Vulnerabilities in third-party libraries. Report them to that library's maintainers.
