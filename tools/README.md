# Tools

Addons that are not payment methods: the Telegram bot and its Mini App first, then what
admins write themselves. Each goes in `tools/<id>/`, laid out like a payment adapter
(`adapter.json` with `"category": "tools"`, the code, tests, a `Dockerfile`), and is
published as `ghcr.io/getmikan/tool-<id>`.

A tool does more than a payment adapter: it reads and changes the panel's users and
subscriptions, hears the panel's events and has its own settings and pages. Its protocol,
the panel's API for addons, is being designed, and there are no tools here yet. Whatever it becomes,
a tool never speaks the payment protocol (1), so the panels of today never offer one.
