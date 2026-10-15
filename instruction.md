I need the exact Cookie header each of our synthetic shopper robots sent on every request of the last campaign.

A robot is Playwright driving Chromium 153.0.8010.12, the headless shell build. They run in four pools, and /app/data/fleet.json lists the extra Chromium switches each pool was launched with; nothing else was changed from the defaults. Each robot had a single browser context that started with an empty profile (no cookies, no storage) and stayed open for the whole campaign, and the browser was never restarted. All traffic went through our egress proxy. Its log is /app/data/proxy/requests.jsonl and /app/data/README.md explains the fields. The proxy's privacy filter stripped the Cookie header from every request it logged.

Cookies got into those browsers in two ways only: Set-Cookie headers, all of which are in the log, and document.cookie assignments by our tag manager. The tag manager is /app/data/site/tm.js; it ran with /app/data/site/tm-config.json on every page that sent its audit beacon. No script read document.cookie, and apart from the response headers in the log nothing else changed or cleared cookies or storage.

Write /app/output/cookie_headers.json as one JSON object with exactly one key per request id in the log and no other keys. The value is the Cookie request header Chromium attached to that request, as a string, or null when it attached none. With made-up values: {"r03-00017": "sid=4f1; cart=88a", "r03-00018": null}.

A value is compared as its list of name=value entries, split at ";" with surrounding whitespace ignored. The order of entries counts, an empty string is the same as null, and every request has to match.

You have 9000 seconds to complete this task. Do not cheat by using online solutions or hints specific to this task.
