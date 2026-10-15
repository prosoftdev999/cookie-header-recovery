Proxy log of the Alderbay synthetic-shopper campaign, 2026-09-07 to 2026-09-24 (UTC).

proxy/requests.jsonl has one JSON object per request, in proxy arrival order per robot:

- id: robot id and a per-robot sequence number; sequence order is arrival order.
- robot: r01 to r16. Each robot drove a single tab in its own browser context.
- ts: time the proxy received the request, UTC with milliseconds. The robots' clocks and the
  proxy clock are the same clock.
- method, url, status.
- request_headers: User-Agent, Accept, Upgrade-Insecure-Requests, Referer, Origin, Content-Type
  and the Sec-Fetch-* headers when the browser sent them. The privacy filter removed Cookie.
- response_headers: Date, Location, Clear-Site-Data, and Set-Cookie as a list in the order the
  server sent them.
- request_body: present only on POSTs to https://www.alderbay.com/tm/audit (see below).

fleet.json lists the robot pools: which robots belong to each and the extra command-line
switches that pool's Chromium was launched with, on top of the stock headless-shell defaults.

site/tm.js is the tag manager exactly as deployed, and site/tm-config.json is the object the
pages expose to it as window.tmConfig. The script runs once per page view on the storefront
pages that load it, and every run ends with the audit beacon, so the beacons in the log are
the complete list of its runs. A beacon's request_body is the JSON the script sent; its page
field is the URL of the top-level page the script ran in.

Each visit began with the robot opening a URL directly in its tab, so no page started that
navigation. Every other navigation was started by a document that was open in the tab at the
time, the page or one of its frames (a link, a form or a script).

Product pages show shopper reviews in an iframe loaded from www.alderbay.com/ugc/ with
sandbox="allow-scripts allow-forms allow-top-navigation-by-user-activation". No other iframe
on any of the sites is sandboxed.

Every request each robot's browser made is in the log, including redirect hops, iframe
loads and requests made from inside iframes. No request failed and every response was
delivered to the page. A robot's requests never overlapped: each response had arrived before
its next request was sent. Every fetch the pages made was sent with credentials included.

The hosts were lab stand-ins that answered from a script written before the campaign. No
response, and no Set-Cookie value in one, depends on the cookies its request carried: a
server repeats or changes a cart, session or node id on its own schedule either way.
