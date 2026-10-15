"""Reference solution: rebuilds each robot's Chromium cookie store from the proxy log and writes
the Cookie header of every request to /app/output/cookie_headers.json."""
import json, os, sys
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cookiestore import CookieStore, Features, parse_cookie_line, parse_expires, cookie_line
from browsing import Tab, script_context, url_port
from tagmanager import TagManager

TM_BEACON_DELAY = 0.15   # tm.js sends its beacon 150 ms after it has written its cookies
DATA = os.environ.get('DATA_DIR', '/app/data')
OUT = os.environ.get('OUT_PATH', '/app/output/cookie_headers.json')


def ts(s):
    return datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp()


class RobotBrowser:
    """One long-lived browser context: its cookie store and the frame tree of its tab."""

    def __init__(self, tm_config, features=Features()):
        self.features = features
        self.store = CookieStore(features)
        self.tab = Tab()
        self.tm_config = tm_config
        self.tag_manager = None

    def tag_manager_run(self, r, beacon_time):
        """A beacon means tm.js ran on the reported page 150 ms earlier: replay the script against
        this profile's localStorage and apply its document.cookie assignments."""
        payload = json.loads(r['request_body'])
        page = payload['page']
        if self.tag_manager is None:
            self.tag_manager = TagManager(self.tm_config, r['request_headers']['User-Agent'])
        now = beacon_time - TM_BEACON_DELAY
        writes, uid, session = self.tag_manager.run(page, now * 1000.0)
        if (uid, session) != (payload['cid'], payload['ses']):
            raise RuntimeError(f"tag manager state diverged at {r['id']}: {uid} {session} vs {payload}")
        ctx, pk, secure = script_context(page)
        u = urlsplit(page)
        for w in writes:
            cc = parse_cookie_line(w, u.scheme, u.hostname, u.path or '/', now, None, pk,
                                   url_port(page), self.features)
            if cc is not None:
                self.store.set_cookie(cc, secure, ctx, True, now)

    def request(self, r):
        now = ts(r['ts'])
        if r.get('request_body') and r['url'].endswith('/tm/audit'):
            self.tag_manager_run(r, now)
        req = self.tab.classify(r)
        ctx, set_ctx, pk = self.tab.context(r, req, self.features.redirect_chain)
        u = urlsplit(r['url'])
        port = url_port(r['url'])
        sent = self.store.cookies_for_request(u.scheme, u.hostname, u.path or '/', ctx, pk, now, port)
        header = cookie_line(sent)
        resp = r['response_headers']
        server_date = parse_expires(resp['Date']) if resp.get('Date') else None
        for line in resp.get('Set-Cookie', []):
            cc = parse_cookie_line(line, u.scheme, u.hostname, u.path or '/', now, server_date, pk,
                                   port, self.features)
            if cc is not None:
                self.store.set_cookie(cc, u.scheme == 'https', set_ctx, False, now)
        # Clear-Site-Data is acted on once the response's own cookies are stored, so those go too.
        directives = [d.strip().strip('"') for d in resp.get('Clear-Site-Data', '').split(',')]
        if 'cookies' in directives and u.scheme == 'https':
            self.store.clear_site_data(u.hostname, pk)
        if 'storage' in directives and u.scheme == 'https' and self.tag_manager:
            self.tag_manager.storage.pop(f'{u.scheme}://{u.netloc}', None)
        self.tab.done(r, req)
        return header


def main():
    by_robot = defaultdict(list)
    with open(f'{DATA}/proxy/requests.jsonl') as f:
        for line in f:
            r = json.loads(line)
            by_robot[r['robot']].append(r)
    with open(f'{DATA}/site/tm-config.json') as f:
        tm_config = json.load(f)
    with open(f'{DATA}/fleet.json') as f:
        fleet = json.load(f)
    switches = {robot: pool['extra_chromium_args'] for pool in fleet['pools'].values()
                for robot in pool['robots']}
    out = {}
    for robot, rows in sorted(by_robot.items()):
        rows.sort(key=lambda r: (ts(r['ts']), r['id']))
        b = RobotBrowser(tm_config, Features.from_switches(switches[robot]))
        for r in rows:
            out[r['id']] = b.request(r)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w') as f:
        json.dump(out, f, indent=0, sort_keys=True)
    print(f'wrote {len(out)} request headers to {OUT}')


if __name__ == '__main__':
    main()
