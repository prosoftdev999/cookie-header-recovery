"""Python port of the storefront tag manager (data/site/tm.js): what it assigns to
document.cookie on a page view, given its per-origin localStorage."""
import re
from urllib.parse import urlsplit

SESSION_IDLE_MS = 1800000
PRODUCT_PATH = re.compile(r'^/p/([a-z0-9]+)$')


def fnv(s):
    h = 0x811c9dc5
    for ch in s:
        h ^= ord(ch)
        h = (h * 0x01000193) & 0xffffffff
    return h


def base36(n):
    digits = '0123456789abcdefghijklmnopqrstuvwxyz'
    out = ''
    while True:
        n, r = divmod(n, 36)
        out = digits[r] + out
        if n == 0:
            return out


class TagManager:
    """One browser profile's view of the script: localStorage is kept per origin."""

    def __init__(self, config, user_agent):
        self.config = config
        self.user_agent = user_agent
        self.storage = {}

    def run(self, page_url, now_ms):
        """Returns (cookie strings in assignment order, visitor id, session label)."""
        u = urlsplit(page_url)
        origin = f'{u.scheme}://{u.netloc}'
        ls = self.storage.setdefault(origin, {})
        written = []

        def put(name, value, max_age, extra=''):
            written.append(f'{name}={value}; Max-Age={max_age}; Domain=alderbay.com; Path=/{extra}')

        uid = ls.get('mf_uid')
        if not uid:
            uid = ls['mf_uid'] = base36(fnv(origin + '|' + self.user_agent))
            put('_mf_uid', uid, 34560000, '; Secure' if u.scheme == 'https' else '')

        ses = ls.get('mf_ses')
        if not ses or now_ms - ses['last'] > SESSION_IDLE_MS:
            count = (ses['count'] if ses else 0) + 1
            ses = {'id': base36(fnv(f'{uid}|{count}')), 'count': count, 'pages': 0}
        ses['pages'] += 1
        ses['last'] = now_ms
        ls['mf_ses'] = ses
        label = f"{ses['id']}.{ses['pages']}"
        put('_mf_ses', label, 1800)
        put('consent', 'v3.all', 15552000)

        m = PRODUCT_PATH.match(u.path) if u.hostname == 'shop.alderbay.com' else None
        if m:
            sku = m.group(1)
            for tile in self.config['related'].get(sku, []):
                put('_xt_' + tile, 'abc'[fnv(f'{uid}|{tile}') % 3], 7776000)
            seen = ls.setdefault('mf_exp', [])
            for k in self.config['campaigns']:
                if (k['category'] == self.config['category'].get(sku)
                        and k['start'] <= now_ms < k['end'] and k['code'] not in seen):
                    seen.append(k['code'])
                    put('_exp_' + k['code'], 'ab'[fnv(f"{uid}|{k['code']}") % 2], 7776000, '; Priority=Low')

        if u.path == '/privacy':
            put('sid', '', 0)
            put('cart', '', 0)
        return written, uid, label
