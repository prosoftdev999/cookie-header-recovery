"""Cookie store model following Chromium 153's CookieMonster (net/cookies): schemeful same-site,
Lax-by-default with the Lax-allowing-unsafe exception, CHIPS partitions, per-registrable-domain
eviction and the 60 second access-time granularity, plus the feature switches the robot pools
were launched with (origin-bound cookies, time-limited insecure cookies, Lax-unsafe variants)."""
import calendar
from dataclasses import dataclass

DAY = 86400.0
MAX_EXPIRY_AGE = 400 * DAY
INSECURE_MAX_EXPIRY_AGE = 3 * 3600.0
LAX_ALLOW_UNSAFE_MAX_AGE = 120.0
SHORT_LAX_ALLOW_UNSAFE_MAX_AGE = 10.0
ACCESS_UPDATE_THRESHOLD = 60.0
DOMAIN_MAX_COOKIES, DOMAIN_PURGE_COOKIES = 180, 30
DOMAIN_QUOTA = {'low': 30, 'medium': 50, 'high': 180 - 30 - 30 - 50}
PARTITION_MAX_COOKIES, PARTITION_MAX_BYTES = 180, 10240
PURGE_ROUNDS = [('low', True), ('low', False), ('medium', True), ('high', True),
                ('medium', False), ('high', False)]

# SameSite context levels, ordered as Chromium's ContextType.
CROSS_SITE, LAX_METHOD_UNSAFE, SAME_SITE_LAX, SAME_SITE_STRICT = 0, 1, 2, 3

PUBLIC_SUFFIXES = {'com', 'net', 'io', 'org'}


@dataclass(frozen=True)
class Features:
    """--enable-features switches that change cookie handling (all off in stock Chromium 153)."""
    scheme_bound: bool = False            # EnableSchemeBoundCookies
    port_bound: bool = False              # EnablePortBoundCookies
    time_limited_insecure: bool = False   # TimeLimitedInsecureCookies (needs scheme_bound)
    short_lax_unsafe: bool = False        # ShortLaxAllowUnsafeThreshold
    rigorous_lax: bool = False            # SameSiteDefaultChecksMethodRigorously
    redirect_chain: bool = False          # CookieSameSiteConsidersRedirectChain

    NAMES = {'EnableSchemeBoundCookies': 'scheme_bound', 'EnablePortBoundCookies': 'port_bound',
             'TimeLimitedInsecureCookies': 'time_limited_insecure',
             'ShortLaxAllowUnsafeThreshold': 'short_lax_unsafe',
             'SameSiteDefaultChecksMethodRigorously': 'rigorous_lax',
             'CookieSameSiteConsidersRedirectChain': 'redirect_chain'}

    @classmethod
    def from_switches(cls, args):
        on = {}
        for arg in args:
            if arg.startswith('--enable-features='):
                for name in arg.split('=', 1)[1].split(','):
                    if name in cls.NAMES:
                        on[cls.NAMES[name]] = True
        return cls(**on)

    @property
    def origin_bound(self):
        return self.scheme_bound or self.port_bound

    @property
    def lax_unsafe_max_age(self):
        if self.rigorous_lax:
            return None
        return SHORT_LAX_ALLOW_UNSAFE_MAX_AGE if self.short_lax_unsafe else LAX_ALLOW_UNSAFE_MAX_AGE


def registrable_domain(host):
    labels = host.lower().split('.')
    for i in range(len(labels)):
        if '.'.join(labels[i:]) in PUBLIC_SUFFIXES:
            return '.'.join(labels[i - 1:]) if i > 0 else None
    return host.lower()


def schemeful_site(scheme, host):
    return (scheme, registrable_domain(host))


def domain_match(cookie_domain, host):
    if cookie_domain.startswith('.'):
        return host == cookie_domain[1:] or host.endswith(cookie_domain)
    return host == cookie_domain


def path_match(cookie_path, url_path):
    if not url_path.startswith(cookie_path):
        return False
    return (cookie_path.endswith('/') or len(url_path) == len(cookie_path)
            or url_path[len(cookie_path)] == '/')


def default_path(url_path):
    if not url_path.startswith('/'):
        return '/'
    idx = url_path.rfind('/')
    return '/' if idx == 0 else url_path[:idx]


def is_subdomain_of(sub, parent):
    return sub == parent or sub.endswith('.' + parent)


@dataclass
class Cookie:
    name: str
    value: str
    domain: str
    path: str
    creation: float
    expiry: float | None
    last_access: float
    secure: bool
    httponly: bool
    samesite: str          # 'unspecified' | 'none' | 'lax' | 'strict'
    priority: str          # 'low' | 'medium' | 'high'
    partition: tuple | None
    source_secure: bool    # set by an https URL (or carries Secure)
    source_port: int

    def expired(self, now):
        return self.expiry is not None and now >= self.expiry

    def is_host_cookie(self):
        return not self.domain.startswith('.')

    def size(self):
        return len(self.name) + len(self.value)


MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']
DATE_DELIMITERS = '\t !"#$%&\'()*+,-./;<=>?@[\\]^_`{|}~'


def parse_expires(text):
    """cookie_util::ParseCookieExpirationTime: free-order tokens, month by its first three
    letters, a two-digit year below 70 meaning 20xx. Returns a UTC timestamp or None."""
    tokens, cur = [], ''
    for ch in text:
        if ch in DATE_DELIMITERS:
            if cur:
                tokens.append(cur)
            cur = ''
        else:
            cur += ch
    if cur:
        tokens.append(cur)
    month = day = year = clock = None
    for tok in tokens:
        low = tok.lower()
        if not tok[0].isdigit():
            if month is None and low[:3] in MONTHS:
                month = MONTHS.index(low[:3]) + 1
        elif ':' in tok:
            if clock is None:
                parts = tok.split(':')
                if len(parts) == 3 and all(x.isdigit() for x in parts):
                    clock = tuple(int(x) for x in parts)
        elif tok.isdigit():
            if day is None and len(tok) <= 2:
                day = int(tok)
            elif year is None and len(tok) <= 5:
                year = int(tok)
    if None in (month, day, year, clock):
        return None
    if year < 70:
        year += 2000
    elif year < 100:
        year += 1900
    if not (1 <= day <= 31 and clock[0] <= 23 and clock[1] <= 59 and clock[2] <= 59 and year >= 1601):
        return None
    try:
        return calendar.timegm((year, month, day) + clock)
    except (ValueError, OverflowError):
        return None


def prefix_ok(name, secure, url_secure, has_domain, path):
    """__Secure- and __Host- name prefixes (matched without regard to case)."""
    low = name.lower()
    if low.startswith('__secure-'):
        return secure and url_secure
    if low.startswith('__host-'):
        return secure and url_secure and not has_domain and path == '/'
    return True


def parse_cookie_line(line, url_scheme, url_host, url_path, now, server_date=None,
                      partition_key=None, url_port=None, features=Features()):
    """CanonicalCookie::Create for the attribute forms used by the robots' sites.
    Returns a Cookie or None when Chromium refuses to create it."""
    parts = line.split(';')
    pair = parts[0]
    if '=' in pair:
        name, value = pair.split('=', 1)
    else:
        name, value = '', pair
    name, value = name.strip(' \t'), value.strip(' \t')
    attrs = {}
    for raw in parts[1:]:
        if '=' in raw:
            k, v = raw.split('=', 1)
        else:
            k, v = raw, ''
        attrs[k.strip(' \t').lower()] = v.strip(' \t')   # later attributes win

    has_domain = bool(attrs.get('domain'))
    if has_domain:
        d = attrs['domain'].lower().lstrip('.')
        if not is_subdomain_of(url_host, d):
            return None
        if registrable_domain(d) is None and d != url_host:
            return None
        domain = '.' + d
    else:
        domain = url_host

    p = attrs.get('path', '')
    path = p if p.startswith('/') else default_path(url_path)

    secure = 'secure' in attrs
    source_secure = secure or url_scheme == 'https'
    if not prefix_ok(name, secure, url_scheme == 'https', has_domain, path):
        return None
    if url_port is None:
        url_port = 443 if url_scheme == 'https' else 80
    source_port = 443 if (secure and url_scheme != 'https') else url_port

    expiry = None
    if 'max-age' in attrs:
        try:
            delta = int(attrs['max-age'])
            expiry = now + delta if delta > 0 else float('-inf')
        except ValueError:
            pass
    if expiry is None and 'expires' in attrs:
        exp = parse_expires(attrs['expires'])
        if exp is not None:
            # Chromium corrects the server's Expires by the skew between the response's Date
            # header and its own clock.
            ref = server_date if server_date is not None else now
            expiry = now + (exp - ref)
    cap = MAX_EXPIRY_AGE
    if features.scheme_bound and features.time_limited_insecure and not source_secure:
        cap = INSECURE_MAX_EXPIRY_AGE
    if expiry is not None and expiry > now + cap:
        expiry = now + cap

    ss = attrs.get('samesite', '').lower()
    samesite = ss if ss in ('none', 'lax', 'strict') else 'unspecified'
    pr = attrs.get('priority', '').lower()
    priority = pr if pr in ('low', 'medium', 'high') else 'medium'
    partition = None
    if 'partitioned' in attrs:
        if not secure:
            return None
        partition = partition_key
    return Cookie(name, value, domain, path, now, expiry, now, secure, 'httponly' in attrs,
                  samesite, priority, partition, source_secure, source_port)


class CookieStore:
    def __init__(self, features=Features()):
        self.features = features
        self.cookies = {}       # registrable domain -> [Cookie]
        self.partitioned = {}   # partition key -> {registrable domain -> [Cookie]}
        self.purges = []        # (time, key, [evicted names]) for diagnostics
        self._last_stamp = float('-inf')

    def _stamp(self, now):
        # Chromium reads a microsecond clock for every cookie it creates, so two cookies are never
        # created at the same instant; keep creations strictly increasing in arrival order.
        self._last_stamp = max(now, self._last_stamp + 1e-6)
        return self._last_stamp

    def _bucket(self, key, partition):
        if partition is None:
            return self.cookies.setdefault(key, [])
        return self.partitioned.setdefault(partition, {}).setdefault(key, [])

    def unique_key(self, c):
        """CookieBase::RefUniqueKey: origin-bound switches add scheme (and port for host cookies)."""
        scheme = c.source_secure if self.features.scheme_bound else None
        port = c.source_port if (self.features.port_bound and c.is_host_cookie()) else None
        return (c.name, c.domain, c.path, scheme, port)

    def is_secure(self, c):
        """CookieBase::IsSecure."""
        return c.secure or (self.features.scheme_bound and c.source_secure)

    # ---- writes -------------------------------------------------------------------------
    def set_cookie(self, cc, source_secure, set_context, is_script, now):
        """SetCanonicalCookie. Returns a short status string."""
        if cc.secure and not source_secure:
            return 'secure-only'
        if is_script and cc.httponly:
            return 'httponly'
        if cc.samesite == 'none' and not cc.secure:
            return 'none-insecure'
        if cc.samesite in ('strict', 'lax', 'unspecified') and set_context < SAME_SITE_LAX:
            return 'samesite'
        key = registrable_domain(cc.domain.lstrip('.'))
        bucket = self._bucket(key, cc.partition)
        blocked = None
        existing = None
        new_key = self.unique_key(cc)
        for cur in bucket:
            if cur.secure and not source_secure and self._equivalent_for_secure(cc, cur):
                blocked = 'overwrite-secure'
            if self.unique_key(cur) == new_key:
                if is_script and cur.httponly:
                    blocked = blocked or 'overwrite-httponly'
                existing = cur
        if blocked:
            return blocked
        stamp = self._stamp(now)
        cc.creation = cc.last_access = stamp
        inherit = None
        if existing is not None:
            if existing.value == cc.value:
                inherit = existing.creation
            bucket.remove(existing)
        if not cc.expired(now):
            if inherit is not None:
                cc.creation = inherit
            bucket.append(cc)
        if cc.partition is None:
            self._garbage_collect(now, key)
        else:
            self._garbage_collect_partition(now, cc.partition, key)
        return 'ok'

    @staticmethod
    def _equivalent_for_secure(new, secure_cookie):
        same_name = new.name == secure_cookie.name
        a, b = new.domain.lstrip('.'), secure_cookie.domain.lstrip('.')
        dm = is_subdomain_of(a, b) or is_subdomain_of(b, a)
        return (new.partition == secure_cookie.partition and same_name and dm
                and path_match(secure_cookie.path, new.path))

    def _garbage_collect(self, now, key):
        bucket = self.cookies.get(key, [])
        if len(bucket) <= DOMAIN_MAX_COOKIES:
            return
        bucket[:] = [c for c in bucket if not c.expired(now)]
        if len(bucket) <= DOMAIN_MAX_COOKIES:
            return
        purge_goal = len(bucket) - (DOMAIN_MAX_COOKIES - DOMAIN_PURGE_COOKIES)
        lru = sorted(bucket, key=lambda c: (c.last_access, c.creation))
        evicted = []
        purge = self._purge_origin_bound if self.features.origin_bound else self._purge_least_recent
        for priority, protect_secure in PURGE_ROUNDS:
            if purge_goal <= 0:
                break
            purge_goal -= purge(lru, priority, DOMAIN_QUOTA[priority], purge_goal, protect_secure, evicted)
        gone = set(map(id, evicted))
        bucket[:] = [c for c in bucket if id(c) not in gone]
        self.purges.append((now, key, [c.name for c in evicted]))

    @staticmethod
    def _purge_least_recent(lru, priority, to_protect, purge_goal, protect_secure, evicted):
        """PurgeLeastRecentMatches (stock behaviour)."""
        count = sum(1 for c in lru if c.priority == priority)
        if count <= to_protect:
            return 0
        if protect_secure:
            secure = sum(1 for c in lru if c.priority == priority and c.secure)
            possible = count - max(secure, to_protect)
        else:
            possible = count - to_protect
        removed = 0
        i = 0
        while removed < purge_goal and i < len(lru) and possible > 0:
            c = lru[i]
            if c.priority == priority and not (protect_secure and c.secure):
                evicted.append(c)
                del lru[i]
                removed += 1
                possible -= 1
            else:
                i += 1
        return removed

    def _purge_origin_bound(self, lru, priority, to_protect, purge_goal, protect_secure, evicted):
        """PurgeLeastRecentMatchesForOBC: within a round, domain cookies go before host cookies."""
        delete_secure = not protect_secure
        at_priority = [c for c in lru if c.priority == priority]
        if len(at_priority) <= to_protect:
            return 0
        deletable = [c for c in at_priority if self.is_secure(c) == delete_secure]
        budget = min(len(deletable), len(at_priority) - to_protect, purge_goal)
        ordered = [c for c in deletable if not c.is_host_cookie()] + [c for c in deletable if c.is_host_cookie()]
        victims = ordered[:budget]
        gone = set(map(id, victims))
        lru[:] = [c for c in lru if id(c) not in gone]
        evicted.extend(victims)
        return len(victims)

    def _garbage_collect_partition(self, now, partition, key):
        bucket = self.partitioned.get(partition, {}).get(key, [])
        if (sum(c.size() for c in bucket) <= PARTITION_MAX_BYTES
                and len(bucket) <= PARTITION_MAX_COOKIES):
            return
        bucket[:] = [c for c in bucket if not c.expired(now)]
        used = sum(c.size() for c in bucket)
        lru = sorted(bucket, key=lambda c: (c.last_access, c.creation))
        if self.features.origin_bound:
            lru = [c for c in lru if not c.is_host_cookie()] + [c for c in lru if c.is_host_cookie()]
        i = 0
        while used > PARTITION_MAX_BYTES or len(lru) - i > PARTITION_MAX_COOKIES:
            used -= lru[i].size()
            i += 1
        gone = set(map(id, lru[:i]))
        bucket[:] = [c for c in bucket if id(c) not in gone]

    def clear_site_data(self, host, partition_key):
        """Clear-Site-Data: "cookies" from a top-level response on host: every unpartitioned
        cookie of the registrable domain goes, and the partitioned ones of the response's own
        partition; the same domain's cookies in other partitions stay."""
        key = registrable_domain(host)
        self.cookies.pop(key, None)
        self.partitioned.get(partition_key, {}).pop(key, None)

    # ---- reads --------------------------------------------------------------------------
    def _excluded(self, c, scheme, host, port, path, context, now, ignore_path=False):
        """IncludeForRequestURL: returns (excluded, scheme_mismatch)."""
        f = self.features
        excluded = False
        if c.secure and scheme != 'https':
            excluded = True
        scheme_mismatch = c.source_secure != (scheme == 'https')
        if f.scheme_bound and scheme_mismatch:
            excluded = True
        if f.port_bound and c.is_host_cookie() and c.source_port != port:
            excluded = True
        if not domain_match(c.domain, host):
            excluded = True
        if not ignore_path and not path_match(c.path, path):
            excluded = True
        ss = c.samesite
        if ss == 'strict' and context < SAME_SITE_STRICT:
            excluded = True
        elif ss == 'lax' and context < SAME_SITE_LAX:
            excluded = True
        elif ss == 'unspecified':
            max_age = f.lax_unsafe_max_age
            recent = max_age is not None and now - c.creation <= max_age
            if context < (LAX_METHOD_UNSAFE if recent else SAME_SITE_LAX):
                excluded = True
        elif ss == 'none' and not c.secure:
            excluded = True
        return excluded, scheme_mismatch

    def cookies_for_request(self, scheme, host, path, context, partition_key, now, port=None):
        """GetCookieListWithOptions + FilterCookiesWithOptions; returns the ordered list."""
        if port is None:
            port = 443 if scheme == 'https' else 80
        key = registrable_domain(host)
        candidates = []
        for bucket in [self.cookies.get(key)] + (
                [self.partitioned.get(partition_key, {}).get(key)] if partition_key else []):
            if not bucket:
                continue
            live = [c for c in bucket if not c.expired(now)]
            if len(live) != len(bucket):
                bucket[:] = live
            candidates.extend(bucket)
        shadowing = set()
        if self.features.scheme_bound:
            # Host cookies that would be sent (path aside, and bound to this exact port) hide
            # same-named domain cookies.
            for c in candidates:
                if not c.is_host_cookie() or c.source_port != port:
                    continue
                if not self._excluded(c, scheme, host, port, path, context, now, ignore_path=True)[0]:
                    shadowing.add(c.name)
        included = []
        for c in candidates:
            excluded, scheme_mismatch = self._excluded(c, scheme, host, port, path, context, now)
            if not c.is_host_cookie() and not scheme_mismatch and c.name in shadowing:
                excluded = True
            if not excluded:
                included.append(c)
        for c in included:
            if now - c.last_access >= ACCESS_UPDATE_THRESHOLD:
                c.last_access = now
        included.sort(key=lambda c: (-len(c.path), c.creation))
        return included


def cookie_line(cookies):
    if not cookies:
        return None
    return '; '.join(f'{c.name}={c.value}' if c.name else c.value for c in cookies)
