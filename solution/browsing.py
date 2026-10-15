"""Request contexts for cookie access. The proxy log shows requests, not documents, so the frame
tree of each tab is rebuilt from Fetch Metadata, Referer and Origin, and from it come the three
inputs of Chromium's cookie_util::ComputeSameSiteContext and CHIPS: the site for cookies, the
initiator and the partition key."""
import re
from urllib.parse import urlsplit
from cookiestore import (schemeful_site, CROSS_SITE, LAX_METHOD_UNSAFE, SAME_SITE_LAX,
                         SAME_SITE_STRICT)

OPAQUE = 'null'    # initiator with an opaque origin (a sandboxed document)
# README: product pages show reviews in an iframe sandboxed without allow-same-origin.
REVIEWS_FRAME = re.compile(r'^https://www\.alderbay\.com/ugc/')


def url_site(url):
    u = urlsplit(url)
    return schemeful_site(u.scheme, u.hostname)


def url_origin(url):
    u = urlsplit(url)
    return f'{u.scheme}://{u.netloc}'


def url_port(url):
    u = urlsplit(url)
    return u.port or (443 if u.scheme == 'https' else 80)


class Doc:
    """A document in the tab: the top-level page or an iframe at any depth."""

    def __init__(self, url, parent=None, sandboxed=False):
        self.url, self.parent, self.sandboxed = url, parent, sandboxed

    @property
    def origin(self):
        return OPAQUE if self.sandboxed else url_origin(self.url)


class Request:
    """What the store needs to know about one request."""

    def __init__(self, kind, doc, initiator, chain):
        self.kind = kind            # 'main' | 'frame' | 'sub'
        self.doc = doc              # main: None; frame: the navigating frame; sub: the requesting document
        self.initiator = initiator  # origin string, OPAQUE, or None for a browser-initiated navigation
        self.chain = chain          # URLs of the earlier hops of this request's redirect chain


class Tab:
    """The frame tree of one tab, driven by the log."""

    def __init__(self):
        self.top = None
        self.frames = []            # iframes of the current page, oldest first
        self.pending = None         # (next URL, Request) while a redirect is being followed

    # ---- which document made this request -----------------------------------------------
    def _doc_for(self, referer, origin_header):
        """The document a Referer / Origin pair points at. Same-origin requests carry the full
        URL of the document; cross-origin ones only its origin."""
        docs = self.frames[::-1] + ([self.top] if self.top else [])
        if referer:
            for d in docs:
                if not d.sandboxed and d.url == referer:
                    return d
        origin = origin_header or (url_origin(referer) if referer else None)
        if self.top and origin == self.top.origin:
            return self.top
        for d in docs:
            if d.origin == origin:
                return d
        return self.top

    def _sandboxed_frame(self):
        for d in self.frames[::-1]:
            if d.sandboxed:
                return d
        return None

    def classify(self, r):
        h = r['request_headers']
        url = r['url']
        if self.pending and self.pending[0] == url:
            req = self.pending[1]
            return Request(req.kind, req.doc, req.initiator, req.chain + [req.url])
        dest, mode = h.get('Sec-Fetch-Dest'), h.get('Sec-Fetch-Mode')
        referer, origin = h.get('Referer'), h.get('Origin')
        if 'Sec-Fetch-Mode' not in h and h.get('Upgrade-Insecure-Requests') == '1':
            # Chromium only sends Fetch Metadata to secure origins; plain-http page loads are
            # recognisable by the navigation-only Upgrade-Insecure-Requests header.
            mode, dest = 'navigate', 'document'
        if mode == 'navigate' and dest == 'document':
            if h.get('Sec-Fetch-Site') == 'none' or ('Sec-Fetch-Site' not in h and not referer):
                initiator = None
            elif origin:
                initiator = origin
            elif referer:
                initiator = url_origin(referer)
            else:
                initiator = OPAQUE     # a sandboxed frame navigated the tab: no Referer, no Origin
            return Request('main', None, initiator, [])
        if mode == 'navigate' and dest == 'iframe':
            if not referer:            # the sandboxed frame navigated itself
                return Request('frame', self._sandboxed_frame() or self.frames[-1], OPAQUE, [])
            for d in self.frames[::-1]:
                if not d.sandboxed and d.url == referer:      # a frame navigated itself
                    return Request('frame', d, d.origin, [])
            parent = self._doc_for(referer, origin)
            child = Doc(url, parent, bool(REVIEWS_FRAME.match(url)))
            self.frames.append(child)
            return Request('frame', child, parent.origin, [])
        if not referer and (origin == OPAQUE or (not origin and h.get('Sec-Fetch-Site') == 'cross-site')):
            doc = self._sandboxed_frame() or self.top
        else:
            doc = self._doc_for(referer, None if origin == OPAQUE else origin)
        return Request('sub', doc, doc.origin if doc else None, [])

    def done(self, r, req):
        """Apply the response: commit navigations, remember a redirect that is being followed."""
        url = r['url']
        req.url = url
        loc = r['response_headers'].get('Location')
        redirected = bool(loc) and 300 <= r['status'] < 400
        if req.kind == 'main':
            self.top, self.frames = Doc(url), []
        elif req.kind == 'frame' and req.doc is not None:
            req.doc.url = url
        self.pending = (loc, req) if redirected else None

    # ---- cookie inputs ------------------------------------------------------------------
    def _first_party_site(self, doc):
        """Site for cookies of a document: the top-level site while the document and all its
        ancestors are same-site with the top-level page and none is sandboxed, otherwise null."""
        top_site = url_site(self.top.url)
        while doc is not None:
            if doc.sandboxed or url_site(doc.url) != top_site:
                return None
            doc = doc.parent
        return top_site

    def context(self, r, req, consider_chain):
        """Returns (get_context, set_context, partition_key) for request r."""
        url, method = r['url'], r['method']
        site = url_site(url)
        if req.kind == 'main':
            sfc, cross_ancestor, top_site = site, False, site
        else:
            top_site = url_site(self.top.url)
            holder = req.doc.parent if req.kind == 'frame' else req.doc
            sfc = self._first_party_site(holder)
            # A frame navigation is keyed by the document it will create, a subresource by the
            # document that asked for it.
            cross_ancestor = sfc is None or (req.kind == 'frame' and site != top_site)
        pk = (top_site[0], top_site[1], cross_ancestor)
        is_main = req.kind == 'main'
        set_main = SAME_SITE_LAX   # responses to top-level navigations may set any SameSite cookie
        if sfc is None or sfc != site:
            return CROSS_SITE, (set_main if is_main else CROSS_SITE), pk
        same_site_initiator = req.initiator is None or (
            req.initiator != OPAQUE and url_site(req.initiator) == site)
        chain_same_site = all(url_site(u) == sfc for u in req.chain)
        if same_site_initiator and (chain_same_site or not consider_chain):
            get = SAME_SITE_STRICT
        elif is_main:
            get = SAME_SITE_LAX
        else:
            get = CROSS_SITE
        set_ctx = set_main if is_main else min(get, SAME_SITE_LAX)
        if is_main and get == SAME_SITE_LAX and method not in ('GET', 'HEAD'):
            get = LAX_METHOD_UNSAFE
        return get, set_ctx, pk


def script_context(page_url):
    """(set_context, partition_key, source_is_secure) for document.cookie in a top-level page."""
    site = url_site(page_url)
    return SAME_SITE_LAX, (site[0], site[1], False), urlsplit(page_url).scheme == 'https'
