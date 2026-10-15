/* Alderbay tag manager 4.2 - loaded on storefront pages after the load event. */
(function () {
  var cfg = window.tmConfig;
  var ls = window.localStorage;
  var now = Date.now();
  var https = location.protocol === 'https:';
  var written = [];

  function fnv(s) {
    var h = 0x811c9dc5;
    for (var i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h;
  }

  function put(name, value, maxAge, extra) {
    var c = name + '=' + value + '; Max-Age=' + maxAge + '; Domain=alderbay.com; Path=/' + (extra || '');
    document.cookie = c;
    written.push(c);
  }

  // visitor id
  var uid = ls.getItem('mf_uid');
  if (!uid) {
    uid = fnv(location.origin + '|' + navigator.userAgent).toString(36);
    ls.setItem('mf_uid', uid);
    put('_mf_uid', uid, 34560000, https ? '; Secure' : '');
  }

  // session: a new one after 30 minutes without a page view
  var ses = JSON.parse(ls.getItem('mf_ses') || 'null');
  if (!ses || now - ses.last > 1800000) {
    var count = (ses ? ses.count : 0) + 1;
    ses = { id: fnv(uid + '|' + count).toString(36), count: count, pages: 0 };
  }
  ses.pages += 1;
  ses.last = now;
  ls.setItem('mf_ses', JSON.stringify(ses));
  put('_mf_ses', ses.id + '.' + ses.pages, 1800);
  put('consent', 'v3.all', 15552000);

  // experiments on product pages
  var m = location.hostname === 'shop.alderbay.com' && location.pathname.match(/^\/p\/([a-z0-9]+)$/);
  if (m) {
    var sku = m[1];
    var tiles = cfg.related[sku] || [];
    for (var i = 0; i < tiles.length; i++) {
      put('_xt_' + tiles[i], 'abc'.charAt(fnv(uid + '|' + tiles[i]) % 3), 7776000);
    }
    var seen = JSON.parse(ls.getItem('mf_exp') || '[]');
    for (var j = 0; j < cfg.campaigns.length; j++) {
      var k = cfg.campaigns[j];
      if (k.category === cfg.category[sku] && now >= k.start && now < k.end && seen.indexOf(k.code) < 0) {
        seen.push(k.code);
        put('_exp_' + k.code, 'ab'.charAt(fnv(uid + '|' + k.code) % 2), 7776000, '; Priority=Low');
      }
    }
    ls.setItem('mf_exp', JSON.stringify(seen));
  }

  // privacy page: drop identifying cookies
  if (location.pathname === '/privacy') {
    put('sid', '', 0);
    put('cart', '', 0);
  }

  window.tmWritten = written;
  window.tmDone = new Promise(function (resolve) {
    setTimeout(function () {
      fetch('https://www.alderbay.com/tm/audit', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'text/plain' },
        body: JSON.stringify({ page: location.href, cid: uid, ses: ses.id + '.' + ses.pages })
      }).then(resolve, resolve);
    }, 150);
  });
})();
