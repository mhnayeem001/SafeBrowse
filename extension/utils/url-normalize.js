/**
 * SafeBrowse X - Fast Client-side URL Normalizer
 */
export function normalizeURL(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { isValid: false, normalizedUrl: '', hostname: '', registeredDomain: '' };
  }

  let urlStr = rawUrl.trim();
  if (!urlStr.includes('://')) {
    urlStr = 'http://' + urlStr;
  }

  try {
    const parsed = new URL(urlStr);
    const scheme = parsed.protocol.replace(':', '').toLowerCase();
    
    // Ignore internal browser schemes
    if (['chrome', 'chrome-extension', 'about', 'edge', 'brave', 'devtools'].includes(scheme)) {
      return { isValid: false, isInternal: true, scheme };
    }

    let hostname = parsed.hostname.toLowerCase().replace(/\.+$/, '');
    const port = parsed.port;
    const pathname = parsed.pathname || '/';
    
    // Strip default ports
    let hostWithPort = hostname;
    if (port && !((scheme === 'http' && port === '80') || (scheme === 'https' && port === '443'))) {
      hostWithPort = `${hostname}:${port}`;
    }

    // Extract registered domain (handling 2-part TLDs)
    const parts = hostname.split('.');
    let registeredDomain = hostname;
    const twoPartTlds = ['co.uk', 'org.uk', 'gov.uk', 'com.au', 'net.au', 'co.jp', 'com.br', 'co.in'];

    if (parts.length > 2) {
      const lastTwo = parts.slice(-2).join('.');
      if (twoPartTlds.includes(lastTwo) && parts.length >= 3) {
        registeredDomain = parts.slice(-3).join('.');
      } else {
        registeredDomain = parts.slice(-2).join('.');
      }
    }

    // Sort query params for consistent cache keys
    const params = Array.from(parsed.searchParams.entries()).sort((a, b) => a[0].localeCompare(b[0]));
    const searchParams = new URLSearchParams();
    for (const [k, v] of params) {
      searchParams.append(k, v);
    }
    const queryString = searchParams.toString() ? `?${searchParams.toString()}` : '';

    const normalizedUrl = `${scheme}://${hostWithPort}${pathname}${queryString}`;

    return {
      isValid: true,
      originalUrl: rawUrl,
      normalizedUrl,
      scheme,
      hostname,
      registeredDomain,
      isPunycode: hostname.includes('xn--'),
      isIpHost: /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname),
    };
  } catch (e) {
    return { isValid: false, error: e.message };
  }
}
