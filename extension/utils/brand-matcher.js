/**
 * SafeBrowse X - Fast Client-side Brand and Typosquatting Matcher
 */

const PROTECTED_BRANDS = {
  paypal: ['paypal.com', 'paypal.me'],
  google: ['google.com', 'google.co.uk', 'google.ca'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'],
  apple: ['apple.com', 'icloud.com'],
  amazon: ['amazon.com', 'amazon.co.uk'],
  netflix: ['netflix.com'],
  meta: ['facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com'],
  chase: ['chase.com'],
  wellsfargo: ['wellsfargo.com'],
  binance: ['binance.com'],
  coinbase: ['coinbase.com'],
};

const HOMOGLYPHS = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a',
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x'
};

export function checkBrandSpoofLocal(domain) {
  if (!domain) return { isSpoofed: false };

  const clean = domain.toLowerCase().trim();
  
  // Check if official domain
  for (const [brand, legits] of Object.entries(PROTECTED_BRANDS)) {
    if (legits.includes(clean)) {
      return { isSpoofed: false, isOfficial: true, brand };
    }
  }

  // Normalize homoglyphs
  let normalized = '';
  for (const ch of clean) {
    normalized += HOMOGLYPHS[ch] || ch;
  }

  const rootLabel = clean.split('.')[0];
  const normLabel = normalized.split('.')[0];

  for (const [brand, legits] of Object.entries(PROTECTED_BRANDS)) {
    // Check if brand or homoglyph is present in an unauthorized domain
    if (normLabel.includes(brand) && !legits.includes(clean)) {
      return {
        isSpoofed: true,
        matchedBrand: brand,
        confidence: 95,
        reason: `Domain resembles or impersonates protected brand '${brand}'`
      };
    }
  }

  return { isSpoofed: false };
}
