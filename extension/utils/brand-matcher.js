/**
 * SafeBrowse X - Fast Client-side Brand and Typosquatting Matcher
 */

const PROTECTED_BRANDS = {
  paypal: ['paypal.com', 'paypal.me', 'paypal-communication.com', 'paypalobjects.com'],
  google: [
    'google.com', 'google.co.uk', 'google.ca', 'google.com.bd', 'google.de',
    'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'youtube.com', 'gmail.com'
  ],
  microsoft: [
    'microsoft.com', 'microsoftonline.com', 'live.com', 'office.com',
    'office365.com', 'outlook.com', 'msn.com', 'azure.com', 'windows.net',
    'visualstudio.com', 'bing.com', 'microsoftedge.com', 'partner.microsoft.com',
    'sharepoint.com', 'microsoft365.com', 'skype.com', 'xbox.com'
  ],
  apple: ['apple.com', 'icloud.com', 'mzstatic.com', 'appleid.apple.com'],
  amazon: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com', 'amazonaws.com'],
  netflix: ['netflix.com', 'nflxvideo.net'],
  meta: ['facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com', 'fbcdn.net', 'messenger.com'],
  chase: ['chase.com', 'jpmorgan.com'],
  wellsfargo: ['wellsfargo.com'],
  binance: ['binance.com', 'binance.org'],
  coinbase: ['coinbase.com'],
  github: ['github.com', 'github.io', 'githubusercontent.com', 'github.dev'],
};

const HOMOGLYPHS = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a',
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x'
};

export function checkBrandSpoofLocal(domain) {
  if (!domain) return { isSpoofed: false };

  const clean = domain.toLowerCase().trim();
  
  // Check if official domain or subdomain of official domain
  for (const [brand, legits] of Object.entries(PROTECTED_BRANDS)) {
    for (const legit of legits) {
      if (clean === legit || clean.endsWith('.' + legit)) {
        return { isSpoofed: false, isOfficial: true, brand };
      }
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
    if (normLabel.includes(brand)) {
      const isLegit = legits.some(l => clean === l || clean.endsWith('.' + l));
      if (!isLegit) {
        return {
          isSpoofed: true,
          matchedBrand: brand,
          confidence: 95,
          reason: `Domain resembles or impersonates protected brand '${brand}'`
        };
      }
    }
  }

  return { isSpoofed: false };
}
