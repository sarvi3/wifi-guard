# Suspicious Website Detection Improvements

## Summary of Changes

Your WiFi Guard project now has enhanced suspicious website detection capabilities using local heuristics and Google Safe Browsing API integration.

## Key Improvements Made

### 1. **Direct IP Address Detection**
- Added detection for direct IP address access (e.g., `http://192.168.1.1`)
- Direct IP access without a domain name is now flagged as suspicious (score: 25/100)
- This helps detect potential attacks that try to bypass domain-based filtering

### 2. **Enhanced Google Safe Browsing Integration**
- Changed from "either-or" to "always-check" approach
- Now checks Google Safe Browsing API regardless of local analysis results
- Added fallback to check just the hostname when full URL is not available
- This ensures known malicious websites are always detected

### 3. **Local Heuristic Analysis**
The system analyzes websites using multiple suspicious pattern detection rules:

#### a. Suspicious TLD Detection
- Flags websites using commonly abused top-level domains: `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.top`, `.xyz`, `.cc`, `.pw`, `.biz`, `.info`, `.download`, `.racing`, `.science`, `.win`, `.trade`, `.accountants`, `.cricket`, `.fit`, `.date`, `.review`, `.tech`, `.online`, `.site`, `.work`, `.world`, `.zip`, `.mov`, `.mp4`, `.party`, `.fun`, `.club`, `.pro`, `.wang`, `.ren`, `.kim`, `.loan`, `.click`, `.country`, `.stream`, `.gdn`, `.icu`, `.cyou`
- Score: +20 points

#### b. Excessive Numeric Characters
- Detects hostnames with more than 40% numeric characters
- Score: +15 points
- Helps detect random-looking or generated domains

#### c. Excessive Hyphens
- Flags hostnames with more than 3 hyphens
- Score: +10 points
- Common in suspicious domains trying to appear legitimate

#### d. Brand Impersonation Detection
- Checks for popular brand names within hostnames (Google, Facebook, Amazon, Apple, Microsoft, Netflix, PayPal, eBay, Twitter, Instagram, LinkedIn, Yahoo, Outlook, Hotmail, Gmail, Chase, Wells, Citibank, HSBC)
- Only flags when brand name is contained but NOT the registrable domain (e.g., `google-security.com` is flagged, but `google.com` is NOT)
- Score: +25 points
- Helps detect phishing attempts while avoiding false positives on legitimate domains

#### e. Other Patterns
- Punycode (xn--) detection: +35 points
- User-info (@) syntax: +30 points
- Very long hostnames (>60 chars): +15 points
- Many subdomains (5+): +15 points
- Suspicious keywords (login, verify, account, etc.): +5-20 points
- Very long URLs (>180 chars): +15 points
- Large query strings (>100 chars): +10 points
- Heavy percent-encoding (8+): +15 points
- Suspicious path keywords: +5-15 points

### 4. **No Hardcoded Test Domains**
- Removed all hardcoded "demo" or "test" domain lists
- Detection relies entirely on real analysis methods:
  - Local heuristic analysis
  - Google Safe Browsing API
  - Actual suspicious characteristics
- This ensures the system detects genuine threats, not pre-defined test sites

## How It Works

When you visit a website, the system now:

1. **Captures the website** from network traffic (DNS requests, TLS SNI, HTTP headers)
2. **Performs local analysis** checking for suspicious patterns
3. **Checks Google Safe Browsing API** for known malicious websites
4. **Calculates a risk score** (0-100) based on all detected patterns
5. **Creates a threat event** if the score exceeds 20 or Google flags it
6. **Alerts you** in the frontend with detailed reasons

## Important Limitations

### HTTPS Path Visibility
- **Passive packet capture cannot see HTTPS URL paths** (e.g., `/malware.html`)
- Google Safe Browsing can flag specific full URLs (like `example.com/malware.html`)
- But packet capture typically only sees the domain name (like `example.com`)
- Therefore, path-specific Safe Browsing detection is limited with passive monitoring
- Google Safe Browsing is most effective for domain-level reputation

### Testing Recommendations
Instead of relying on Google/AMTSO test pages (which may not trigger detection):
- Test with sites having suspicious TLDs (.tk, .ml, .ga, etc.)
- Test with direct IP access
- Test with sites exhibiting suspicious characteristics (many numbers, hyphens, etc.)
- Test with legitimate brand impersonation attempts

## Detection Thresholds

- **Score 0-19**: Safe - No alert
- **Score 20-79**: Warning - Yellow alert
- **Score 80-100**: Critical - Red alert
- **Google Safe Browsing**: Always triggers critical alert (score 100)

## Real-Time Detection

The system detects websites in real-time as you visit them:
- DNS requests are captured and analyzed
- TLS SNI (Server Name Indication) is extracted from HTTPS connections
- HTTP headers are examined for full URLs (HTTP only)
- Results appear immediately in your threat events

## Configuration

The detection sensitivity can be adjusted by modifying:
- Threshold scores in the `analyze_website()` function (currently 20)
- The suspicious keyword lists
- The suspicious TLD list
- The brand list for impersonation detection

## API Endpoints

- `POST /start-monitoring` - Start monitoring network traffic
- `GET /threat-events` - Get detected threat events (suspicious websites)
- `GET /threat-status` - Get current threat status and score
- `POST /block-website` - Block a detected suspicious website
- `POST /unblock-website` - Unblock a website

## Notes

- Google Safe Browsing API requires a valid API key in your `.env` file
- The system caches results to avoid repeated API calls
- Detection works for both HTTP and HTTPS traffic
- Windows Firewall rules are used to block malicious websites when requested
- HTTPS path detection is limited by passive packet capture architecture