// URL and Email Analysis Module
// Simulates real-time phishing detection with pattern matching

const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
  'bank', 'password', 'credential', 'suspend', 'restrict', 'unusual',
  'activity', 'limit', 'verify', 'authenticate', 'urgent', 'immediate',
  'click', 'link', 'reward', 'winner', 'prize', 'lottery', 'inheritance',
  'nigerian', 'prince', 'department', 'support', 'help', 'service',
  'amazon', 'paypal', 'apple', 'microsoft', 'google', 'netflix', 'facebook',
  'instagram', 'twitter', 'linkedin', 'dropbox', 'onedrive', 'icloud'
];

const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.work', '.click', '.link', '.online', '.site', '.website',
  '.space', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.rest'
];

const KNOWN_PHISHING_DOMAINS = [
  'secure-bank-login.com', 'paypal-verify.net', 'amazon-account-verify.com',
  'microsoft-security-update.com', 'google-drive-verify.com', 'apple-id-reset.com',
  'netflix-payment-update.com', 'facebook-security-alert.net'
];

// Levenshtein distance for typosquatting detection
function levenshteinDistance(str1, str2) {
  const m = str1.length;
  const n = str2.length;
  const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (str1[i - 1] === str2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

// Check for homograph attacks (lookalike characters)
function containsHomographs(url) {
  // Check for common Cyrillic lookalikes
  const lookalikes = ['а', 'с', 'е', 'о', 'р', 'х', 'у'];
  const latin = ['a', 'c', 'e', 'o', 'p', 'x', 'y'];
  let hasLookalike = false;
  
  for (let i = 0; i < lookalikes.length; i++) {
    if (url.includes(lookalikes[i]) && !url.includes(latin[i])) {
      hasLookalike = true;
      break;
    }
  }
  return hasLookalike;
}

// Check for URL shorteners
function isShortenedUrl(url) {
  const shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly'];
  return shorteners.some(s => url.includes(s));
}

// Analyze URL
function analyzeUrl(url) {
  const analysis = {
    url: url,
    risk_score: 0,
    threat_level: 'safe',
    checks: [],
    details: {}
  };

  try {
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch (e) {
      // Try adding protocol
      parsedUrl = new URL('http://' + url);
    }

    const hostname = parsedUrl.hostname.toLowerCase();
    const pathname = parsedUrl.pathname.toLowerCase();
    const fullUrl = hostname + pathname;

    // Check 1: Protocol security
    if (parsedUrl.protocol === 'http:') {
      analysis.risk_score += 15;
      analysis.checks.push({ name: 'Protocol', status: 'warning', message: 'Insecure HTTP connection' });
    } else {
      analysis.checks.push({ name: 'Protocol', status: 'pass', message: 'Secure HTTPS connection' });
    }

    // Check 2: Known phishing domains
    if (KNOWN_PHISHING_DOMAINS.some(d => hostname.includes(d))) {
      analysis.risk_score += 50;
      analysis.checks.push({ name: 'Blacklist', status: 'danger', message: 'Domain matches known phishing site' });
    } else {
      analysis.checks.push({ name: 'Blacklist', status: 'pass', message: 'Not in known phishing database' });
    }

    // Check 3: Suspicious TLD
    if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))) {
      analysis.risk_score += 20;
      analysis.checks.push({ name: 'TLD', status: 'warning', message: 'Suspicious top-level domain' });
    }

    // Check 4: Suspicious keywords
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => fullUrl.includes(kw));
    if (foundKeywords.length > 0) {
      analysis.risk_score += Math.min(foundKeywords.length * 10, 30);
      analysis.details.suspicious_keywords = foundKeywords;
      analysis.checks.push({ name: 'Keywords', status: 'warning', message: `Contains suspicious keywords: ${foundKeywords.slice(0, 3).join(', ')}` });
    }

    // Check 5: Typosquatting detection (simulated)
    const legitimateDomains = ['google.com', 'facebook.com', 'amazon.com', 'paypal.com', 'microsoft.com', 'apple.com', 'netflix.com'];
    for (const legit of legitimateDomains) {
      const distance = levenshteinDistance(hostname, legit);
      if (distance > 0 && distance <= 3 && !hostname.includes(legit)) {
        analysis.risk_score += 35;
        analysis.details.typosquatting_target = legit;
        analysis.checks.push({ name: 'Typosquatting', status: 'danger', message: `Similar to legitimate domain: ${legit}` });
        break;
      }
    }

    // Check 6: Homograph attack
    if (containsHomographs(url)) {
      analysis.risk_score += 40;
      analysis.checks.push({ name: 'Homograph', status: 'danger', message: 'Contains lookalike characters (possible IDN attack)' });
    }

    // Check 7: URL shortener
    if (isShortenedUrl(url)) {
      analysis.risk_score += 15;
      analysis.details.is_shortened = true;
      analysis.checks.push({ name: 'Shortener', status: 'warning', message: 'Uses URL shortener - destination hidden' });
    }

    // Check 8: Excessive subdomains
    const subdomains = hostname.split('.').length - 1;
    if (subdomains > 3) {
      analysis.risk_score += 10;
      analysis.checks.push({ name: 'Subdomains', status: 'warning', message: 'Excessive subdomains' });
    }

    // Check 9: IP address as hostname
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(hostname)) {
      analysis.risk_score += 20;
      analysis.checks.push({ name: 'IP Address', status: 'warning', message: 'Hostname is an IP address' });
    }

    // Check 10: Suspicious patterns
    const suspiciousPatterns = [
      /\@/g, // @ symbol in URL (credential stuffing)
      /\/redirect\//i,
      /\/click\//i,
      /\?.*=/, // Query parameters
      /#.*/, // Fragments
    ];

    suspiciousPatterns.forEach(pattern => {
      if (pattern.test(url)) {
        analysis.risk_score += 5;
        if (!analysis.details.suspicious_patterns) {
          analysis.details.suspicious_patterns = [];
        }
        analysis.details.suspicious_patterns.push(pattern.toString());
      }
    });

    // Determine threat level
    if (analysis.risk_score >= 70) {
      analysis.threat_level = 'dangerous';
    } else if (analysis.risk_score >= 40) {
      analysis.threat_level = 'suspicious';
    } else {
      analysis.threat_level = 'safe';
    }

  } catch (error) {
    analysis.risk_score = 50;
    analysis.threat_level = 'suspicious';
    analysis.checks.push({ name: 'Parse', status: 'error', message: 'Unable to parse URL properly' });
  }

  return analysis;
}

// Analyze Email
function analyzeEmail(emailData) {
  const analysis = {
    email: emailData,
    risk_score: 0,
    threat_level: 'safe',
    checks: [],
    details: {}
  };

  try {
    // Extract sender from email data
    let sender = emailData;
    if (typeof emailData === 'object' && emailData.sender) {
      sender = emailData.sender;
    }

    // Extract email address
    const emailMatch = sender.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    const senderEmail = emailMatch ? emailMatch[1] : sender;
    const senderDomain = senderEmail.split('@')[1]?.toLowerCase() || '';

    analysis.details.sender_email = senderEmail;
    analysis.details.sender_domain = senderDomain;

    // Check 1: Suspicious domain
    if (SUSPICIOUS_TLDS.some(tld => senderDomain.endsWith(tld))) {
      analysis.risk_score += 25;
      analysis.checks.push({ name: 'Domain TLD', status: 'warning', message: 'Suspicious email domain' });
    }

    // Check 2: Lookalike domains (typosquatting)
    const legitimateDomains = ['google.com', 'facebook.com', 'amazon.com', 'paypal.com', 'microsoft.com', 'apple.com', 'netflix.com', 'linkedin.com', 'dropbox.com'];
    for (const legit of legitimateDomains) {
      const domainPart = senderDomain.split('.')[0];
      const legitPart = legit.split('.')[0];
      if (domainPart !== legitPart) {
        const distance = levenshteinDistance(domainPart, legitPart);
        if (distance > 0 && distance <= 2) {
          analysis.risk_score += 40;
          analysis.details.domain_impersonation = legit;
          analysis.checks.push({ name: 'Domain Spoofing', status: 'danger', message: `Impersonates legitimate domain: ${legit}` });
          break;
        }
      }
    }

    // Check 3: Number substitution (a→0, l→1, etc.)
    const numberSubstituted = /[0-9]/.test(senderDomain) && /[a-z]/.test(senderDomain.replace(/[0-9]/g, ''));
    if (numberSubstituted) {
      analysis.risk_score += 30;
      analysis.checks.push({ name: 'Character Swap', status: 'danger', message: 'Contains numbers instead of letters' });
    }

    // Check 4: Hidden characters
    if (/[\u200b-\u200d\ufeff]/.test(sender)) {
      analysis.risk_score += 25;
      analysis.checks.push({ name: 'Hidden Characters', status: 'danger', message: 'Contains hidden/zero-width characters' });
    }

    // Check 5: Urgency keywords (if body is provided)
    if (typeof emailData === 'object' && emailData.body) {
      const urgencyKeywords = ['urgent', 'immediately', 'suspend', 'limit', 'restrict', 'verify', '24 hours', 'expire', 'action required'];
      const foundUrgency = urgencyKeywords.filter(kw => emailData.body.toLowerCase().includes(kw));
      
      if (foundUrgency.length > 0) {
        analysis.risk_score += 15;
        analysis.details.urgency_keywords = foundUrgency;
        analysis.checks.push({ name: 'Urgency', status: 'warning', message: 'Contains urgency-inducing language' });
      }

      // Check for suspicious links in body
      const linkMatches = emailData.body.match(/https?:\/\/[^\s]+/g) || [];
      if (linkMatches.length > 0) {
        const suspiciousLinks = linkMatches.filter(link => {
          const analysis = analyzeUrl(link);
          return analysis.threat_level !== 'safe';
        });
        
        if (suspiciousLinks.length > 0) {
          analysis.risk_score += 30;
          analysis.details.suspicious_links = suspiciousLinks;
          analysis.checks.push({ name: 'Links', status: 'danger', message: `${suspiciousLinks.length} suspicious links found in email body` });
        }
      }
    }

    // Check 6: Free email providers (less suspicious but worth noting)
    const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
    if (freeProviders.includes(senderDomain)) {
      analysis.checks.push({ name: 'Provider', status: 'info', message: 'Uses free email provider' });
    }

    // Determine threat level
    if (analysis.risk_score >= 70) {
      analysis.threat_level = 'dangerous';
    } else if (analysis.risk_score >= 40) {
      analysis.threat_level = 'suspicious';
    } else {
      analysis.threat_level = 'safe';
    }

  } catch (error) {
    analysis.risk_score = 20;
    analysis.threat_level = 'suspicious';
    analysis.checks.push({ name: 'Parse', status: 'error', message: 'Unable to analyze email properly' });
  }

  return analysis;
}

// Simulate async analysis delay
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Main analysis function
async function analyze(type, content) {
  // Simulate processing time
  await delay(500 + Math.random() * 1000);

  if (type === 'url') {
    return analyzeUrl(content);
  } else if (type === 'email') {
    return analyzeEmail(content);
  }

  throw new Error('Unknown analysis type');
}

module.exports = {
  analyze,
  analyzeUrl,
  analyzeEmail
};
