# Phishing URL & Email Detection System - Specification

## 1. Project Overview

**Project Name:** CyberShield - Phishing Detection System  
**Project Type:** Full-stack Web Application  
**Core Functionality:** Real-time phishing URL and email detection with instant user warnings and threat database management  
**Target Users:** General internet users, security-conscious individuals, small businesses

---

## 2. UI/UX Specification

### Layout Structure

**Page Sections:**
- **Header**: Logo, navigation, dark mode toggle
- **Hero Section**: Main detection interface with input forms
- **Results Section**: Analysis results with threat level indicators
- **Threat Database Section**: View known threats with filtering
- **Stats Dashboard**: Real-time statistics and charts
- **Footer**: Links, copyright, security tips

**Grid/Layout:**
- Single-page application with smooth scroll navigation
- CSS Grid for dashboard layouts
- Flexbox for component alignment
- Max-width container: 1400px

**Responsive Breakpoints:**
- Mobile: < 768px (single column, stacked elements)
- Tablet: 768px - 1024px (2-column grid)
- Desktop: > 1024px (full layout with sidebar)

### Visual Design

**Color Palette:**
- Primary Background: #0a0e17 (Deep space black)
- Secondary Background: #111827 (Dark slate)
- Card Background: #1a2332 (Navy dark)
- Primary Accent: #00ff88 (Cyber green - safe)
- Danger Accent: #ff3366 (Phishing red)
- Warning Accent: #ffaa00 (Suspicious amber)
- Info Accent: #00d4ff (Cyan blue)
- Text Primary: #e8f0ff (Ice white)
- Text Secondary: #8892a6 (Muted gray)
- Gradient Primary: linear-gradient(135deg, #00ff88 0%, #00d4ff 100%)
- Gradient Danger: linear-gradient(135deg, #ff3366 0%, #ff6b35 100%)

**Typography:**
- Headings: 'Orbitron', sans-serif (futuristic tech feel)
- Body: 'Rajdhani', sans-serif (clean, modern)
- Monospace: 'JetBrains Mono', monospace (for URLs/code)
- H1: 48px, weight 700
- H2: 32px, weight 600
- H3: 24px, weight 600
- Body: 16px, weight 400
- Small: 14px, weight 400

**Spacing System:**
- Base unit: 8px
- xs: 4px, sm: 8px, md: 16px, lg: 24px, xl: 32px, xxl: 48px

**Visual Effects:**
- Card shadows: 0 8px 32px rgba(0, 212, 255, 0.1)
- Glow effects on interactive elements
- Animated gradient borders on focus
- Particle background animation
- Scan line overlay effect
- Pulse animation on threat indicators

### Components

**1. Navigation Bar**
- Fixed position, glassmorphism effect
- Logo with glow animation
- Nav links with hover underline animation
- States: default, hover (glow), active

**2. URL Input Form**
- Large input field with animated border
- "Analyze" button with gradient background
- Loading state with pulsing animation
- States: default, focus (gradient border), loading, error

**3. Email Input Form**
- Multi-field input for email headers
- Paste functionality
- Analysis button
- States: default, focus, analyzing, complete

**4. Result Card**
- Threat level indicator (color-coded bar)
- Detailed breakdown sections
- Risk score gauge (animated arc)
- Recommendation badges
- States: safe (green), suspicious (amber), dangerous (red)

**5. Threat Database Table**
- Sortable columns
- Search/filter functionality
- Pagination
- Row hover effect with glow
- Expandable row details

**6. Statistics Cards**
- Animated counters
- Trend indicators
- Mini sparkline charts
- Glassmorphism background

**7. Alert/Warning Modal**
- Slide-in animation
- Color-coded severity
- Action buttons
- Close button

---

## 3. Functionality Specification

### Core Features

**1. URL Analysis**
- Input: Single URL or batch URLs
- Analysis checks:
  - Domain age and reputation
  - SSL certificate validation
  - URL pattern analysis (typosquatting, homograph attacks)
  - Suspicious keywords detection
  - Redirect chain analysis
  - Known phishing database lookup
- Output: Risk score (0-100), threat level, detailed report

**2. Email Analysis**
- Input: Email headers, sender address, body content
- Analysis checks:
  - Sender domain verification
  - SPF/DKIM/DMARC record check
  - Suspicious link detection in body
  - Social engineering pattern recognition
  - Attachment analysis (metadata)
- Output: Threat classification, detailed findings

**3. Real-time Detection**
- Instant analysis on input
- Progress indicator during analysis
- Results displayed within 2 seconds
- Auto-save to history

**4. User Warning System**
- Visual threat indicators
- Detailed warning messages
- Recommended actions
- "Report False Positive" option

**5. Threat Database**
- Store analyzed URLs/emails
- Categories: Phishing, Malware, Spam, Safe
- Timestamp tracking
- Source attribution
- Export functionality

**6. Statistics Dashboard**
- Total URLs analyzed
- Threats detected (last 24h, 7d, 30d)
- Most common threat types
- Detection rate trends

### User Interactions and Flows

**Primary Flow:**
1. User enters URL/email
2. Click "Analyze" or press Enter
3. System shows loading animation
4. Results displayed with threat level
5. Option to save or share results

**Secondary Flows:**
- Browse threat database
- View statistics
- Filter/search threats
- Export reports

### Data Handling

**Database Schema (SQLite):**

```
sql
-- Threats table
CREATE TABLE threats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL, -- 'url' or 'email'
  content TEXT NOT NULL,
  threat_level TEXT NOT NULL, -- 'safe', 'suspicious', 'dangerous'
  risk_score INTEGER NOT NULL,
  analysis_data TEXT, -- JSON blob
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Analysis history
CREATE TABLE analysis_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  threat_id INTEGER,
  user_id TEXT,
  analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (threat_id) REFERENCES threats(id)
);

-- Statistics cache
CREATE TABLE stats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  date DATE NOT NULL,
  total_analyzed INTEGER DEFAULT 0,
  threats_detected INTEGER DEFAULT 0,
  safe_results INTEGER DEFAULT 0
);
```

### Edge Cases
- Invalid URL format → Show validation error
- Empty input → Disable analyze button
- Network timeout → Show retry option
- Very long URLs → Truncate display, full in details
- Database connection failure → Show offline mode

---

## 4. Technical Architecture

### Stack
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Backend**: Node.js with Express
- **Database**: SQLite with better-sqlite3
- **APIs**: RESTful JSON API

### Project Structure
```
Phishing URL & Email Detection/
├── public/
│   ├── index.html
│   ├── css/
│   │   └── styles.css
│   └── js/
│       └── app.js
├── server/
│   ├── index.js
│   ├── database.js
│   ├── analyzer.js
│   └── routes.js
├── data/
│   └── threats.db
├── package.json
└── SPEC.md
```

---

## 5. Acceptance Criteria

### Visual Checkpoints
- [ ] Dark theme with cyber-security aesthetic loads correctly
- [ ] All colors match specified hex codes
- [ ] Fonts load correctly (Orbitron, Rajdhani)
- [ ] Animations are smooth (60fps)
- [ ] Responsive layout works on all breakpoints
- [ ] Glow effects visible on interactive elements

### Functional Checkpoints
- [ ] URL input accepts valid URLs
- [ ] Analysis returns result within 3 seconds
- [ ] Results display correct threat level
- [ ] Database stores analysis results
- [ ] Threat database displays with filtering
- [ ] Statistics update correctly
- [ ] All API endpoints respond correctly

### Performance Checkpoints
- [ ] Page loads under 2 seconds
- [ ] Analysis completes under 3 seconds
- [ ] Database queries respond under 100ms
- [ ] Smooth scrolling and animations

---

## 6. API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/analyze/url | Analyze a URL |
| POST | /api/analyze/email | Analyze email content |
| GET | /api/threats | Get threat database |
| GET | /api/stats | Get statistics |
| GET | /api/health | Health check |
