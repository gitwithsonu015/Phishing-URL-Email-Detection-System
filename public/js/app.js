// CyberShield - Phishing Detection System
// Frontend Application

const App = {
  currentTab: 'url',
  currentResult: null,
  dbPage: 1,
  
  init() {
    this.bindEvents();
    this.loadStats();
    this.loadThreats();
    this.animateCounters();
    setInterval(() => this.loadStats(), 30000);
    console.log('CyberShield initialized');
  },
  
  bindEvents() {
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => this.switchTab(btn.dataset.tab));
    });
    
    // URL analysis
    document.getElementById('analyzeUrlBtn').addEventListener('click', () => this.analyzeUrl());
    document.getElementById('urlInput').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.analyzeUrl();
    });
    
    // Quick link buttons
    document.querySelectorAll('.quick-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.getElementById('urlInput').value = btn.dataset.url;
        this.analyzeUrl();
      });
    });
    
    // Email analysis
    document.getElementById('analyzeEmailBtn').addEventListener('click', () => this.analyzeEmail());
    
    // Result actions
    document.getElementById('newAnalysisBtn').addEventListener('click', () => this.resetAnalysis());
    
    // Database filters
    document.getElementById('filterType').addEventListener('change', () => { 
      this.dbPage = 1; 
      this.loadThreats(); 
    });
    
    document.getElementById('filterThreat').addEventListener('change', () => { 
      this.dbPage = 1; 
      this.loadThreats(); 
    });
    
    document.getElementById('dbSearch').addEventListener('input', debounce(() => { 
      this.dbPage = 1; 
      this.loadThreats(); 
    }, 300));
    
    // Smooth scroll
    document.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const target = document.querySelector(link.getAttribute('href'));
        if (target) target.scrollIntoView({ behavior: 'smooth' });
      });
    });
    
    window.addEventListener('scroll', () => this.handleScroll());
  },
  
  handleScroll() {
    const navbar = document.getElementById('navbar');
    if (window.scrollY > 50) {
      navbar.style.background = 'rgba(10,14,23,0.95)';
    } else {
      navbar.style.background = 'rgba(10,14,23,0.85)';
    }
  },
  
  switchTab(tab) {
    this.currentTab = tab;
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === tab);
    });
    document.querySelectorAll('.analyzer-panel').forEach(panel => {
      panel.classList.toggle('active', panel.id === tab + '-panel');
    });
  },
  
  async analyzeUrl() {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) {
      this.showToast('Please enter a URL to analyze', 'error');
      return;
    }
    
    this.showLoading();
    
    try {
      const response = await fetch('/api/analyze/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      
      if (!response.ok) throw new Error('Analysis failed');
      const result = await response.json();
      this.displayResult(result);
      this.loadThreats();
      this.loadStats();
    } catch (error) {
      console.error('URL Analysis Error:', error);
      this.showToast('Failed to analyze URL', 'error');
    }
  },
  
  async analyzeEmail() {
    const sender = document.getElementById('senderInput').value.trim();
    if (!sender) {
      this.showToast('Please enter sender address', 'error');
      return;
    }
    
    const subject = document.getElementById('subjectInput').value.trim();
    const body = document.getElementById('emailBodyInput').value.trim();
    
    this.showLoading();
    
    try {
      const response = await fetch('/api/analyze/email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sender, subject, body })
      });
      
      if (!response.ok) throw new Error('Analysis failed');
      const result = await response.json();
      this.displayResult(result);
      this.loadThreats();
      this.loadStats();
    } catch (error) {
      console.error('Email Analysis Error:', error);
      this.showToast('Failed to analyze email', 'error');
    }
  },
  
  showLoading() {
    const container = document.getElementById('resultsContainer');
    container.innerHTML = `
      <div class="result-loading" id="resultLoading">
        <div class="loading-scanner">
          <div class="scanner-line"></div>
          <div class="scanner-ring"></div>
        </div>
        <p class="loading-text">Analyzing<span class="loading-dots"></span></p>
      </div>
    `;
  },
  
  displayResult(result) {
    if (!result) return;
    this.currentResult = result;
    
    const container = document.getElementById('resultsContainer');
    const level = result.threat_level;
    const levelText = level.charAt(0).toUpperCase() + level.slice(1);
    const levelIcon = level === 'safe' ? '✓' : level === 'suspicious' ? '!' : '✕';
    
    const checksHtml = result.checks.map(check => `
      <div class="check-item ${check.status}">
        <span class="check-name">${check.name}</span>
        <span class="check-message">${check.message}</span>
      </div>
    `).join('');
    
    let recommendation = '';
    if (level === 'safe') {
      recommendation = `
        <div class="recommendation-title">Safe to Proceed</div>
        <p class="recommendation-text">This URL appears to be legitimate. However, always exercise caution when sharing personal information online.</p>
      `;
    } else if (level === 'suspicious') {
      recommendation = `
        <div class="recommendation-title">Proceed with Caution</div>
        <p class="recommendation-text">This URL has some suspicious characteristics. Do not enter personal information. If possible, verify the URL through official channels.</p>
      `;
    } else {
      recommendation = `
        <div class="recommendation-title">High Risk Detected</div>
        <p class="recommendation-text">This URL shows strong indicators of being a phishing attempt. Do NOT visit this site or enter any personal information. Report this URL if encountered.</p>
      `;
    }
    
    container.innerHTML = `
      <div class="result-card" id="resultCard">
        <div class="result-header">
          <div class="threat-level ${level}">
            <span class="threat-icon">${levelIcon}</span>
            <span class="threat-label">${levelText}</span>
          </div>
          <div class="risk-score ${level}">
            <span class="score-value">${result.risk_score}</span>
            <span class="score-label">Risk Score</span>
          </div>
        </div>
        <div class="result-content">
          <div class="result-analyzed">
            <span class="analyzed-label">Analyzed:</span>
            <span class="analyzed-value">${result.url || result.email || result.details?.sender_email || 'Unknown'}</span>
          </div>
          <div class="analysis-checks">
            ${checksHtml}
          </div>
          <div class="result-recommendation ${level}">
            ${recommendation}
          </div>
        </div>
        <div class="result-actions">
          <button class="action-btn primary" id="newAnalysisBtn">
            <span>🔄</span> New Analysis
          </button>
        </div>
      </div>
    `;
    
    document.getElementById('newAnalysisBtn').addEventListener('click', () => this.resetAnalysis());
  },
  
  resetAnalysis() {
    document.getElementById('urlInput').value = '';
    document.getElementById('senderInput').value = '';
    document.getElementById('subjectInput').value = '';
    document.getElementById('emailBodyInput').value = '';
    document.getElementById('resultsContainer').innerHTML = '';
    this.currentResult = null;
  },
  
  async loadStats() {
    try {
      const response = await fetch('/api/stats');
      const data = await response.json();
      
      document.getElementById('totalAnalyzed').textContent = data.total.total_analyzed || 0;
      document.getElementById('threatsBlocked').textContent = data.total.threats_detected || 0;
      
      document.getElementById('todayTotal').textContent = data.today.total_analyzed || 0;
      document.getElementById('todayThreats').textContent = data.today.threats_detected || 0;
      document.getElementById('todaySafe').textContent = data.today.safe_results || 0;
      
      this.renderChart(data.weekly);
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  },
  
  renderChart(weeklyData) {
    const container = document.getElementById('trendChart');
    if (!container || !weeklyData || weeklyData.length === 0) return;
    
    const maxValue = Math.max(...weeklyData.map(d => d.total_analyzed), 1);
    const bars = weeklyData.map(d => {
      const height = (d.total_analyzed / maxValue) * 80 + 10;
      return `<div class="chart-bar" style="height: ${height}px" title="${d.date}: ${d.total_analyzed} analyzed"></div>`;
    }).join('');
    
    container.innerHTML = bars;
  },
  
  async loadThreats() {
    try {
      const type = document.getElementById('filterType').value;
      const threatLevel = document.getElementById('filterThreat').value;
      const search = document.getElementById('dbSearch').value;
      
      const params = new URLSearchParams({
        page: this.dbPage,
        limit: 10
      });
      
      if (type) params.append('type', type);
      if (threatLevel) params.append('threat_level', threatLevel);
      if (search) params.append('search', search);
      
      const response = await fetch('/api/threats?' + params);
      const data = await response.json();
      
      this.renderThreatTable(data.threats);
      this.renderPagination(data.pagination);
    } catch (error) {
      console.error('Failed to load threats:', error);
    }
  },
  
  renderThreatTable(threats) {
    const tbody = document.getElementById('threatTableBody');
    if (!tbody) return;
    
    if (threats.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 2rem;">No threats found</td></tr>';
      return;
    }
    
    tbody.innerHTML = threats.map(threat => {
      const date = new Date(threat.created_at).toLocaleDateString();
      const content = threat.content.length > 60 ? threat.content.substring(0, 60) + '...' : threat.content;
      
      return `
        <tr>
          <td><span class="type-badge ${threat.type}">${threat.type.toUpperCase()}</span></td>
          <td class="content-cell" title="${threat.content}">${content}</td>
          <td><span class="level-badge ${threat.threat_level}">${threat.threat_level}</span></td>
          <td class="score-cell">${threat.risk_score}</td>
          <td class="date-cell">${date}</td>
        </tr>
      `;
    }).join('');
  },
  
  renderPagination(pagination) {
    const container = document.getElementById('dbPagination');
    if (!container || pagination.pages <= 1) {
      if (container) container.innerHTML = '';
      return;
    }
    
    let html = '';
    
    if (pagination.page > 1) {
      html += `<button class="page-btn" onclick="App.goToPage(${pagination.page - 1})">Prev</button>`;
    }
    
    for (let i = 1; i <= pagination.pages; i++) {
      if (i === 1 || i === pagination.pages || (i >= pagination.page - 1 && i <= pagination.page + 1)) {
        html += `<button class="page-btn ${i === pagination.page ? 'active' : ''}" onclick="App.goToPage(${i})">${i}</button>`;
      } else if (i === pagination.page - 2 || i === pagination.page + 2) {
        html += `<span style="color: var(--text-muted)">...</span>`;
      }
    }
    
    if (pagination.page < pagination.pages) {
      html += `<button class="page-btn" onclick="App.goToPage(${pagination.page + 1})">Next</button>`;
    }
    
    container.innerHTML = html;
  },
  
  goToPage(page) {
    this.dbPage = page;
    this.loadThreats();
    document.getElementById('database').scrollIntoView({ behavior: 'smooth' });
  },
  
  animateCounters() {
    const counters = document.querySelectorAll('.stat-card-value, .hero-stat .stat-value');
    counters.forEach(counter => {
      const target = parseInt(counter.textContent) || 0;
      if (target > 0) {
        counter.textContent = '0';
        this.animateCounter(counter, target);
      }
    });
  },
  
  animateCounter(element, target) {
    let current = 0;
    const increment = target / 30;
    const timer = setInterval(() => {
      current += increment;
      if (current >= target) {
        element.textContent = target;
        clearInterval(timer);
      } else {
        element.textContent = Math.floor(current);
      }
    }, 50);
  },
  
  showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.className = 'toast ' + type;
    toast.querySelector('.toast-message').textContent = message;
    toast.classList.add('show');
    
    setTimeout(() => {
      toast.classList.remove('show');
    }, 3000);
  }
};

// Utility function
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
