const express = require('express');
const router = express.Router();
const { analyze } = require('./analyzer');
const { threatOps, statsOps } = require('./database');

// Health check
router.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Analyze URL
router.post('/api/analyze/url', async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    const result = await analyze('url', url);

    // Save to database
    const savedThreat = threatOps.insert({
      type: 'url',
      content: url,
      threat_level: result.threat_level,
      risk_score: result.risk_score,
      analysis_data: JSON.stringify(result)
    });

    result.id = savedThreat.lastInsertRowid;
    result.saved = true;

    res.json(result);
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ error: 'Analysis failed' });
  }
});

// Analyze Email
router.post('/api/analyze/email', async (req, res) => {
  try {
    const { sender, body, subject } = req.body;
    
    if (!sender && !body) {
      return res.status(400).json({ error: 'Email sender or body is required' });
    }

    const emailData = { sender, body, subject };
    const result = await analyze('email', emailData);

    // Save to database
    const content = sender + (body ? ' | ' + body.substring(0, 100) : '');
    const savedThreat = threatOps.insert({
      type: 'email',
      content: content,
      threat_level: result.threat_level,
      risk_score: result.risk_score,
      analysis_data: JSON.stringify(result)
    });

    result.id = savedThreat.lastInsertRowid;
    result.saved = true;

    res.json(result);
  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ error: 'Analysis failed' });
  }
});

// Get threats (paginated)
router.get('/api/threats', (req, res) => {
  try {
    const { page = 1, limit = 20, type, threat_level, search } = req.query;
    const offset = (page - 1) * limit;
    
    const threats = threatOps.getAll(parseInt(limit), offset, {
      type,
      threat_level,
      search
    });

    const total = threatOps.count({ type, threat_level });

    res.json({
      threats,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get threats error:', error);
    res.status(500).json({ error: 'Failed to fetch threats' });
  }
});

// Get single threat
router.get('/api/threats/:id', (req, res) => {
  try {
    const threat = threatOps.getById(req.params.id);
    
    if (!threat) {
      return res.status(404).json({ error: 'Threat not found' });
    }

    res.json(threat);
  } catch (error) {
    console.error('Get threat error:', error);
    res.status(500).json({ error: 'Failed to fetch threat' });
  }
});

// Get statistics
router.get('/api/stats', (req, res) => {
  try {
    const today = statsOps.getToday();
    const weekly = statsOps.getWeekly();
    const total = statsOps.getTotal();

    res.json({
      today,
      weekly,
      total
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

module.exports = router;
