const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'data', 'threats.db');
let db = null;

// Initialize database
async function initializeDatabase() {
  const SQL = await initSqlJs();
  
  // Load existing database or create new one
  if (fs.existsSync(dbPath)) {
    const fileBuffer = fs.readFileSync(dbPath);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  // Create tables
  db.run(`
    CREATE TABLE IF NOT EXISTS threats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      content TEXT NOT NULL,
      threat_level TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      analysis_data TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS stats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      date TEXT NOT NULL,
      total_analyzed INTEGER DEFAULT 0,
      threats_detected INTEGER DEFAULT 0,
      safe_results INTEGER DEFAULT 0,
      UNIQUE(date)
    )
  `);

  saveDatabase();
  console.log('Database initialized successfully (empty)');
}

function saveDatabase() {
  if (db) {
    const data = db.export();
    const buffer = Buffer.from(data);
    const dataDir = path.join(__dirname, '..', 'data');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    fs.writeFileSync(dbPath, buffer);
  }
}

// Database operations
const threatOps = {
  insert: (threat) => {
    db.run(
      `INSERT INTO threats (type, content, threat_level, risk_score, analysis_data) VALUES (?, ?, ?, ?, ?)`,
      [threat.type, threat.content, threat.threat_level, threat.risk_score, threat.analysis_data]
    );
    const result = db.exec('SELECT last_insert_rowid()');
    saveDatabase();
    return { lastInsertRowid: result[0].values[0][0] };
  },

  getAll: (limit = 100, offset = 0, filter = {}) => {
    let query = 'SELECT * FROM threats WHERE 1=1';
    const params = [];

    if (filter.type) {
      query += ' AND type = ?';
      params.push(filter.type);
    }
    if (filter.threat_level) {
      query += ' AND threat_level = ?';
      params.push(filter.threat_level);
    }
    if (filter.search) {
      query += ' AND content LIKE ?';
      params.push('%' + filter.search + '%');
    }

    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const result = db.exec(query, params);
    if (result.length === 0) return [];
    
    const columns = result[0].columns;
    return result[0].values.map(row => {
      const obj = {};
      columns.forEach((col, i) => obj[col] = row[i]);
      return obj;
    });
  },

  getById: (id) => {
    const result = db.exec('SELECT * FROM threats WHERE id = ?', [id]);
    if (result.length === 0 || result[0].values.length === 0) return null;
    
    const columns = result[0].columns;
    const row = result[0].values[0];
    const obj = {};
    columns.forEach((col, i) => obj[col] = row[i]);
    return obj;
  },

  count: (filter = {}) => {
    let query = 'SELECT COUNT(*) as count FROM threats WHERE 1=1';
    const params = [];

    if (filter.type) {
      query += ' AND type = ?';
      params.push(filter.type);
    }
    if (filter.threat_level) {
      query += ' AND threat_level = ?';
      params.push(filter.threat_level);
    }

    const result = db.exec(query, params);
    return result.length > 0 ? result[0].values[0][0] : 0;
  }
};

const statsOps = {
  getToday: () => {
    const today = new Date().toISOString().split('T')[0];
    const result = db.exec('SELECT * FROM stats WHERE date = ?', [today]);
    
    if (result.length === 0 || result[0].values.length === 0) {
      const totalResult = db.exec('SELECT COUNT(*) as count FROM threats');
      const total = totalResult.length > 0 ? totalResult[0].values[0][0] : 0;
      const threatsResult = db.exec("SELECT COUNT(*) as count FROM threats WHERE threat_level = 'dangerous' OR threat_level = 'suspicious'");
      const threats = threatsResult.length > 0 ? threatsResult[0].values[0][0] : 0;
      return { date: today, total_analyzed: total, threats_detected: threats, safe_results: total - threats };
    }
    
    const columns = result[0].columns;
    const row = result[0].values[0];
    const obj = {};
    columns.forEach((col, i) => obj[col] = row[i]);
    return obj;
  },

  getWeekly: () => {
    const result = db.exec(`
      SELECT * FROM stats 
      WHERE date >= date('now', '-7 days')
      ORDER BY date ASC
    `);
    
    if (result.length === 0) return [];
    
    const columns = result[0].columns;
    return result[0].values.map(row => {
      const obj = {};
      columns.forEach((col, i) => obj[col] = row[i]);
      return obj;
    });
  },

  getTotal: () => {
    const result = db.exec(`
      SELECT 
        COUNT(*) as total_analyzed,
        SUM(CASE WHEN threat_level = 'dangerous' OR threat_level = 'suspicious' THEN 1 ELSE 0 END) as threats_detected,
        SUM(CASE WHEN threat_level = 'safe' THEN 1 ELSE 0 END) as safe_results
      FROM threats
    `);
    
    if (result.length === 0) return { total_analyzed: 0, threats_detected: 0, safe_results: 0 };
    
    const columns = result[0].columns;
    const row = result[0].values[0];
    const obj = {};
    columns.forEach((col, i) => obj[col] = row[i]);
    return obj;
  }
};

module.exports = {
  initializeDatabase,
  threatOps,
  statsOps
};
