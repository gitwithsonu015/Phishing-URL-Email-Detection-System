const http = require('http');

function postData(url, data) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const postData = JSON.stringify(data);
    
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || 3000,
      path: urlObj.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': postData.length
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch(e) {
          resolve(data);
        }
      });
    });

    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

async function test() {
  console.log('Testing URL Analysis API...');
  const result = await postData('http://localhost:3000/api/analyze/url', {
    url: 'http://phishing-test.com/login'
  });
  console.log(JSON.stringify(result, null, 2));
  
  console.log('\nTesting Stats API...');
  const stats = await new Promise((resolve, reject) => {
    http.get('http://localhost:3000/api/stats', (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve(JSON.parse(data)));
    }).on('error', reject);
  });
  console.log(JSON.stringify(stats, null, 2));
}

test().catch(console.error);
