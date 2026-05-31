import dotenv from 'dotenv';
import fetch from 'node-fetch';

dotenv.config();

const {
  VITE_SHODAN_API_KEY,
  VITE_CENSYS_API_ID,
  VITE_CENSYS_API_SECRET,
  VITE_GREYHAT_API_KEY
} = process.env;

async function testShodan() {
  console.log('Testing Shodan...');
  // Corrected endpoint: /api-info requires the key as a query param
  const url = `https://api.shodan.io/api-info?key=${VITE_SHODAN_API_KEY}`;
  try {
    const res = await fetch(url);
    const text = await res.text();
    console.log('Shodan Status:', res.status);
    try {
      const data = JSON.parse(text);
      console.log('Shodan Response:', JSON.stringify(data, null, 2));
    } catch {
      console.log('Shodan Response (not JSON):', text.slice(0, 100));
    }
  } catch (err) {
    console.log('Shodan Error:', err.message);
  }
}

async function testCensys() {
  console.log('\nTesting Censys...');
  const auth = Buffer.from(`${VITE_CENSYS_API_ID}:${VITE_CENSYS_API_SECRET}`).toString('base64');
  // Using hosts/search V2
  const url = `https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.names:google.com&per_page=1`;
  try {
    const res = await fetch(url, { 
      headers: { 
        'Authorization': `Basic ${auth}`,
        'Accept': 'application/json'
      } 
    });
    const text = await res.text();
    console.log('Censys Status:', res.status);
    try {
      const data = JSON.parse(text);
      console.log('Censys Response:', JSON.stringify(data, null, 2));
    } catch {
      console.log('Censys Response (not JSON):', text.slice(0, 100));
    }
  } catch (err) {
    console.log('Censys Error:', err.message);
  }
}

async function testGreyHat() {
  console.log('\nTesting GreyHat...');
  const url = `https://v1.greyhatwarfare.com/api/v1/buckets/search?keywords=google&key=${VITE_GREYHAT_API_KEY}`;
  try {
    const res = await fetch(url);
    const text = await res.text();
    console.log('GreyHat Status:', res.status);
    try {
      const data = JSON.parse(text);
      console.log('GreyHat Response:', JSON.stringify(data, null, 2));
    } catch {
      console.log('GreyHat Response (not JSON):', text.slice(0, 100));
    }
  } catch (err) {
    console.log('GreyHat Error:', err.message);
  }
}

(async () => {
  await testShodan();
  await testCensys();
  await testGreyHat();
})();
