const axios = require('axios');

// List of URLs to test
const urlsToTest = [
  "http://google.com",
  "http://example.com",
  "http://phishingsite.test" // replace or add more URLs
];

const FASTAPI_URL = 'http://127.0.0.1:8000/predict';

async function testURL(url) {
  try {
    const response = await axios.post(FASTAPI_URL, { url });
    console.log(`✅ Result for ${url}:`, response.data);
  } catch (error) {
    console.error(`❌ Error for ${url}:`, error.response?.data || error.message);
  }
}

async function runTests() {
  for (const url of urlsToTest) {
    await testURL(url);
  }
}

runTests();
