const axios = require('axios');
const readline = require('readline');

const FASTAPI_URL = 'http://127.0.0.1:8000/predict';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

async function checkURL(url) {
  try {
    const response = await axios.post(FASTAPI_URL, { url });
    console.log(`✅ Result for ${url}:`, response.data);
  } catch (error) {
    console.error(`❌ Error for ${url}:`, error.response?.data || error.message);
  }
}

function askURL() {
  rl.question('Enter a URL to check (or type "exit" to quit): ', async (url) => {
    if (url.toLowerCase() === 'exit') {
      console.log('Exiting...');
      rl.close();
      return;
    }
    await checkURL(url);
    askURL(); // Ask again
  });
}

// Start interactive prompt
askURL();
