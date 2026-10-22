// test-cloud-api.js
//
// Verifies whether this machine can obtain an Omada Cloud OpenAPI access token
// with client credentials, and then whether the Omada controller is actually
// reachable through the cloud (the part that matters for bypassing CGNAT).
//
// Usage:
//   OMADA_CLOUD_URL=https://use1-omada-northbound.tplinkcloud.com \
//   OMADA_ID=<omadacId> \
//   OMADA_CLIENT_ID=<client id> \
//   OMADA_CLIENT_SECRET=<client secret> \
//   node test-cloud-api.js
//
// Variable names of the backend are accepted as fallbacks so an existing
// backend/.env can be used via `node -r ./backend/node_modules/dotenv/config`.

const CLOUD_URL = (
  process.env.OMADA_CLOUD_URL ||
  process.env.OMADA_NORTHBOUND_BASE_URL ||
  'https://INSERT_YOUR_INTERFACE_ACCESS_ADDRESS_HERE'
).replace(/\/+$/, '');
const OMADA_ID = process.env.OMADA_ID || process.env.OMADA_OMADAC_ID || 'INSERT_YOUR_OMADA_ID_HERE';
const CLIENT_ID = process.env.OMADA_CLIENT_ID || 'INSERT_YOUR_CLIENT_ID_HERE';
const CLIENT_SECRET = process.env.OMADA_CLIENT_SECRET || 'INSERT_YOUR_CLIENT_SECRET_HERE';

function fail(message) {
  console.error('❌ ' + message);
  process.exitCode = 1;
}

async function testCloudConnection() {
  console.log('Testing Omada Cloud OpenAPI connection...');
  console.log('Endpoint:', CLOUD_URL);

  try {
    // The OpenAPI uses a specific token endpoint with a query parameter for client credentials
    const url = `${CLOUD_URL}/openapi/authorize/token?grant_type=client_credentials`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        omadacId: OMADA_ID,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET
      })
    });

    const data = await response.json();

    // Real controllers wrap the payload in `result`; accept a flat shape too so
    // the test cannot report a false failure.
    const accessToken =
      (data && data.accessToken) ||
      (data && data.result && data.result.accessToken) ||
      null;

    if (response.ok && accessToken) {
      console.log('✅ SUCCESS! Cloud API is capable.');
      console.log('Access Token acquired (first 15 chars):', accessToken.substring(0, 15) + '...');

      // Proof that the controller itself is reachable through the cloud: the
      // backend uses this same authenticated call to resolve the site.
      const sitesUrl = `${CLOUD_URL}/openapi/v1/${OMADA_ID}/sites`;
      const sitesRes = await fetch(sitesUrl, {
        headers: {
          Accept: 'application/json',
          Authorization: 'AccessToken=' + accessToken
        }
      });
      const sitesData = await sitesRes.json();

      if (sitesRes.ok && sitesData.errorCode === 0) {
        const list =
          (sitesData.result && (sitesData.result.data || sitesData.result.sites)) ||
          (Array.isArray(sitesData.result) ? sitesData.result : []);
        console.log('✅ Controller reachable through the cloud — GET /sites returned',
          Array.isArray(list) ? list.length : 0, 'site(s).');
        console.log('The Render backend can successfully use this approach to bypass CGNAT.');
      } else {
        fail('Token worked, but the controller could not be reached through the cloud.');
        console.error('Status:', sitesRes.status);
        console.error('Response:', sitesData);
      }
    } else {
      fail('FAILED to get access token.');
      console.error('Status:', response.status);
      console.error('Response:', data);
    }
  } catch (error) {
    fail('NETWORK ERROR: ' + error.message);
  }
}

testCloudConnection();
