async function getToken() {
  const gw = document.getElementById('gateway').value;
  const creds = btoa('demo:demo');
  const res = await fetch(`${gw}/api/auth/token`, { headers: { Authorization: `Basic ${creds}` }});
  const json = await res.json();
  window._token = json.token;
  document.getElementById('tokenOut').textContent = JSON.stringify(json, null, 2);
}
async function run() {
  const gw = document.getElementById('gateway').value;
  const q = document.getElementById('q').value;
  const k = parseInt(document.getElementById('k').value, 10) || 3;
  const res = await fetch(`${gw}/api/query`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${window._token || ''}`
    },
    body: JSON.stringify({ query: q, k })
  });
  const json = await res.json();
  document.getElementById('out').textContent = JSON.stringify(json, null, 2);
}
document.getElementById('getToken').addEventListener('click', getToken);
document.getElementById('run').addEventListener('click', run);
