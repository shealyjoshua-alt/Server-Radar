const USER_AGENT = 'ServerRadar/1.0 (personal dashboard)';

class HttpError extends Error {
  constructor(status, url) {
    super(`HTTP ${status} ${url}`);
    this.name = 'HttpError';
    this.status = status;
  }
}

async function httpGet(url, { timeoutMs = 30000, headers = {}, method = 'GET', body } = {}) {
  const res = await fetch(url, {
    method,
    body,
    headers: { 'User-Agent': USER_AGENT, ...headers },
    signal: AbortSignal.timeout(timeoutMs),
    redirect: 'follow',
  });
  if (!res.ok) throw new HttpError(res.status, url);
  return res.text();
}

module.exports = { httpGet, HttpError, USER_AGENT };
