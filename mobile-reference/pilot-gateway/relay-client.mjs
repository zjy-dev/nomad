export const ALPHA_LOCAL_DEVICE = '00112233445566778899aabbccddeeff';
const MAX_FRAME_LIST_RESPONSE_BYTES = 16 * 1024 * 1024;
const MAX_ACK_RESPONSE_BYTES = 64 * 1024;

export class RelayClient {
  constructor(baseUrl, token, fetchImpl = fetch) {
    this.baseUrl = loopbackOrigin(baseUrl);
    if (!token) throw new Error('Relay token is required');
    this.token = token;
    this.fetchImpl = fetchImpl;
  }

  async #request(path, init, maxResponseBytes) {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        authorization: `Bearer ${this.token}`,
        'content-type': 'application/json',
        ...(init.headers || {}),
      },
    });
    if (!response.ok) throw new Error(`Relay request failed (${response.status})`);
    return readBoundedJson(response, maxResponseBytes);
  }

  listFrames() {
    return this.#request(
      `/v1/frames?device=${ALPHA_LOCAL_DEVICE}`,
      { method: 'GET' },
      MAX_FRAME_LIST_RESPONSE_BYTES,
    );
  }

  ackFrames(frameIds) {
    return this.#request(
      '/v1/ack',
      {
        method: 'POST',
        body: JSON.stringify({ device: ALPHA_LOCAL_DEVICE, frame_ids: frameIds }),
      },
      MAX_ACK_RESPONSE_BYTES,
    );
  }
}

function loopbackOrigin(baseUrl) {
  let url;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new Error('Relay URL must be a loopback HTTP origin');
  }
  const ipv4 = url.hostname.split('.').map(Number);
  const loopback = url.hostname === 'localhost' || url.hostname === '[::1]'
    || (ipv4.length === 4 && ipv4.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) && ipv4[0] === 127);
  if (url.protocol !== 'http:' || !loopback || url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) {
    throw new Error('Relay URL must be a loopback HTTP origin');
  }
  return url.origin;
}

async function readBoundedJson(response, limit) {
  if (!response.body?.getReader) {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > limit) throw new Error('Relay response too large');
    return JSON.parse(text);
  }
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw new Error('Relay response too large');
    }
    chunks.push(value);
  }
  const body = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), size).toString('utf8');
  return JSON.parse(body);
}
