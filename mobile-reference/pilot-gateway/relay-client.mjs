export class RelayClient {
  constructor(baseUrl, token, fetchImpl = fetch) {
    this.baseUrl = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
    this.token = token;
    this.fetchImpl = fetchImpl;
  }

  async request(path, init = {}) {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      ...init,
      headers: { authorization: `Bearer ${this.token}`, 'content-type': 'application/json', ...(init.headers || {}) },
    });
    if (!response.ok) throw new Error(`Relay request failed (${response.status})`);
    return response.json();
  }

  list(channel, target) {
    return this.request(`/v1/test/messages?channel=${encodeURIComponent(channel)}&target=${target}`, { method: 'GET' });
  }

  post(channel, target, messageId, payload) {
    return this.request('/v1/test/messages', { method: 'POST', body: JSON.stringify({ channel, target, message_id: messageId, payload }) });
  }

  ack(channel, target, messageIds) {
    return this.request('/v1/test/ack', { method: 'POST', body: JSON.stringify({ channel, target, message_ids: messageIds }) });
  }
}
