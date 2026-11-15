// Bounded CDP transport for an owned browser. Never log command parameters.
export class BrowserProtocol {
  constructor(socket, timeoutMs = 10000) {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('invalid CDP deadline');
    this.socket = socket;
    this.timeoutMs = timeoutMs;
    this.sequence = 0;
    this.pending = new Map();
    this.failure = undefined;
    this.lastCompleted = undefined;
    socket.addEventListener('error', () => this.fail(new Error('CDP socket error')));
    socket.addEventListener('close', () => this.fail(new Error('CDP socket closed')));
    socket.addEventListener('message', ({ data }) => {
      try {
        const value = JSON.parse(data);
        if (!value.id) return;
        const waiter = this.pending.get(value.id);
        // A response may arrive after its command deadline expired.
        if (!waiter) return;
        if (value.error) waiter.reject(new Error(`CDP ${waiter.method}: protocol error`));
        else {
          this.lastCompleted = waiter.method;
          waiter.resolve(value.result);
        }
      } catch {
        this.fail(new Error('malformed CDP response'));
      }
    });
  }

  fail(error) {
    this.failure ??= error;
    for (const waiter of this.pending.values()) waiter.reject(this.failure);
  }

  async ready() {
    if (this.failure) throw this.failure;
    if (this.socket.readyState === 1) return;
    let opened;
    const waiting = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('CDP connection deadline')), this.timeoutMs);
      const done = (action, value) => {
        clearTimeout(timer);
        this.pending.delete(0);
        action(value);
      };
      this.pending.set(0, { method: 'connect', reject: error => done(reject, error) });
      opened = () => done(resolve);
      this.socket.addEventListener('open', opened, { once: true });
    });
    try {
      await waiting;
    } catch (error) {
      this.fail(error);
      this.socket.close();
      throw error;
    } finally {
      this.pending.delete(0);
      this.socket.removeEventListener('open', opened);
    }
  }

  async send(method, params = {}, sessionId) {
    if (this.failure) throw this.failure;
    const id = ++this.sequence;
    let timer;
    try {
      return await new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`CDP ${method}: response deadline`)), this.timeoutMs);
        this.pending.set(id, { method, resolve, reject });
        this.socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
      });
    } finally {
      clearTimeout(timer);
      this.pending.delete(id);
    }
  }

  snapshot() {
    return { lastCompleted: this.lastCompleted, pending: [...this.pending.values()].map(value => value.method), failure: this.failure?.message };
  }

  close() {
    this.fail(new Error('CDP owner closed'));
    this.socket.close();
  }
}
