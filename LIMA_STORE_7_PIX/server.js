import 'dotenv/config';
import express from 'express';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';

const app = express();
const PORT = Number(process.env.PORT || 3000);
const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN;
const MP_WEBHOOK_SECRET = process.env.MP_WEBHOOK_SECRET || '';
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || '').replace(/\/$/, '');
const db = new Database(process.env.DB_PATH || 'lima-store.sqlite');
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    value_cents INTEGER NOT NULL,
    buyer_name TEXT NOT NULL,
    buyer_email TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    mp_payment_id TEXT,
    pix_copy_paste TEXT,
    pix_qr_base64 TEXT,
    ticket_url TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
`);
const allowedValues = new Set([3000, 5000, 20000, 35000]);

app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

// Validate Mercado Pago webhook signature when a secret is configured.
// Configure the webhook secret from your Mercado Pago application settings.
function validateWebhook(req) {
  if (!MP_WEBHOOK_SECRET) return process.env.NODE_ENV !== 'production';
  const signature = req.get('x-signature') || '';
  const requestId = req.get('x-request-id') || '';
  const dataId = String(req.query['data.id'] || req.body?.data?.id || '').toLowerCase();
  const ts = signature.match(/(?:^|,)ts=([^,]+)/)?.[1];
  const v1 = signature.match(/(?:^|,)v1=([^,]+)/)?.[1];
  if (!ts || !v1 || !requestId || !dataId) return false;
  const manifest = `id:${dataId};request-id:${requestId};ts:${ts};`;
  const expected = crypto.createHmac('sha256', MP_WEBHOOK_SECRET).update(manifest).digest('hex');
  return safeEqual(expected, v1);
}

async function mpRequest(path, options = {}) {
  if (!MP_ACCESS_TOKEN) throw new Error('MP_ACCESS_TOKEN não configurado no servidor.');
  const response = await fetch(`https://api.mercadopago.com${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${MP_ACCESS_TOKEN}`,
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    console.error('Mercado Pago API error:', response.status, data);
    const error = new Error(data.message || 'Erro ao comunicar com o provedor de pagamentos.');
    error.status = 502;
    throw error;
  }
  return data;
}

app.post('/api/orders', async (req, res) => {
  try {
    const valueCents = Number(req.body?.valueCents);
    const buyerName = String(req.body?.name || '').trim().slice(0, 100);
    const buyerEmail = String(req.body?.email || '').trim().toLowerCase().slice(0, 160);
    if (!allowedValues.has(valueCents)) return res.status(400).json({ error: 'Valor de baú inválido.' });
    if (buyerName.length < 2) return res.status(400).json({ error: 'Informe seu nome.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(buyerEmail)) return res.status(400).json({ error: 'Informe um e-mail válido.' });

    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const amount = valueCents / 100;
    db.prepare(`INSERT INTO orders (id,value_cents,buyer_name,buyer_email,status,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?)`).run(id, valueCents, buyerName, buyerEmail, 'pending', now, now);

    const payment = await mpRequest('/v1/payments', {
      method: 'POST',
      headers: { 'X-Idempotency-Key': id },
      body: JSON.stringify({
        transaction_amount: amount,
        description: `LIMA STORE 7 - Baú de Cartões ${amount.toLocaleString('pt-BR', {style:'currency',currency:'BRL'})}`,
        payment_method_id: 'pix',
        external_reference: id,
        notification_url: PUBLIC_BASE_URL ? `${PUBLIC_BASE_URL}/api/webhooks/mercadopago` : undefined,
        payer: { email: buyerEmail, first_name: buyerName }
      })
    });

    const tx = payment.point_of_interaction?.transaction_data || {};
    db.prepare(`UPDATE orders SET mp_payment_id=?,pix_copy_paste=?,pix_qr_base64=?,ticket_url=?,updated_at=? WHERE id=?`)
      .run(String(payment.id), tx.qr_code || '', tx.qr_code_base64 || '', tx.ticket_url || '', new Date().toISOString(), id);

    res.status(201).json({
      orderId: id,
      status: payment.status || 'pending',
      amount,
      pixCopyPaste: tx.qr_code || '',
      pixQrBase64: tx.qr_code_base64 || '',
      ticketUrl: tx.ticket_url || ''
    });
  } catch (err) {
    console.error(err);
    res.status(err.status || 500).json({ error: err.message || 'Não foi possível criar o PIX.' });
  }
});

app.get('/api/orders/:id', (req, res) => {
  const order = db.prepare('SELECT id,value_cents,buyer_name,status,created_at,updated_at FROM orders WHERE id=?').get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Pedido não encontrado.' });
  res.json({ orderId: order.id, amount: order.value_cents / 100, name: order.buyer_name, status: order.status, createdAt: order.created_at, updatedAt: order.updated_at });
});

async function updatePayment(paymentId) {
  const payment = await mpRequest(`/v1/payments/${encodeURIComponent(paymentId)}`);
  const orderId = payment.external_reference;
  if (!orderId) return;
  const order = db.prepare('SELECT * FROM orders WHERE id=?').get(orderId);
  if (!order || String(order.mp_payment_id) !== String(payment.id)) return;
  // Only mark paid after verifying the payment directly with Mercado Pago and matching exact amount.
  const expectedAmount = order.value_cents / 100;
  if (payment.status === 'approved' && Number(payment.transaction_amount) === expectedAmount) {
    db.prepare('UPDATE orders SET status=?,updated_at=? WHERE id=?').run('paid', new Date().toISOString(), orderId);
  } else if (['rejected', 'cancelled', 'refunded', 'charged_back'].includes(payment.status)) {
    db.prepare('UPDATE orders SET status=?,updated_at=? WHERE id=?').run(payment.status, new Date().toISOString(), orderId);
  } else {
    db.prepare('UPDATE orders SET status=?,updated_at=? WHERE id=?').run('pending', new Date().toISOString(), orderId);
  }
}

app.post('/api/webhooks/mercadopago', async (req, res) => {
  if (!validateWebhook(req)) return res.status(401).send('Invalid webhook signature');
  res.sendStatus(200); // Acknowledge quickly; fetch authoritative payment state next.
  const topic = req.query.type || req.body?.type;
  const paymentId = req.query['data.id'] || req.body?.data?.id;
  if ((topic === 'payment' || req.body?.action?.startsWith('payment.')) && paymentId) {
    try { await updatePayment(String(paymentId)); }
    catch (e) { console.error('Webhook payment refresh failed:', e.message); }
  }
});

// A customer-side polling endpoint is also available, but it never trusts browser-provided payment status.
app.post('/api/orders/:id/refresh', async (req, res) => {
  try {
    const order = db.prepare('SELECT mp_payment_id FROM orders WHERE id=?').get(req.params.id);
    if (!order) return res.status(404).json({ error: 'Pedido não encontrado.' });
    if (order.mp_payment_id) await updatePayment(order.mp_payment_id);
    const updated = db.prepare('SELECT id,value_cents,status FROM orders WHERE id=?').get(req.params.id);
    res.json({ orderId: updated.id, amount: updated.value_cents / 100, status: updated.status });
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: 'Não foi possível atualizar o status agora.' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true }));
app.listen(PORT, () => console.log(`LIMA STORE 7 rodando na porta ${PORT}`));
