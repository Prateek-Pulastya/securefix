import express from 'express';
import { invoices } from './routes/invoices';

export const app = express();
app.use(express.json());
app.use('/invoices', invoices);

app.get('/health', (_req, res) => res.json({ ok: true }));
