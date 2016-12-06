CREATE TABLE IF NOT EXISTS messages (
  id INTEGER NOT NULL,
  dt TEXT NOT NULL,
  message TEXT NOT NULL,
  sender TEXT NOT NULL,
  recipient TEXT NOT NULL,
  readRcpt TEXT
);
