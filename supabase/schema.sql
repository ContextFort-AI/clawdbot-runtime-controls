-- scan_events table only — api_keys and profiles are already created by the website.
-- Run this in the Supabase SQL Editor.

CREATE TABLE scan_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  api_key_id UUID REFERENCES api_keys(id),
  user_id UUID REFERENCES profiles(id),
  install_id TEXT,
  skill_path TEXT,
  skill_name TEXT,
  file_count INTEGER,
  result_suspicious BOOLEAN,
  haiku_reason TEXT,
  skill_files JSONB,
  event_type TEXT,
  scan_type TEXT DEFAULT 'skill',
  scanned_at TIMESTAMPTZ DEFAULT now()
);

-- Migration: add scan_type column to existing tables
-- ALTER TABLE scan_events ADD COLUMN scan_type TEXT DEFAULT 'skill';
