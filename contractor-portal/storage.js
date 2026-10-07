require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

async function main() {
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env;
  const bucket = process.env.CONTRACTOR_STORAGE_BUCKET || 'contractor-private';
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error('Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in the private environment.');
  }

  const storage = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false }
  }).storage;
  const { data: buckets, error: listError } = await storage.listBuckets();
  if (listError) throw listError;

  const existing = buckets.find(item => item.name === bucket);
  if (existing?.public) throw new Error(`Storage bucket "${bucket}" exists but is public. Use a private bucket for worker records.`);
  if (!existing) {
    const { error: createError } = await storage.createBucket(bucket, {
      public: false,
      fileSizeLimit: '5MB',
      allowedMimeTypes: ['image/jpeg', 'image/png', 'image/webp', 'application/pdf']
    });
    if (createError) throw createError;
  }
  console.log(`Private contractor storage bucket "${bucket}" is ready.`);
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
