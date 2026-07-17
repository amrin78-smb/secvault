import { pool } from '../../../../lib/db';
import { getLastSyncStatus, getFeedStatusBySource } from '../../../../lib/feeds';

export const dynamic = 'force-dynamic';

export async function GET(request) {
  try {
    const [rows, bySource] = await Promise.all([getLastSyncStatus(pool), getFeedStatusBySource(pool)]);
    return Response.json({ syncs: rows, bySource });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
