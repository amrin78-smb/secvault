import { pool } from '../../../../lib/db';
import { getLastSyncStatus } from '../../../../lib/feeds';

export const dynamic = 'force-dynamic';

export async function GET(request) {
  try {
    const rows = await getLastSyncStatus(pool);
    return Response.json({ syncs: rows });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
