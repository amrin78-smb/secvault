import { getApiInfo, getEngines } from '../../../../lib/adapters/forcepoint/smc';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../lib/rbac';

export const dynamic = 'force-dynamic';

// POST /api/devices/test-smc — test SMC connectivity BEFORE a device is saved (used by
// the "Add Device" form, which has no device id / stored credential yet). The API key
// is passed raw in the request body since there's no device row or credStore entry to
// look it up from. This route must NOT write anything to the database.
export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }

  const body = await request.json().catch(() => ({}));
  const { smc_host, smc_port, api_key, allow_self_signed_ssl } = body || {};

  if (!smc_host || !api_key) {
    return Response.json(
      { ok: false, message: 'smc_host and api_key are required' },
      { status: 400 }
    );
  }

  const conn = {
    smcHost: smc_host,
    smcPort: smc_port || 8082,
    apiKey: api_key,
    allowSelfSignedSsl: allow_self_signed_ssl !== false,
  };

  try {
    await getApiInfo(conn);

    let engineCount = null;
    try {
      const engines = await getEngines(conn);
      engineCount = engines.length;
    } catch (_err) {
      // Connectivity succeeded but engine listing failed — still report ok, just
      // without an engine count.
      engineCount = null;
    }

    return Response.json({
      ok: true,
      message:
        engineCount !== null
          ? `Connected — SMC reachable, ${engineCount} engines found`
          : 'Connected — SMC reachable',
      engineCount,
    });
  } catch (err) {
    return Response.json({ ok: false, message: err.message });
  }
}
