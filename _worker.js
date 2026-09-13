import { connect } from 'cloudflare:sockets';

// ===================================================
// TYPE A: SPEED-DEMON (VLESS + WEBSOCKET ONLY)
// Features: Strict Path Routing, Mask Page, High Speed
// ===================================================

export default {
    async fetch(request, env, ctx) {
        // 1. Load Configurations from Env
        const UUID = (env.UUID || "d342d11e-d424-4583-b36e-524ab1f0afa4").toLowerCase().trim();
        const PROXY_IP = env.PROXY_IP || "cdn-b100.xn--b6gac.eu.org";
        let WS_PATH = env.WS_PATH || "/speed-tunnel";
        if (!WS_PATH.startsWith('/')) WS_PATH = '/' + WS_PATH;

        const url = new URL(request.url);
        const upgradeHeader = request.headers.get('Upgrade');

        // ==========================================
        // 2. STRICT WEBSOCKET ROUTING (ANTI-PROBING)
        // ==========================================
        if (upgradeHeader === 'websocket') {
            // Path အတိအကျ မှန်မှသာ VPN အဖြစ် လက်ခံမည်
            if (url.pathname === WS_PATH || url.pathname === WS_PATH + '/') {
                return await vlessOverWSHandler(request, UUID, PROXY_IP);
            } else {
                // Path မှားပါက ချက်ချင်း Connection ဖြတ်ချမည် (Active Probing ကာကွယ်ရန်)
                return new Response("Not Found", { status: 404 });
            }
        }

        // ==========================================
        // 3. SECRET DASHBOARD (UUID ဖြင့် ဝင်ရန်)
        // ==========================================
        if (url.pathname === `/${UUID}`) {
            return new Response(getDashboard(url.hostname, UUID, WS_PATH, PROXY_IP), {
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
        }

        // ==========================================
        // 4. MASK PAGE (CAMOUFLAGE)
        // ==========================================
        // သာမန်ဝင်လာသူတိုင်းကို Nginx Error Page အတုသာ ပြထားမည်
        return new Response(
            `<!DOCTYPE html>
<html>
<head>
<title>404 Not Found</title>
<style>
    body { font-family: Tahoma, Verdana, Arial, sans-serif; text-align: center; margin-top: 50px; }
    h1 { font-size: 24px; font-weight: normal; }
</style>
</head>
<body>
<h1>404 Not Found</h1>
<hr>
<p>nginx/1.18.0 (Ubuntu)</p>
</body>
</html>`,
            { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
        );
    }
};

// ===================================================
// VLESS PROTOCOL HANDLER (LEAN & FAST)
// ===================================================
async function vlessOverWSHandler(request, expectedUUID, proxyIP) {
    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);
    server.accept();

    let address = '';
    let portWithRandomLog = '';
    let isFirstMessage = true;
    let remoteSocket = null;
    let log = '';

    server.addEventListener('message', async (event) => {
        if (isFirstMessage) {
            isFirstMessage = false;
            const payload = event.data;
            if (payload.byteLength < 24) return server.close();

            // 1. Verify UUID
            const uuidBytes = new Uint8Array(payload.slice(1, 17));
            const uuidString = [...uuidBytes].map(b => b.toString(16).padStart(2, '0')).join('').replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
            if (uuidString !== expectedUUID) return server.close();

            // 2. Parse Destination Address & Port
            const optLength = new Uint8Array(payload.slice(17, 18))[0];
            const command = new Uint8Array(payload.slice(18 + optLength, 18 + optLength + 1))[0];
            if (command !== 1) return server.close(); // Only TCP supported

            const portIndex = 18 + optLength + 1;
            const portBuffer = payload.slice(portIndex, portIndex + 2);
            const portRemote = new DataView(portBuffer).getUint16(0);
            
            let addressIndex = portIndex + 2;
            const addressType = new Uint8Array(payload.slice(addressIndex, addressIndex + 1))[0];
            addressIndex++;

            if (addressType === 1) { // IPv4
                address = new Uint8Array(payload.slice(addressIndex, addressIndex + 4)).join('.');
                addressIndex += 4;
            } else if (addressType === 2) { // Domain
                const addressLength = new Uint8Array(payload.slice(addressIndex, addressIndex + 1))[0];
                addressIndex++;
                address = new TextDecoder().decode(payload.slice(addressIndex, addressIndex + addressLength));
                addressIndex += addressLength;
            } else if (addressType === 3) { // IPv6
                const v6a = new Uint8Array(payload.slice(addressIndex, addressIndex + 16));
                const ipv6 = [];
                for (let i = 0; i < 16; i += 2) ipv6.push((v6a[i] << 8 | v6a[i + 1]).toString(16));
                address = ipv6.join(':');
                addressIndex += 16;
            }

            // 3. Connect to Target or Proxy IP
            try {
                // Connect direct, but if it's cloudflare-restricted, we might need proxyIP
                // For Speed-Demon, we try direct connect via Cloudflare Sockets
                remoteSocket = connect({ hostname: address, port: portRemote });
                
                remoteSocket.closed.catch(console.error);

                // 4. VLESS Initial Response
                const vlessResponseHeader = new Uint8Array([payload[0], 0]);
                const rawClientData = payload.slice(addressIndex);

                const writer = remoteSocket.writable.getWriter();
                await writer.write(rawClientData);
                writer.releaseLock();

                // 5. Stream Piping (Duplex)
                remoteSocket.readable.pipeTo(new WritableStream({
                    start() { server.send(vlessResponseHeader); },
                    write(chunk) { server.send(chunk); },
                    close() { server.close(); },
                    abort(e) { server.close(); }
                })).catch(console.error);

            } catch (err) {
                server.close();
            }
        } else {
            // Forward subsequent WS data to TCP Socket
            if (remoteSocket) {
                const writer = remoteSocket.writable.getWriter();
                await writer.write(event.data);
                writer.releaseLock();
            }
        }
    });

    return new Response(null, { status: 101, webSocket: client });
}

// ===================================================
// SECRET DASHBOARD UI
// ===================================================
function getDashboard(hostName, uuid, wsPath, proxyIP) {
    const vlessLink = `vless://${uuid}@${hostName}:443?encryption=none&security=tls&sni=${hostName}&type=ws&host=${hostName}&path=${encodeURIComponent(wsPath + "?ed=2048")}#Speed-Demon-TLS`;
    
    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Speed-Demon Dashboard</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #f4f4f9; padding: 20px; color: #333; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            h2 { color: #0070f3; text-align: center; }
            .box { background: #f9f9f9; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #ddd; word-break: break-all; }
            .label { font-weight: bold; color: #555; }
            .btn { display: block; width: 100%; text-align: center; background: #0070f3; color: white; padding: 10px; text-decoration: none; border-radius: 5px; font-weight: bold; margin-top: 10px; }
            .btn:hover { background: #005bb5; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>⚡ Speed-Demon VLESS Node</h2>
            
            <div class="box">
                <p><span class="label">Status:</span> 🟢 Online (VLESS + WS Only)</p>
                <p><span class="label">Domain / Host:</span> ${hostName}</p>
                <p><span class="label">Secret WS Path:</span> ${wsPath}</p>
                <p><span class="label">Proxy IP:</span> ${proxyIP}</p>
            </div>

            <div class="box">
                <p class="label">🚀 Subscription Link (TLS Port 443):</p>
                <code style="display:block; margin-top:10px; background:#eef; padding:10px; border-radius:5px;">${vlessLink}</code>
                <a href="${vlessLink}" class="btn">Add to Nekobox / v2rayN</a>
            </div>
        </div>
    </body>
    </html>`;
             }
