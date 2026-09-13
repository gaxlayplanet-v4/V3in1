import { connect } from 'cloudflare:sockets';

// ===================================================
// TYPE A: SPEED-DEMON (VLESS + WS) + DYNAMIC PROXY IP
// Features: Strict Path, Mask Page, Dynamic GitHub IPs
// ===================================================

// Global Variables for Caching (Cloudflare Isolate Memory)
let cachedProxyIPs = [];
let lastFetchTime = 0;
const CACHE_TTL = 5 * 60 * 1000; // 5 မိနစ် (Millisecond ဖြင့်)

export default {
    async fetch(request, env, ctx) {
        // 1. Configurations
        const UUID = (env.UUID || ";
        let WS_PATH = env.WS_PATH || "/speed-tunnel";
        if (!WS_PATH.startsWith('/')) WS_PATH = '/' + WS_PATH;
        
        // Github URL နှင့် Fallback IP
        const PROXY_URL = env.PROXY_URL || "https://galaxytunnel.github.io/PROXYIP.txt";
        const DEFAULT_PROXY_IP = env.PROXY_IP || "cdn-b100.xn--b6gac.eu.org";

        const url = new URL(request.url);
        const upgradeHeader = request.headers.get('Upgrade');

        if (upgradeHeader === 'websocket') {
            if (url.pathname === WS_PATH || url.pathname === WS_PATH + '/') {
                return await vlessOverWSHandler(request, UUID, PROXY_URL, DEFAULT_PROXY_IP);
            } else {
                return new Response("Not Found", { status: 404 });
            }
        }

        if (url.pathname === `/${UUID}`) {
            return new Response(getDashboard(url.hostname, UUID, WS_PATH, PROXY_URL), {
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            });
        }

        return new Response(
            `<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>`,
            { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
        );
    }
};

// ===================================================
// DYNAMIC PROXY IP FETCHER (WITH CACHE)
// ===================================================
async function getProxyIPs(url, defaultIp) {
    const now = Date.now();
    // ၅ မိနစ် မပြည့်သေးရင် မှတ်ထားတဲ့ IP တွေကိုပဲ အမြန်ပြန်ပေးမယ်
    if (cachedProxyIPs.length > 0 && (now - lastFetchTime < CACHE_TTL)) {
        return cachedProxyIPs;
    }
    
    try {
        const response = await fetch(url);
        if (response.ok) {
            const text = await response.text();
            // စာကြောင်း တစ်ကြောင်းချင်းစီခွဲထုတ်မယ်၊ အလွတ်တွေ ဖျက်မယ်
            const ips = text.split('\n').map(ip => ip.trim()).filter(ip => ip.length > 0);
            if (ips.length > 0) {
                cachedProxyIPs = ips;
                lastFetchTime = now;
                return cachedProxyIPs;
            }
        }
    } catch (e) {
        console.error("Failed to fetch proxy IPs from GitHub", e);
    }
    
    // GitHub ကနေ ယူလို့မရရင် Default IP ကို သုံးမယ်
    return cachedProxyIPs.length > 0 ? cachedProxyIPs : [defaultIp];
}

// ===================================================
// VLESS PROTOCOL HANDLER
// ===================================================
async function vlessOverWSHandler(request, expectedUUID, proxyUrl, defaultProxyIp) {
    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);
    server.accept();

    let address = '';
    let isFirstMessage = true;
    let remoteSocket = null;

    server.addEventListener('message', async (event) => {
        if (isFirstMessage) {
            isFirstMessage = false;
            const payload = event.data;
            if (payload.byteLength < 24) return server.close();

            const uuidBytes = new Uint8Array(payload.slice(1, 17));
            const uuidString = [...uuidBytes].map(b => b.toString(16).padStart(2, '0')).join('').replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
            if (uuidString !== expectedUUID) return server.close();

            const optLength = new Uint8Array(payload.slice(17, 18))[0];
            const command = new Uint8Array(payload.slice(18 + optLength, 18 + optLength + 1))[0];
            if (command !== 1) return server.close(); 

            const portIndex = 18 + optLength + 1;
            const portRemote = new DataView(payload.slice(portIndex, portIndex + 2)).getUint16(0);
            
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

            try {
                // ==========================================
                // 1. DYNAMIC PROXY ROUTING
                // ==========================================
                // GitHub ကနေ IP တွေ လှမ်းယူမယ် (သို့) Cache ထဲက ယူမယ်
                const proxyIPs = await getProxyIPs(proxyUrl, defaultProxyIp);
                
                // Array ထဲကနေ Random IP တစ်ခု ရွေးမယ်
                const randomProxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
                
                // ရွေးထားတဲ့ Proxy IP ကို အသုံးပြုပြီး ချိတ်ဆက်မယ်
                remoteSocket = connect({ 
                    hostname: randomProxyIP,
                    port: portRemote 
                });
                
                remoteSocket.closed.catch(console.error);

                const vlessResponseHeader = new Uint8Array([payload[0], 0]);
                const rawClientData = payload.slice(addressIndex);

                const writer = remoteSocket.writable.getWriter();
                await writer.write(rawClientData);
                writer.releaseLock();

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
function getDashboard(hostName, uuid, wsPath, proxyUrl) {
    const vlessLink = `vless://${uuid}@${hostName}:443?encryption=none&security=tls&sni=${hostName}&type=ws&host=${hostName}&path=${encodeURIComponent(wsPath + "?ed=2048")}#VLESS-Global-Speed`;
    
    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>VLESS Dynamic Node</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #f4f4f9; padding: 20px; color: #333; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-top: 5px solid #0070f3; }
            h2 { color: #0070f3; text-align: center; }
            .box { background: #f9f9f9; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #ddd; word-break: break-all; }
            .label { font-weight: bold; color: #555; }
            .btn { display: block; width: 100%; text-align: center; background: #0070f3; color: white; padding: 10px; text-decoration: none; border-radius: 5px; font-weight: bold; margin-top: 10px; }
            .btn:hover { background: #005bb5; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🌍 VLESS Dynamic Routing Node</h2>
            
            <div class="box">
                <p><span class="label">Status:</span> 🟢 Online (Dynamic Proxy IP)</p>
                <p><span class="label">Domain:</span> ${hostName}</p>
                <p><span class="label">WS Path:</span> ${wsPath}</p>
                <p><span class="label">Proxy List URL:</span> <a href="${proxyUrl}" target="_blank">GitHub TXT File</a></p>
                <p><small style="color:#666;">(IP List auto-updates every 5 minutes)</small></p>
            </div>

            <div class="box">
                <p class="label">🚀 Subscription Link:</p>
                <code style="display:block; margin-top:10px; background:#eef; padding:10px; border-radius:5px;">${vlessLink}</code>
                <a href="${vlessLink}" class="btn">Add to Nekobox / v2rayN</a>
            </div>
        </div>
    </body>
    </html>`;
                                              }
