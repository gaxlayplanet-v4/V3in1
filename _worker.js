import { connect } from "cloudflare:sockets";

// =========================================================================
// 🚀 GALAXY TUNNEL - ALL IN ONE (VLESS + TROJAN)
// =========================================================================
// Features: 
// 1. VLESS & Trojan Multiplexing (Same Port)
// 2. TLS & NoTLS (Port 80, 8080) Full Support
// 3. Dynamic Auto-rotating ProxyIP Pool
// 4. Pure SHA-224 implementation for strict Trojan Clients
// 5. Subscription Generator (/sub) & Clash Generator (/clash)
// =========================================================================

// --- Default Configuration (Overridden by wrangler.toml / Env Vars) ---
let userID = "";
let proxyIP = ""; // Leave blank to use Auto-Pool
let dohURL = "https://cloudflare-dns.com/dns-query";

// --- Cloudflare Supported Ports ---
const TLS_PORTS = [443, 8443, 2053, 2096, 2087, 2083];
const NOTLS_PORTS = [80, 8080, 8880, 2052, 2086, 2095];

// --- Auto-rotating Proxy Pool (Fallback) ---
const PROXY_POOL = [
    "cdn.anycast.eu.org", "cdn-all.xn--b6gac.eu.org", "time.cloudflare.com",
    "icook.hk", "japan.com", "malaysia.com", "singapore.com", "skk.moe",
    "www.visa.com.sg", "www.visa.com.hk", "www.visa.com.tw", "www.visa.co.jp",
    "www.visakorea.com", "www.digitalocean.com", "www.csgo.com", "www.udemy.com"
];

// ============================================
// MAIN WORKER ENTRY POINT
// ============================================
export default {
    async fetch(request, env, ctx) {
        // Load Environment Variables
        userID = (env.UUID || env.uuid || userID).toLowerCase().trim();
        proxyIP = env.PROXYIP || env.proxyip || env.PROXY_IP || proxyIP;
        dohURL = env.DNS_RESOLVER_URL || dohURL;

        if (!isValidUUID(userID)) {
            return new Response("Invalid UUID Configured in Dashboard", { status: 500 });
        }

        const upgradeHeader = request.headers.get("Upgrade");
        const url = new URL(request.url);
        const host = request.headers.get("Host");

        // 1. Strict WebSocket Path Routing (Anti-Probing)
        const wsPath = (env.WS_PATH || "/galaxy-tunnel").replace(/^\/?/, '/');
        
        if (upgradeHeader === "websocket") {
            if (path === wsPath || path === wsPath + "/") {
                return await proxyOverWSHandler(request);
            } else {
                return new Response("Not Found", { status: 404 });
            }
        }

        // 2. HTTP Requests -> Handle Routing
        const path = url.pathname;

        // Subscriptions (Hidden behind UUID path to prevent discovery)
        if (path === `/${userID}/sub`) {
            return new Response(generateSubscription(userID, host, wsPath), {
                headers: { "Content-Type": "text/plain; charset=utf-8" }
            });
        }

        if (path === `/${userID}/clash`) {
            return new Response(generateClashConfig(userID, host, wsPath), {
                headers: { "Content-Type": "text/yaml; charset=utf-8" }
            });
        }

        // Config Page (UI) - Only accessible via /UUID
        if (path === `/${userID}`) {
            return new Response(getGalaxyUI(userID, host, proxyIP, wsPath), {
                headers: { "Content-Type": "text/html; charset=utf-8" }
            });
        }

        // Default Fake Page (Camouflage against Active Probing)
        return new Response(
            `<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>`, 
            { status: 404, headers: { "Content-Type": "text/html; charset=utf-8" } }
        );
    }
};

// ============================================
// WEBSOCKET PROXY LOGIC
// ============================================
async function proxyOverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = "";
    let portWithLog = "";
    const log = (info) => console.log(`[${address}:${portWithLog}] ${info}`);

    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWrapper = { value: null };
    let udpStreamWrite = null;
    let isDns = false;
    let protocolDetected = false;

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns && udpStreamWrite) return udpStreamWrite(chunk);
            
            if (remoteSocketWrapper.value) {
                const writer = remoteSocketWrapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            // Protocol Multiplexing (VLESS vs Trojan)
            let result = processVlessHeader(chunk, userID);
            if (result.hasError) {
                // If not VLESS, try Trojan (Password = UUID)
                result = await processTrojanHeader(chunk, userID);
                if (result.hasError) throw new Error(result.message);
                protocolDetected = "trojan";
            } else {
                protocolDetected = "vless";
            }

            const { addressRemote = "", portRemote = 443, rawDataIndex, responseHeader, isUDP } = result;
            address = addressRemote;
            portWithLog = `${portRemote} ${isUDP ? "udp" : "tcp"}`;

            if (isUDP && portRemote !== 53) throw new Error("UDP proxy only enabled for DNS (port 53)");
            if (isUDP && portRemote === 53) {
                isDns = true;
                const { write } = await handleUDPOutBound(webSocket, responseHeader, log);
                udpStreamWrite = write;
                udpStreamWrite(chunk.slice(rawDataIndex));
                return;
            }

            handleTCPOutBound(remoteSocketWrapper, addressRemote, portRemote, chunk.slice(rawDataIndex), webSocket, responseHeader, log);
        },
        close() { log("WebSocket stream closed"); },
        abort(reason) { log("WebSocket stream aborted"); }
    })).catch((err) => log("WebSocket pipeTo error"));

    return new Response(null, { status: 101, webSocket: client });
}

// ============================================
// TCP FORWARDING & PROXY-POOL RETRY
// ============================================
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log) {
    async function connectAndWrite(address, port) {
        const tcpSocket = connect({ hostname: address, port });
        remoteSocket.value = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function retry() {
        // Auto-select proxy IP if direct fails
        let fallbackIP = proxyIP;
        if (!fallbackIP) {
            fallbackIP = PROXY_POOL[Math.floor(Math.random() * PROXY_POOL.length)];
        }
        log(`Direct connection failed. Retrying via ProxyIP: ${fallbackIP}`);
        
        try {
            const tcpSocket = await connectAndWrite(fallbackIP, portRemote);
            tcpSocket.closed.catch(() => safeCloseWebSocket(webSocket));
            remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
        } catch (e) {
            log("Retry also failed.");
            safeCloseWebSocket(webSocket);
        }
    }

    try {
        const tcpSocket = await connectAndWrite(addressRemote, portRemote);
        tcpSocket.closed.catch(() => safeCloseWebSocket(webSocket));
        remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
    } catch (e) {
        await retry();
    }
}

// ============================================
// VLESS PARSER
// ============================================
function processVlessHeader(vlessBuffer, userID) {
    if (vlessBuffer.byteLength < 24) return { hasError: true, message: "Invalid VLESS data" };
    
    const version = new Uint8Array(vlessBuffer.slice(0, 1));
    const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
    const slicedBufferString = stringify(slicedBuffer);

    if (slicedBufferString !== userID) return { hasError: true, message: "Invalid VLESS user" };

    const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
    const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
    const isUDP = command === 2;

    const portIndex = 18 + optLength + 1;
    const portRemote = new DataView(vlessBuffer.slice(portIndex, portIndex + 2)).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressType = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1))[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = "";

    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;
        case 2:
            addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3:
            addressLength = 16;
            const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
            addressValue = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `Invalid VLESS address type` };
    }

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        responseHeader: new Uint8Array([version[0], 0]),
        isUDP
    };
}

// ============================================
// TROJAN PARSER (Strict SHA-224)
// ============================================
async function processTrojanHeader(buffer, userID) {
    if (buffer.byteLength < 56) return { hasError: true, message: "Invalid Trojan data" };

    const passwordBuffer = new Uint8Array(buffer.slice(0, 56));
    const passwordHex = Array.from(passwordBuffer).map((b) => b.toString(16).padStart(2, "0")).join("");
    const expectedHex = await sha224(userID);

    if (passwordHex !== expectedHex) return { hasError: true, message: "Invalid Trojan password" };

    let cursor = 56;
    if (new Uint8Array(buffer.slice(cursor, cursor + 2)).join(",") !== "13,10") return { hasError: true, message: "Invalid Trojan CRLF" };
    cursor += 2;

    const addressType = new Uint8Array(buffer.slice(cursor, cursor + 1))[0];
    cursor += 1;
    let addressRemote = "";
    let addressLength = 0;

    switch (addressType) {
        case 1:
            addressLength = 4;
            addressRemote = new Uint8Array(buffer.slice(cursor, cursor + addressLength)).join(".");
            break;
        case 3:
            addressLength = new Uint8Array(buffer.slice(cursor, cursor + 1))[0];
            cursor += 1;
            addressRemote = new TextDecoder().decode(buffer.slice(cursor, cursor + addressLength));
            break;
        case 4:
            addressLength = 16;
            const dataView = new DataView(buffer.slice(cursor, cursor + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
            addressRemote = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `Invalid Trojan address type` };
    }

    cursor += addressLength;
    const portRemote = new DataView(buffer.slice(cursor, cursor + 2)).getUint16(0);
    cursor += 4;

    return {
        hasError: false,
        addressRemote,
        addressType,
        portRemote,
        rawDataIndex: cursor,
        responseHeader: new Uint8Array([0]),
        isUDP: false
    };
}

// ============================================
// PURE SHA-224 (Strict Trojan Spec)
// ============================================
async function sha224(str) {
    function rightRotate(value, amount) { return (value >>> amount) | (value << (32 - amount)); }
    const mathPow = Math.pow; const maxWord = mathPow(2, 32); let result = '';
    const words = []; const asciiBitLength = str.length * 8;
    let hash = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
    const k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    let s = str + '\x80';
    while (s.length % 64 - 56) s += '\x00';
    for (let i = 0; i < s.length; i++) {
        const j = s.charCodeAt(i);
        words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words.length] = ((asciiBitLength / maxWord) | 0);
    words[words.length] = (asciiBitLength);
    for (let j = 0; j < words.length;) {
        const w = words.slice(j, j += 16);
        const oldHash = hash.slice(0);
        for (let i = 0; i < 64; i++) {
            if (i >= 16) {
                const w15 = w[i - 15], w2 = w[i - 2];
                w[i] = (w[i - 16] + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) +
                    w[i - 7] + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))) | 0;
            }
            const a = hash[0], e = hash[4];
            const temp1 = (hash[7] + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) +
                ((e & hash[5]) ^ (~e & hash[6])) + k[i] + w[i]);
            const temp2 = ((rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) +
                ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2])));
            hash = [(temp1 + temp2) | 0].concat(hash);
            hash[4] = (hash[4] + temp1) | 0;
            hash.pop();
        }
        for (let i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
    }
    for (let i = 0; i < 7; i++) {
        const hex = hash[i];
        result += ((hex >> 28) & 0xf).toString(16) + ((hex >> 24) & 0xf).toString(16) + ((hex >> 20) & 0xf).toString(16) +
            ((hex >> 16) & 0xf).toString(16) + ((hex >> 12) & 0xf).toString(16) + ((hex >> 8) & 0xf).toString(16) +
            ((hex >> 4) & 0xf).toString(16) + (hex & 0xf).toString(16);
    }
    return result;
}

// ============================================
// SUBSCRIPTION GENERATORS (/sub)
// ============================================
function generateSubscription(userID, hostName, wsPath) {
    let sub = "";
    const encodedPath = encodeURIComponent(`${wsPath}?ed=2048`);
    
    // NoTLS Ports (80, 8080, etc)
    for (const port of NOTLS_PORTS) {
        sub += `vless://${userID}@${hostName}:${port}?encryption=none&security=none&type=ws&host=${hostName}&path=${encodedPath}#VLESS-NoTLS-${port}\n`;
        sub += `trojan://${userID}@${hostName}:${port}?security=none&type=ws&host=${hostName}&path=${encodedPath}#Trojan-NoTLS-${port}\n`;
    }

    // TLS Ports (443, 8443, etc)
    for (const port of TLS_PORTS) {
        sub += `vless://${userID}@${hostName}:${port}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=${encodedPath}#VLESS-TLS-${port}\n`;
        sub += `trojan://${userID}@${hostName}:${port}?security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=${encodedPath}#Trojan-TLS-${port}\n`;
    }

    return btoa(sub); // Base64 encoded for v2rayN/Nekobox
}

function generateClashConfig(userID, hostName, wsPath) {
    let proxies = "";
    let names = [];

    // Clash YAML for NoTLS Ports
    for (const port of NOTLS_PORTS) {
        names.push(`VLESS-NoTLS-${port}`);
        proxies += `  - {name: "VLESS-NoTLS-${port}", server: ${hostName}, port: ${port}, type: vless, uuid: ${userID}, network: ws, tls: false, udp: false, ws-opts: {path: "${wsPath}?ed=2048", headers: {Host: ${hostName}}}}\n`;
    }
    // Clash YAML for TLS Ports
    for (const port of TLS_PORTS) {
        names.push(`VLESS-TLS-${port}`);
        proxies += `  - {name: "VLESS-TLS-${port}", server: ${hostName}, port: ${port}, type: vless, uuid: ${userID}, network: ws, tls: true, sni: ${hostName}, client-fingerprint: chrome, udp: false, ws-opts: {path: "${wsPath}?ed=2048", headers: {Host: ${hostName}}}}\n`;
    }

    return `proxies:\n${proxies}proxy-groups:\n  - {name: "Auto", type: url-test, proxies: [${names.map(n => `"${n}"`).join(", ")}], url: "http://www.gstatic.com/generate_204", interval: 86400}\n`;
}

// ============================================
// HELPER FUNCTIONS
// ============================================
async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
    let header = responseHeader;
    let hasData = false;
    await remoteSocket.readable.pipeTo(new WritableStream({
        async write(chunk, controller) {
            hasData = true;
            if (webSocket.readyState !== 1) controller.error("WS closed");
            if (header) { webSocket.send(await new Blob([header, chunk]).arrayBuffer()); header = null; } 
            else { webSocket.send(chunk); }
        },
        close() { log(`Remote closed`); },
        abort() { log("Remote abort"); }
    })).catch(() => safeCloseWebSocket(webSocket));
    if (!hasData && retry) retry();
}

function makeReadableWebSocketStream(ws, earlyDataHeader, log) {
    let cancel = false;
    return new ReadableStream({
        start(controller) {
            ws.addEventListener("message", (e) => { if (!cancel) controller.enqueue(e.data); });
            ws.addEventListener("close", () => { safeCloseWebSocket(ws); if (!cancel) controller.close(); });
            ws.addEventListener("error", (err) => { log("WS Error"); controller.error(err); });
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) controller.error(error); else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() { cancel = true; safeCloseWebSocket(ws); }
    });
}

async function handleUDPOutBound(ws, responseHeader, log) {
    let sent = false;
    const ts = new TransformStream({
        transform(chunk, ctrl) {
            for (let i = 0; i < chunk.byteLength;) {
                const len = new DataView(chunk.slice(i, i + 2)).getUint16(0);
                ctrl.enqueue(new Uint8Array(chunk.slice(i + 2, i + 2 + len)));
                i += 2 + len;
            }
        }
    });
    ts.readable.pipeTo(new WritableStream({
        async write(chunk) {
            const resp = await fetch(dohURL, { method: "POST", headers: { "content-type": "application/dns-message" }, body: chunk });
            const buf = await resp.arrayBuffer();
            const sz = new Uint8Array([buf.byteLength >> 8 & 255, buf.byteLength & 255]);
            if (ws.readyState === 1) {
                if (sent) ws.send(await new Blob([sz, buf]).arrayBuffer());
                else { ws.send(await new Blob([responseHeader, sz, buf]).arrayBuffer()); sent = true; }
            }
        }
    })).catch(() => log("UDP err"));
    const writer = ts.writable.getWriter();
    return { write: (chunk) => writer.write(chunk) };
}

function base64ToArrayBuffer(b64) {
    if (!b64) return { earlyData: null, error: null };
    try {
        const dec = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
        return { earlyData: Uint8Array.from(dec, (c) => c.charCodeAt(0)).buffer, error: null };
    } catch (e) { return { earlyData: null, error: e }; }
}

const byteToHex = []; for (let i = 0; i < 256; ++i) byteToHex.push((i + 256).toString(16).slice(1));
function stringify(arr) {
    return (byteToHex[arr[0]] + byteToHex[arr[1]] + byteToHex[arr[2]] + byteToHex[arr[3]] + "-" +
        byteToHex[arr[4]] + byteToHex[arr[5]] + "-" + byteToHex[arr[6]] + byteToHex[arr[7]] + "-" +
        byteToHex[arr[8]] + byteToHex[arr[9]] + "-" + byteToHex[arr[10]] + byteToHex[arr[11]] + 
        byteToHex[arr[12]] + byteToHex[arr[13]] + byteToHex[arr[14]] + byteToHex[arr[15]]).toLowerCase();
}
function isValidUUID(id) { return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id); }
function safeCloseWebSocket(ws) { try { if (ws.readyState === 1 || ws.readyState === 2) ws.close(); } catch (e) {} }

// ============================================
// GALAXY UI
// ============================================
function getGalaxyUI(userID, hostName, proxyIP, wsPath) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Galaxy-Tunnel Ultimate</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #02060d; color: #fff; font-family: 'Segoe UI', Arial, sans-serif; overflow-x: hidden; }
    .space-bg { position: fixed; width: 100%; height: 100%; z-index: -2; background: radial-gradient(circle at 50% 35%, rgba(10, 45, 80, 0.7) 0%, transparent 65%), #02060d; }
    .starfield { position: fixed; width: 100%; height: 100%; z-index: -1; background-image: radial-gradient(2px 2px at 20px 30px, #fff, rgba(0,0,0,0)), radial-gradient(2px 2px at 40px 70px, rgba(0,212,255,0.8), rgba(0,0,0,0)); background-size: 220px 220px; animation: twinkle 4s infinite alternate; opacity: 0.6; }
    @keyframes twinkle { 0% { opacity: 0.4; } 100% { opacity: 0.8; } }
    .container { max-width: 800px; margin: 40px auto; padding: 20px; }
    .card { background: rgba(4, 12, 24, 0.75); border: 1px solid rgba(0, 212, 255, 0.4); box-shadow: 0 0 20px rgba(0, 212, 255, 0.1); border-radius: 12px; padding: 30px; backdrop-filter: blur(10px); margin-bottom: 20px; }
    h1 { color: #00f0ff; text-align: center; text-transform: uppercase; letter-spacing: 2px; text-shadow: 0 0 10px rgba(0,240,255,0.5); margin-bottom: 10px; }
    .subtitle { text-align: center; color: #7b93a7; margin-bottom: 30px; font-size: 14px; }
    .status { background: rgba(0,255,136,0.1); border: 1px solid #00ff88; color: #00ff88; padding: 10px; border-radius: 6px; text-align: center; margin-bottom: 20px; }
    .links { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
    @media (max-width: 600px) { .links { grid-template-columns: 1fr; } }
    a.btn { display: block; background: #0a2040; border: 1px solid #00e5ff; color: #00e5ff; text-decoration: none; padding: 12px; text-align: center; border-radius: 6px; font-weight: bold; transition: 0.3s; }
    a.btn:hover { background: #00e5ff; color: #000; box-shadow: 0 0 15px #00e5ff; }
    h2 { color: #fff; font-size: 18px; margin-bottom: 10px; border-bottom: 1px solid #333; padding-bottom: 5px; }
    pre { background: #000; padding: 10px; border-radius: 6px; font-size: 12px; overflow-x: auto; color: #00ff88; border: 1px solid #333; }
    ul { list-style: none; color: #aaa; font-size: 14px; line-height: 1.8; }
    li span { color: #00e5ff; }
  </style>
</head>
<body>
  <div class="space-bg"></div>
  <div class="starfield"></div>
  <div class="container">
    <div class="card">
      <h1>Galaxy-Tunnel Ultimate</h1>
      <div class="subtitle">VLESS + TROJAN • TLS & NOTLS SUPPORTED</div>
      <div class="status">✅ Worker is Online! ProxyIP: ${proxyIP || "Auto-Pool Active"}</div>
      
      <div class="links">
        <a href="/${userID}/sub" class="btn">📋 Copy Subscription (Base64)</a>
        <a href="/${userID}/clash" class="btn">⚔️ Download Clash Config</a>
      </div>
    </div>

    <div class="card">
      <h2>⚙️ Manual Configuration</h2>
      <ul>
        <li>Address: <span>${hostName}</span></li>
        <li>NoTLS Ports: <span>80, 8080, 8880, 2052, 2086, 2095</span></li>
        <li>TLS Ports: <span>443, 8443, 2053, 2096, 2087, 2083</span></li>
        <li>VLESS UUID: <span>${userID}</span></li>
        <li>Trojan Password: <span>${userID}</span></li>
        <li>Network: <span>WebSocket (ws)</span></li>
        <li>Path: <span>${wsPath}?ed=2048</span></li>
      </ul>
    </div>

    <div class="card">
      <h2>🔗 Direct Links (Port 8080 NoTLS)</h2>
      <pre>vless://${userID}@${hostName}:8080?encryption=none&security=none&type=ws&host=${hostName}&path=${encodeURIComponent(wsPath + "?ed=2048")}#VLESS-NoTLS-8080</pre>
      <br>
      <pre>trojan://${userID}@${hostName}:8080?security=none&type=ws&host=${hostName}&path=${encodeURIComponent(wsPath + "?ed=2048")}#Trojan-NoTLS-8080</pre>
    </div>
  </div>
</body>
</html>`;
}
