import { Device, defineLesson, note, pkt } from "@/lib/lesson";
import { build, FieldSpec, LayerSpec } from "@/lib/packet";
import { eth, ext, hsMsg, ipv4, tcp, tls, TlsRecord, vec } from "@/lib/proto";

// Two microservices in one data centre network. Captured on the payments host.
const ORD = { ip: "10.0.1.10", mac: "02:42:0a:00:01:0a" };
const PAY = { ip: "10.0.2.20", mac: "02:42:0a:00:02:14" };
const JOB = { ip: "10.0.3.30", mac: "02:42:0a:00:03:1e" };
const GW_MAC = "02:42:0a:00:00:01"; // the data centre router between subnets
const t = (n: number) => Number(n.toFixed(4));
const size = (spec: LayerSpec) => build(spec).bytes.length;

function conn(cli: { ip: string; mac: string }, sport: number, cBase: number, sBase: number) {
  let c = 0;
  let s = 0;
  const seg = (fromClient: boolean, flags: string, payload?: LayerSpec) => {
    const len = payload ? size(payload) : 0;
    const seq = fromClient ? c : s;
    const ack = fromClient ? s : c;
    const hasAck = flags.includes("A");
    const spec = tcp({
      sport: fromClient ? sport : 8443, dport: fromClient ? 8443 : sport, seq, ack: hasAck ? ack : 0, flags, win: 501,
      seqBase: fromClient ? cBase : sBase, ackBase: hasAck ? (fromClient ? sBase : cBase) : undefined,
    });
    const adv = len + (flags.includes("S") ? 1 : 0) + (flags.includes("F") ? 1 : 0);
    if (fromClient) c += adv; else s += adv;
    const l2 = fromClient
      ? [eth({ src: GW_MAC, dst: PAY.mac }), ipv4({ src: cli.ip, dst: PAY.ip, ttl: 63 })]
      : [eth({ src: PAY.mac, dst: GW_MAC }), ipv4({ src: PAY.ip, dst: cli.ip, ttl: 64 })];
    return { packet: build(...l2, spec, ...(payload ? [payload] : [])), seq, ack, len };
  };
  return { up: (f: string, p?: LayerSpec) => seg(true, f, p), down: (f: string, p?: LayerSpec) => seg(false, f, p) };
}

const u16v = (name: string, code: number, label: string, note?: string): FieldSpec => ({ name, u16: code, value: `${label} (0x${code.toString(16).padStart(4, "0")})`, note });
const enc = (plain: number, what: string, note: string): TlsRecord => ({ type: "appdata", encrypted: plain + 1 + 16, what, note });
const ccs: TlsRecord = { type: "ccs", fields: [{ name: "Change cipher spec message", u8: 1, note: "Dummy record in TLS 1.3, for middlebox compatibility." }] };

const clientHello = (seed: number) =>
  hsMsg("client_hello", "Client Hello", [
    { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)" },
    { name: "Random", random: 32, seed },
    vec("Legacy session ID", 1, [{ name: "Session ID", random: 32, seed: seed + 1 }], "32 bytes"),
    vec("Cipher suites", 2, [u16v("Cipher suite", 0x1301, "TLS_AES_128_GCM_SHA256"), u16v("Cipher suite", 0x1302, "TLS_AES_256_GCM_SHA384")], "2 suites", "Internal services can be strict: TLS 1.3 suites only."),
    vec("Compression methods", 1, [{ name: "Method", u8: 0, value: "null (0)" }], "null"),
    vec("Extensions", 2, [
      ext(0, "server_name", [vec("Server name list", 2, [{ name: "Name type", u8: 0, value: "host_name (0)" }, vec("Host name", 2, [{ name: "Name", text: "payments.internal" }], "payments.internal")])], "payments.internal"),
      ext(10, "supported_groups", [vec("Named groups", 2, [u16v("Group", 0x001d, "x25519"), u16v("Group", 0x0017, "secp256r1")])], "x25519, secp256r1"),
      ext(13, "signature_algorithms", [vec("Algorithms", 2, [u16v("Algorithm", 0x0403, "ecdsa_secp256r1_sha256"), u16v("Algorithm", 0x0804, "rsa_pss_rsae_sha256")])], "2 algorithms"),
      ext(16, "application_layer_protocol_negotiation", [vec("Protocol list", 2, [vec("Protocol", 1, [{ name: "Name", text: "h2" }], "h2")])], "h2", "gRPC runs over HTTP/2."),
      ext(43, "supported_versions", [vec("Versions", 1, [u16v("Version", 0x0304, "TLS 1.3")])], "TLS 1.3 only"),
      ext(51, "key_share", [vec("Client key shares", 2, [u16v("Group", 0x001d, "x25519"), vec("Key exchange", 2, [{ name: "Public key", random: 32, seed: seed + 2 }], "32 bytes")])], "x25519, 32 bytes"),
    ], "6 extensions"),
  ]);

const serverHello = (seed: number) =>
  hsMsg("server_hello", "Server Hello", [
    { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)" },
    { name: "Random", random: 32, seed: seed + 10 },
    vec("Legacy session ID", 1, [{ name: "Session ID", random: 32, seed: seed + 1, note: "Echo of the client's." }], "echo"),
    u16v("Cipher suite", 0x1301, "TLS_AES_128_GCM_SHA256"),
    { name: "Compression method", u8: 0, value: "null (0)" },
    vec("Extensions", 2, [
      ext(43, "supported_versions", [u16v("Selected version", 0x0304, "TLS 1.3")], "TLS 1.3"),
      ext(51, "key_share", [u16v("Group", 0x001d, "x25519"), vec("Key exchange", 2, [{ name: "Public key", random: 32, seed: seed + 11 }], "32 bytes")], "x25519"),
    ], "2 extensions"),
  ]);

// plaintext sizes (handshake header included)
const EE = 15;
const CR = 4 + 1 + 2 + (4 + 2 + 4) + (4 + 2 + 2 + 58); // context, sig algs, certificate_authorities (one DN)
const SCERT = 4 + 1 + 3 + (3 + 520 + 2) + (3 + 430 + 2); // leaf + internal intermediate
const CCERT = 4 + 1 + 3 + (3 + 500 + 2) + (3 + 430 + 2);
const CV = 4 + 2 + 2 + 71;
const FIN = 4 + 32;

const serverFlight = (seed: number): LayerSpec =>
  tls({
    records: [
      { type: "handshake", fields: [serverHello(seed)] }, ccs,
      enc(EE, "EncryptedExtensions (encrypted)", "Inside: ALPN = h2."),
      enc(CR, "CertificateRequest (encrypted)", "Inside: 'send me your certificate'. Lists accepted signature algorithms and the one CA it trusts: CN=Acme Internal Services CA."),
      enc(SCERT, "Certificate (encrypted)", "Inside: payments' certificate (SAN spiffe://acme.internal/ns/prod/sa/payments) and the internal intermediate CA."),
      enc(CV, "CertificateVerify (encrypted)", "Inside: payments' signature over the handshake."),
      enc(FIN, "Finished (encrypted)", "Inside: the server's Finished MAC."),
    ],
    summary: "TLS: Server Hello, Change Cipher Spec, Application Data x5",
  });

const devices: Device[] = [
  { id: "orders", kind: "server", label: "orders service", sub: ORD.ip, x: 10, y: 62 },
  { id: "router", kind: "router", label: "DC router", sub: "10.0.0.1", x: 50, y: 62 },
  { id: "payments", kind: "server", label: "payments service", sub: PAY.ip, x: 90, y: 62 },
  { id: "ca", kind: "auth", label: "Internal CA", sub: "10.0.9.5", x: 50, y: 20 },
];
const links: [string, string][] = [["orders", "router"], ["router", "payments"], ["router", "ca"]];
const jobDevices: Device[] = [...devices, { id: "job", kind: "desktop", label: "old batch job", sub: JOB.ip, x: 12, y: 24 }];
const jobLinks: [string, string][] = [...links, ["job", "router"]];

// ---------------------------------------------------------------- normal
const a = conn(ORD, 40112, 0x10a00000, 0x20b00000);
const ch = a.up("PA", tls({ records: [{ type: "handshake", version: 0x0301, fields: [clientHello(500)] }], summary: "TLS 1.3 Client Hello" }));
const sf = a.down("PA", serverFlight(500));
const cf = a.up("PA", tls({
  records: [
    ccs,
    enc(CCERT, "Certificate (encrypted)", "Inside: the orders service's certificate (SAN spiffe://acme.internal/ns/prod/sa/orders) and the intermediate CA."),
    enc(CV, "CertificateVerify (encrypted)", "Inside: a signature with the orders service's private key over the whole handshake."),
    enc(FIN, "Finished (encrypted)", "Inside: the client's Finished MAC."),
  ],
  summary: "TLS: Change Cipher Spec, Application Data x3 (client Certificate, CertificateVerify, Finished)",
}));
const rq = a.up("PA", tls({ records: [enc(24 + 27 + 92 + 9 + 48, "gRPC request (encrypted)", "Inside: HTTP/2 HEADERS for POST /payments.v1.Payments/Charge and a DATA frame with the protobuf message (order 8812, 499.00 INR).")], summary: "TLS: Application Data" }));
const rs = a.down("PA", tls({ records: [enc(9 + 40 + 9 + 22 + 9 + 30, "gRPC response (encrypted)", "Inside: HEADERS :status 200, DATA with the result (charge approved) and trailers grpc-status: 0.")], summary: "TLS: Application Data" }));

// ---------------------------------------------------------------- no client certificate
const j = conn(JOB, 51877, 0x30c00000, 0x40d00000);
const chJ = j.up("PA", tls({ records: [{ type: "handshake", version: 0x0301, fields: [clientHello(600)] }], summary: "TLS 1.3 Client Hello" }));
const sfJ = j.down("PA", serverFlight(600));
const cfJ = j.up("PA", tls({
  records: [
    ccs,
    enc(4 + 1 + 3, "Certificate (encrypted)", "Inside: a Certificate message with an empty list (8 bytes). The job has no certificate to give."),
    enc(FIN, "Finished (encrypted)", "Inside: the client's Finished. No CertificateVerify, because there is no key to sign with."),
  ],
  summary: "TLS: Change Cipher Spec, Application Data x2 (empty Certificate, Finished)",
}));
const alJ = j.down("PA", tls({ records: [enc(2, "Alert (encrypted)", "Inside: level 2 (fatal), description 116 (certificate_required). Bytes 02 74, then inner type 0x15.")], summary: "TLS: Application Data (Alert: certificate_required)" }));
const finJ = j.down("FA");

export default defineLesson({
  id: "mtls",
  name: "mTLS",
  full: "Mutual TLS (client certificate authentication)",
  group: "security",
  layer: 6,
  difficulty: 3,
  tagline: "Both sides show a certificate: zero-trust between services.",
  description:
    "In normal TLS only the server proves who it is. In mutual TLS the server also asks the client for a certificate, so both ends are verified against a CA they trust. Service meshes and internal APIs use it so a service only talks to services it can identify.",
  facts: [
    ["Layer", "Between TCP and the app (5–6)"],
    ["Built on", "TLS 1.3 / 1.2"],
    ["Extra messages", "CertificateRequest, client Certificate"],
    ["Trust", "Usually a private, internal CA"],
    ["Common in", "Service meshes, banking APIs, IoT"],
    ["Defined in", "RFC 8446 §4.3.2, §4.4.2"],
  ],
  ports: "Any TLS port; here 8443",
  rfc: "RFC 8446",
  keywords: ["mutual tls", "client certificate", "zero trust", "service mesh", "spiffe", "istio", "certificate request", "certificate_required", "116"],
  related: ["tls", "tcp", "oauth", "kerberos"],
  devices,
  links,
  legend: [
    ["blue", "TLS hellos (clear text)"],
    ["teal", "Encrypted handshake, certificates"],
    ["amber", "Request from the client service"],
    ["violet", "Response from the server service"],
    ["red", "Alert"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "orders calls payments over mTLS",
      summary: "Both services hold certificates from the internal CA and verify each other before any gRPC call.",
      kind: "normal",
      steps: [
        {
          title: "Certificates in advance",
          desc: "The internal CA issued both identities",
          detail: "Earlier, the internal CA gave each service a short-lived certificate, valid for 24 hours. Its name is a URI like spiffe://acme.internal/ns/prod/sa/orders. Both services trust only this CA. The TCP connection to port 8443 is already open.",
          facts: [["CA", "Acme Internal Services CA"], ["Certificate life", "24 hours, auto-renewed"], ["Identity", "SPIFFE ID in the SAN"]],
          events: [
            note("ca", "ISSUED BOTH CERTS", "blue"),
            pkt("orders", "payments", "blue", "CLIENT HELLO", ["SNI payments.internal", "TLS 1.3 only"], { time: 0, info: "Client Hello (SNI=payments.internal)", packet: ch.packet }),
          ],
        },
        {
          title: "Server asks for a cert",
          desc: "CertificateRequest inside the encrypted flight",
          detail: "The payments service answers like any TLS 1.3 server, with one extra encrypted message: CertificateRequest. It lists the signature algorithms it accepts and the CA names it trusts, so the client knows which certificate to pick.",
          facts: [["New message", "CertificateRequest (type 13)"], ["Trusted CA", "CN=Acme Internal Services CA"], ["Encrypted", "Yes, like the rest of the flight"]],
          quiz: {
            q: "Which message tells the client it must prove its identity too?",
            options: ["ServerHello", "CertificateRequest", "NewSessionTicket", "EncryptedExtensions"],
            answer: 1,
            why: "Without CertificateRequest the client never sends a certificate. Its presence is the whole difference between TLS and mTLS.",
          },
          events: [pkt("payments", "orders", "teal", "HELLO + REQ", ["Server Hello", "CertificateRequest"], { time: 0.0004, info: "Server Hello, Change Cipher Spec, Application Data", packet: sf.packet })],
        },
        {
          title: "Client proves itself",
          desc: "Certificate, CertificateVerify, Finished",
          detail: "The orders service first checks the server's certificate. Then it sends its own Certificate, a CertificateVerify signed with its private key over the whole handshake, and Finished. The signature is what matters: a stolen certificate file alone is useless without the key.",
          facts: [["Client cert", "spiffe://…/sa/orders"], ["Signature", "ECDSA P-256"], ["Sent", "Encrypted"]],
          quiz: {
            q: "An attacker copied the orders certificate (public) but not its private key. What fails?",
            options: ["Nothing, the certificate is enough", "CertificateVerify, because it can't sign", "The ServerHello", "The TCP handshake"],
            answer: 1,
            why: "CertificateVerify needs a signature with the private key over this exact handshake. Without the key it can't be made.",
          },
          events: [pkt("orders", "payments", "teal", "CLIENT CERT", ["Certificate + Verify", "Finished"], { time: 0.0009, info: "Change Cipher Spec, Application Data", packet: cf.packet })],
        },
        {
          title: "Verified both ways",
          desc: "Server checks the chain, then the call runs",
          detail: "The payments service checks the client chain up to the internal CA, the dates, and the SPIFFE ID against its policy: only the orders service may call Charge. Then the gRPC request and reply travel inside the tunnel. Each side now knows exactly who is on the other end.",
          facts: [["Chain", "Valid to internal CA"], ["Policy", "orders may call Charge"], ["Call", "POST /payments.v1.Payments/Charge"]],
          events: [
            note("payments", "CLIENT = orders ✓", "green"),
            pkt("orders", "payments", "amber", "CHARGE", ["gRPC request"], { time: 0.001, info: "Application Data (gRPC)", packet: rq.packet }),
            pkt("payments", "orders", "violet", "OK", ["charge approved"], { time: 0.0031, info: "Application Data (gRPC)", packet: rs.packet }),
          ],
        },
      ],
      outro: {
        title: "Mutual trust, no passwords",
        text: "With one extra message from the server and three from the client, both services proved their identity with keys and certificates from the internal CA. No API keys or passwords cross the network, and certificates renew themselves daily.",
        facts: [["Server proved", "Certificate + signature"], ["Client proved", "Certificate + signature"], ["Round trips", "Still 1"], ["Secrets sent", "None"]],
      },
    },
    {
      id: "no-cert",
      name: "Client without a certificate",
      summary: "An old batch job connects with plain TLS habits; payments demands a certificate and closes the door.",
      kind: "failure",
      devices: jobDevices,
      links: jobLinks,
      steps: [
        {
          title: "A plain TLS client",
          desc: "The batch job was never given a certificate",
          detail: "An old reporting job tries to call payments. It speaks TLS 1.3 perfectly well, but nobody set up a certificate for it. Its Client Hello looks normal.",
          facts: [["Client", `old batch job, ${JOB.ip}`], ["Certificate", "None"], ["Target", "payments:8443"]],
          events: [pkt("job", "payments", "blue", "CLIENT HELLO", ["SNI payments.internal"], { time: 0, info: "Client Hello (SNI=payments.internal)", packet: chJ.packet })],
        },
        {
          title: "Certificate requested",
          desc: "Same server flight with CertificateRequest",
          detail: "The payments service sends its usual flight, including CertificateRequest. The job checks the server's certificate and is happy with it.",
          facts: [["Server cert", "Valid"], ["CertificateRequest", "Sent"], ["Client has", "Nothing to send"]],
          events: [pkt("payments", "job", "teal", "HELLO + REQ", ["CertificateRequest"], { time: 0.0004, info: "Server Hello, Change Cipher Spec, Application Data", packet: sfJ.packet })],
        },
        {
          title: "An empty Certificate",
          desc: "The rules say: answer anyway, with nothing",
          detail: "TLS 1.3 says a client asked for a certificate must still send a Certificate message, even if the list is empty. The job does that, skips CertificateVerify, and sends Finished.",
          facts: [["Certificate list", "Empty (0 certs)"], ["CertificateVerify", "Not sent"], ["Finished", "Sent"]],
          quiz: {
            q: "The server requires client certificates and receives an empty list. What happens next?",
            options: ["It continues without checking", "It sends a fatal alert and closes", "It asks again with a second CertificateRequest", "It falls back to a password prompt"],
            answer: 1,
            why: "A server configured to require client authentication must abort. TLS 1.3 has a dedicated alert for exactly this case.",
          },
          events: [pkt("job", "payments", "teal", "EMPTY CERT", ["0 certificates", "Finished"], { time: 0.0009, info: "Change Cipher Spec, Application Data", packet: cfJ.packet })],
        },
        {
          title: "Alert 116",
          desc: "certificate_required, then close",
          detail: "The payments service sends a fatal alert 116, certificate_required, and closes the connection. Since keys exist by now, the alert is encrypted and looks like a 24-byte Application Data record on the wire. The job's logs show a TLS error and the call never reaches the Charge code.",
          facts: [["Alert", "116 certificate_required"], ["Level", "2 (fatal)"], ["Added in", "TLS 1.3"]],
          events: [
            pkt("payments", "job", "red", "ALERT 116", ["certificate_required"], { time: 0.001, info: "Application Data (Alert: certificate_required)", packet: alJ.packet }),
            pkt("payments", "job", "slate", "FIN", [], { time: 0.0011, info: `8443 → 51877 [FIN, ACK] Seq=${finJ.seq} Ack=${finJ.ack} Len=0`, packet: finJ.packet }),
            note("payments", "NO CERT, NO ENTRY", "red"),
          ],
        },
      ],
      outro: {
        title: "Blocked before any request",
        text: "Because payments requires mutual TLS, a client without a certificate is stopped during the handshake. The fix is not to relax the server but to give the job its own identity from the internal CA.",
        facts: [["Alert", "116 certificate_required"], ["TLS 1.2 equivalent", "40 handshake_failure"], ["Wrong CA instead", "48 unknown_ca"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Extra messages in mTLS",
      items: [["CertificateRequest (13)", "Server asks for a client cert"], ["Certificate (11)", "Client's chain (may be empty)"], ["CertificateVerify (15)", "Client's signature over the handshake"]],
    },
    {
      title: "Alerts",
      items: [["116 certificate_required", "No client cert (TLS 1.3)"], ["48 unknown_ca", "Signed by a CA the server doesn't trust"], ["45 certificate_expired", "Client cert out of date"], ["42 bad_certificate", "Corrupt or wrong cert"]],
    },
    {
      title: "In practice",
      items: [["Service meshes", "Istio, Linkerd: automatic mTLS"], ["SPIFFE ID", "spiffe://trust-domain/path"], ["Cert lifetime", "Hours to days, auto-rotated"], ["nginx", "ssl_verify_client on"]],
    },
  ],
});
