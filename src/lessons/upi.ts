import { defineLesson, Device, note, pkt, PacketEvent } from "@/lib/lesson";
import { build, LayerSpec } from "@/lib/packet";
import { eth, ipv4, tcp, tls } from "@/lib/proto";

// A simplified, illustrative model of the public UPI architecture. Hostnames, addresses,
// sizes and message contents are made up for teaching; this is not real API traffic.

// ---------------------------------------------------------------- the cast

interface Node { ip: string; mac: string; host: string }
const N: Record<string, Node> = {
  phone: { ip: "198.51.100.23", mac: "f4:5c:89:3a:20:7d", host: "phone" },
  pspA: { ip: "203.0.113.50", mac: "00:16:3e:a0:00:50", host: "psp-a.example" },
  sw: { ip: "203.0.113.80", mac: "00:16:3e:a0:00:80", host: "upi-switch.example" },
  payer: { ip: "192.0.2.30", mac: "00:16:3e:b0:00:30", host: "payer-bank.example" },
  payee: { ip: "192.0.2.60", mac: "00:16:3e:b0:00:60", host: "payee-bank.example" },
  shop: { ip: "198.51.100.88", mac: "02:00:5e:10:00:88", host: "soundbox" },
  scam: { ip: "198.51.100.66", mac: "02:00:5e:66:66:66", host: "scammer" },
  scamPsp: { ip: "203.0.113.90", mac: "00:16:3e:a0:00:90", host: "psp-x.example" },
};

// ---------------------------------------------------------------- HTTPS legs over already-open TLS connections

const FLAG_TXT: Record<string, string> = { S: "SYN", A: "ACK", P: "PSH", F: "FIN", R: "RST" };

/** One long-lived HTTPS connection between a client and a server; records are sent as TLS application data. */
function leg(client: Node, server: Node, sport: number, cBase: number, sBase: number) {
  let cs = 1, ss = 1, idC = 0x2200, idS = 0x6100;
  const go = (fromClient: boolean, records: { n: number; what: string }[]) => {
    const payload: LayerSpec = tls({ records: records.map((r) => ({ type: "appdata" as const, encrypted: r.n, what: r.what })) });
    const len = build(payload).bytes.length;
    const [a, b] = fromClient ? [client, server] : [server, client];
    const seq = fromClient ? cs : ss, ack = fromClient ? ss : cs;
    const packet = build(
      eth({ src: a.mac, dst: b.mac }),
      ipv4({ src: a.ip, dst: b.ip, ttl: 64, id: fromClient ? idC++ : idS++ }),
      tcp({ sport: fromClient ? sport : 443, dport: fromClient ? 443 : sport, seq, ack, flags: "PA", win: 1024, seqBase: fromClient ? cBase : sBase, ackBase: fromClient ? sBase : cBase }),
      payload
    );
    if (fromClient) cs += len; else ss += len;
    const info = `${fromClient ? sport : 443} → ${fromClient ? 443 : sport} [${["P", "A"].map((f) => FLAG_TXT[f]).join(", ")}] Seq=${seq} Ack=${ack} Len=${len}  Application Data`;
    return { packet, info };
  };
  return {
    req: (n: number, what: string) => go(true, [{ n, what }]),
    resp: (n: number, what: string) => go(false, [{ n, what }]),
  };
}

type Leg = ReturnType<typeof leg>;
const send = (l: Leg, dir: "req" | "resp", from: string, to: string, color: PacketEvent["color"], label: string, lines: string[], time: number, n: number, what: string, extra: Partial<PacketEvent> = {}): PacketEvent => {
  const r = l[dir](n, what);
  return pkt(from, to, color, label, lines, { time, info: `${what}: ${r.info}`, packet: r.packet, ...extra });
};

// each scenario gets fresh connections so sequence numbers start clean
const legs = () => ({
  app: leg(N.phone, N.pspA, 52144, 0x1a2b0000, 0x3c4d0000),
  pspSw: leg(N.pspA, N.sw, 40110, 0x5e6f0000, 0x70810000),
  swPayer: leg(N.sw, N.payer, 41220, 0x92a30000, 0xb4c50000),
  swPayee: leg(N.sw, N.payee, 41330, 0xd6e70000, 0xf8090000),
  payeeShop: leg(N.payee, N.shop, 43001, 0x0a1b0000, 0x2c3d0000),
});

// ---------------------------------------------------------------- devices

const devices: Device[] = [
  { id: "phone", kind: "phone", label: "Your phone", sub: "UPI app", x: 7, y: 60 },
  { id: "pspA", kind: "bank", label: "Payer PSP", sub: N.pspA.host, x: 27, y: 25 },
  { id: "switch", kind: "server", label: "UPI switch", sub: N.sw.host, x: 50, y: 60 },
  { id: "payer", kind: "bank", label: "Your bank", sub: N.payer.host, x: 73, y: 25 },
  { id: "payee", kind: "bank", label: "Shop’s bank (payee PSP)", sub: N.payee.host, x: 73, y: 82 },
  { id: "shop", kind: "iot", label: "Shop soundbox", sub: "chai.shop@payeebank", x: 93, y: 55 },
];
const links: [string, string][] = [["phone", "pspA"], ["pspA", "switch"], ["switch", "payer"], ["switch", "payee"], ["payee", "shop"]];

const scamDevices: Device[] = [
  { id: "phone", kind: "phone", label: "Your phone", sub: "UPI app", x: 7, y: 60 },
  { id: "pspA", kind: "bank", label: "Your PSP", sub: N.pspA.host, x: 27, y: 25 },
  { id: "switch", kind: "server", label: "UPI switch", sub: N.sw.host, x: 50, y: 60 },
  { id: "payer", kind: "bank", label: "Your bank", sub: N.payer.host, x: 50, y: 18 },
  { id: "scamPsp", kind: "bank", label: "Scammer’s PSP", sub: N.scamPsp.host, x: 73, y: 25 },
  { id: "attacker", kind: "attacker", label: "“Buyer”", sub: "buyer99@pspx", x: 92, y: 62 },
];
const scamLinks: [string, string][] = [["phone", "pspA"], ["pspA", "switch"], ["switch", "payer"], ["switch", "scamPsp"], ["scamPsp", "attacker"]];

// ---------------------------------------------------------------- shared opening (phone → PSP → switch)

const opening = (L: ReturnType<typeof legs>, t0: number) => [
  note("phone", "₹250 TO chai.shop · PIN ****", "blue"),
  send(L.app, "req", "phone", "pspA", "amber", "ReqPay", ["₹250 → chai.shop", "PIN encrypted"], t0, 912, "ReqPay (PAY) from app"),
  send(L.pspSw, "req", "pspA", "switch", "amber", "ReqPay", ["signed XML", "PIN still sealed"], t0 + 0.12, 1184, "ReqPay (PAY) to switch"),
  send(L.pspSw, "resp", "switch", "pspA", "green", "Ack", ["got it"], t0 + 0.16, 233, "Ack"),
];

const L1 = legs();
const L2 = legs();
const L3 = legs();
const L4 = legs();
const OPEN1 = opening(L1, 0);

export default defineLesson({
  id: "upi",
  name: "UPI",
  full: "Unified Payments Interface (simplified model)",
  group: "india",
  layer: 7,
  difficulty: 2,
  tagline: "What really happens in the two seconds after you pay ₹250 by QR.",
  description:
    "UPI lets any bank app pay any bank account in seconds. Your app talks to its bank (the PSP), which talks to a central UPI switch, which asks your bank to debit and the shop’s bank to credit. Every hop is HTTPS, and your UPI PIN is sealed on the phone so none of the middle hops can read it. This lesson is a simplified teaching model of the public design, not real API traffic.",
  facts: [
    ["Layer", "Application, over HTTPS"],
    ["Messages", "XML: ReqPay / RespPay and friends"],
    ["Two factors", "Device binding + UPI PIN"],
    ["Hub", "Central UPI switch"],
    ["Address", "UPI ID, e.g. name@bank"],
    ["Typical time", "A few seconds end to end"],
  ],
  ports: "TCP 443 (HTTPS) on every leg",
  keywords: ["upi", "npci", "psp", "vpa", "upi id", "qr", "collect request", "upi pin", "reqpay", "resppay", "pending", "reversal", "scam", "india", "payment"],
  related: ["tls", "https", "tcp", "journey"],
  devices,
  links,
  legend: [
    ["amber", "Payment requests"],
    ["violet", "Responses"],
    ["green", "Acks and success"],
    ["blue", "Lookups and status checks"],
    ["red", "Failures and scams"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Pay ₹250 to a shop by QR",
      summary: "You scan the shop’s QR code, enter your PIN, and ₹250 moves from your bank to the shop’s bank through the UPI switch.",
      kind: "normal",
      steps: [
        {
          title: "Scan, check, PIN",
          desc: "The app builds a pay request",
          detail:
            "The QR code holds a link like upi://pay?pa=chai.shop@payeebank&pn=Chai Shop&cu=INR. You type ₹250 and your UPI PIN. The PIN goes into a secure library on the phone that encrypts it straight away with a public key, so even your own UPI app can’t read it. The app sends a pay request over HTTPS to its bank, the payer PSP, which already knows this phone and SIM are registered to you (device binding: factor one; the PIN is factor two).",
          facts: [["Payee", "chai.shop@payeebank"], ["Amount", "₹250.00 INR"], ["Factors", "This phone + PIN"]],
          quiz: {
            q: "Who on the path can read your UPI PIN in plain form?",
            options: ["The UPI app", "Your PSP and the switch", "Only the secure systems that verify it for your bank", "Anyone on the Wi-Fi"],
            answer: 2,
            why: "The PIN is encrypted on the phone before it leaves the secure library. The middle hops just pass the sealed blob along; only the secure hardware that checks PINs for your bank opens it.",
          },
          events: OPEN1.slice(0, 2),
        },
        {
          title: "PSP to the switch",
          desc: "A signed ReqPay, acknowledged at once",
          detail:
            "The PSP checks the request, adds its own details and a digital signature, and forwards a ReqPay message (XML) to the UPI switch over a separate HTTPS connection. UPI is asynchronous: the switch answers immediately with a short Ack meaning “received”, and the real result comes later as RespPay.",
          facts: [["Message", "ReqPay, type PAY"], ["Signed by", "Payer PSP"], ["Immediate reply", "Ack (received, not done)"]],
          events: OPEN1.slice(2),
        },
        {
          title: "Who is chai.shop?",
          desc: "The switch asks the payee’s PSP",
          detail:
            "The switch reads the bank handle after the @ and asks that PSP to resolve the UPI ID (ReqAuthDetails). The shop’s bank confirms the ID is active and returns the account details needed for the credit, plus the merchant name the app showed you. Your app never learns the shop’s account number.",
          facts: [["Request", "ReqAuthDetails"], ["Answer", "RespAuthDetails"], ["Shared with you", "Only the name"]],
          quiz: {
            q: "How does the switch know which PSP to ask about chai.shop@payeebank?",
            options: ["From the part after @, the bank handle", "It asks every bank", "From the shop’s IP address", "Your phone tells it the account number"],
            answer: 0,
            why: "A UPI ID is name@handle, a bit like an email address. The handle maps to one PSP, which owns the lookup for that name.",
          },
          events: [
            send(L1.swPayee, "req", "switch", "payee", "blue", "ReqAuth", ["resolve chai.shop"], 0.3, 640, "ReqAuthDetails"),
            send(L1.swPayee, "resp", "payee", "switch", "violet", "RespAuth", ["active, Chai Shop"], 0.38, 702, "RespAuthDetails"),
          ],
        },
        {
          title: "Debit your account",
          desc: "Your bank checks the PIN and takes ₹250",
          detail:
            "The switch sends a debit ReqPay to your bank, still carrying the sealed PIN. The bank’s secure hardware checks it, confirms you have the balance, and debits ₹250. It answers with RespPay result SUCCESS and a reference number that will appear on both statements.",
          facts: [["Request", "ReqPay (DEBIT)"], ["Checks", "PIN, balance, limits"], ["Result", "SUCCESS + reference no."]],
          quiz: {
            q: "Your bank says SUCCESS. Is the shop paid yet?",
            options: ["Yes, debit and credit happen together", "No, the credit to the shop’s bank is a separate step", "Yes, the PSP pays the shop", "Only after you confirm again"],
            answer: 1,
            why: "Debit and credit are two separate requests to two different banks. That gap is why a payment can occasionally get stuck as pending.",
          },
          events: [
            send(L1.swPayer, "req", "switch", "payer", "amber", "ReqPay", ["DEBIT ₹250", "sealed PIN"], 0.5, 1210, "ReqPay (DEBIT)"),
            note("payer", "PIN OK · −₹250", "green"),
            send(L1.swPayer, "resp", "payer", "switch", "violet", "RespPay", ["DEBIT SUCCESS"], 0.78, 688, "RespPay (DEBIT)"),
          ],
        },
        {
          title: "Credit the shop",
          desc: "The shop’s bank adds ₹250",
          detail:
            "Now the switch sends a credit ReqPay to the shop’s bank, which adds ₹250 to the shop’s account and answers SUCCESS. The bank then pushes a notification to the shop’s soundbox, which announces the payment out loud.",
          facts: [["Request", "ReqPay (CREDIT)"], ["Result", "SUCCESS"], ["Shop hears", "“₹250 received”"]],
          events: [
            send(L1.swPayee, "req", "switch", "payee", "amber", "ReqPay", ["CREDIT ₹250"], 0.9, 1096, "ReqPay (CREDIT)"),
            send(L1.swPayee, "resp", "payee", "switch", "violet", "RespPay", ["CREDIT SUCCESS"], 1.12, 688, "RespPay (CREDIT)"),
            send(L1.payeeShop, "req", "payee", "shop", "green", "NOTIFY", ["₹250 received"], 1.2, 310, "Merchant notification"),
            note("shop", "“₹250 RECEIVED”", "green"),
          ],
        },
        {
          title: "Tell your phone",
          desc: "RespPay flows back the way it came",
          detail:
            "With both legs done, the switch sends the final RespPay to your PSP, which replies to the app. The app shows the green tick with the reference number. Every one of these hops was a TLS-encrypted HTTPS message, so anyone watching the network saw only encrypted records and their sizes.",
          facts: [["Final status", "SUCCESS"], ["Total hops", "8 HTTPS messages + acks"], ["Time", "About 1.5 s"]],
          events: [
            send(L1.pspSw, "resp", "switch", "pspA", "violet", "RespPay", ["SUCCESS", "ref no."], 1.3, 812, "RespPay (PAY)"),
            send(L1.app, "resp", "pspA", "phone", "green", "PAID", ["₹250 to Chai Shop"], 1.42, 540, "Payment result to app"),
            note("phone", "✓ ₹250 PAID", "green"),
          ],
        },
      ],
      outro: {
        title: "₹250 moved in about 1.5 seconds",
        text: "The app asked its PSP, the PSP asked the switch, the switch resolved the shop, debited your bank and credited the shop’s bank, then reported back. Every hop was HTTPS, and your PIN stayed sealed from the phone to the system that checks it.",
        facts: [["Hops", "Phone → PSP → switch → banks"], ["Messages", "ReqPay / RespPay, ReqAuthDetails"], ["Security", "TLS on every leg + sealed PIN"], ["Model", "Simplified, illustrative"]],
      },
    },
    {
      id: "wrong-pin",
      name: "Wrong UPI PIN",
      summary: "You mistype the PIN; your bank rejects the debit and nothing moves.",
      kind: "failure",
      steps: [
        {
          title: "Request with a typo",
          desc: "Same journey, wrong PIN inside",
          detail:
            "You type 1243 instead of 1234. The phone can’t tell: the PIN is sealed before anyone checks it. The request travels through the PSP and the switch exactly like a correct one.",
          facts: [["PIN typed", "Wrong (sealed)"], ["Checked by", "Your bank’s secure systems"], ["Middle hops", "Can’t tell"]],
          events: opening(L2, 0),
        },
        {
          title: "Bank rejects the debit",
          desc: "RespPay FAILURE: incorrect PIN",
          detail:
            "Your bank opens the sealed PIN, finds it doesn’t match, and answers with RespPay result FAILURE and an error code meaning incorrect PIN (for example ZM). No money is debited, so the switch never contacts the shop’s bank. Banks count wrong attempts; after three, UPI payments are usually blocked for about 24 hours.",
          facts: [["Result", "FAILURE (incorrect PIN)"], ["Debited", "Nothing"], ["Limit", "Usually 3 tries, then a 24 h block"]],
          quiz: {
            q: "After the PIN fails, does the switch send a credit request to the shop’s bank?",
            options: ["Yes, then reverses it", "No, the payment stops at the debit", "Yes, credits are sent first", "Only for amounts above ₹2,000"],
            answer: 1,
            why: "The credit leg is only started after a successful debit, so a failed PIN means the shop’s bank is never involved.",
          },
          events: [
            send(L2.swPayer, "req", "switch", "payer", "amber", "ReqPay", ["DEBIT ₹250", "sealed PIN"], 0.5, 1210, "ReqPay (DEBIT)"),
            note("payer", "PIN MISMATCH", "red"),
            send(L2.swPayer, "resp", "payer", "switch", "red", "RespPay", ["FAILURE", "incorrect PIN"], 0.7, 688, "RespPay (DEBIT) FAILURE"),
          ],
        },
        {
          title: "App shows the error",
          desc: "Try again carefully",
          detail:
            "The failure flows back to your PSP and the app, which shows “Incorrect UPI PIN” and lets you retry. Nothing was taken from your account, so there is nothing to refund.",
          facts: [["Final status", "FAILED"], ["Money moved", "None"], ["Next", "Retry or reset PIN"]],
          events: [
            send(L2.pspSw, "resp", "switch", "pspA", "red", "RespPay", ["FAILURE"], 0.82, 760, "RespPay (PAY) FAILURE"),
            send(L2.app, "resp", "pspA", "phone", "red", "FAILED", ["Incorrect UPI PIN"], 0.94, 512, "Payment result to app"),
            note("phone", "INCORRECT UPI PIN", "red"),
          ],
        },
      ],
      outro: {
        title: "Rejected safely",
        text: "Only your bank can check the PIN, so a wrong PIN is caught at the debit step and nothing moves. Too many wrong tries block UPI for a while to stop guessing.",
        facts: [["Caught at", "Your bank"], ["Money moved", "None"], ["Guessing", "Blocked after a few tries"]],
      },
    },
    {
      id: "pending",
      name: "Timeout: pending, then auto-reversal",
      summary: "Your bank debits ₹250 but the shop’s bank doesn’t answer in time; the payment shows pending and the money comes back.",
      kind: "failure",
      steps: [
        {
          title: "Debit succeeds",
          desc: "Your ₹250 has left your account",
          detail: "The first half goes normally: the request reaches the switch and your bank debits ₹250 after checking the PIN.",
          facts: [["Debit", "SUCCESS"], ["Your balance", "−₹250"], ["Next", "Credit the shop"]],
          events: [
            ...opening(L3, 0),
            send(L3.swPayer, "req", "switch", "payer", "amber", "ReqPay", ["DEBIT ₹250"], 0.5, 1210, "ReqPay (DEBIT)"),
            send(L3.swPayer, "resp", "payer", "switch", "violet", "RespPay", ["DEBIT SUCCESS"], 0.78, 688, "RespPay (DEBIT)"),
          ],
        },
        {
          title: "Credit times out",
          desc: "The shop’s bank goes quiet",
          detail:
            "The switch sends the credit request, but the shop’s bank is overloaded and its answer never arrives within the time limit. The switch doesn’t know whether the shop was credited or not, so it can’t call the payment a success or a failure.",
          facts: [["Credit reply", "None in time"], ["Shop credited?", "Unknown"], ["Status", "Deemed / pending"]],
          quiz: {
            q: "Your money left your account but the credit status is unknown. What should the app show?",
            options: ["Success", "Failed", "Pending", "Nothing"],
            answer: 2,
            why: "Saying success might be false, and saying failed might make you pay twice. Pending is the honest answer until the status is confirmed.",
          },
          events: [
            send(L3.swPayee, "req", "switch", "payee", "amber", "ReqPay", ["CREDIT ₹250"], 0.9, 1096, "ReqPay (CREDIT)"),
            send(L3.swPayee, "resp", "payee", "switch", "violet", "RespPay", ["too late"], 1.2, 688, "RespPay (CREDIT)", { lost: true }),
            note("switch", "TIMEOUT", "red"),
          ],
        },
        {
          title: "Phone says pending",
          desc: "Don’t pay twice",
          detail:
            "The switch reports a deemed (pending) status to the PSP and the app shows “Payment pending”. The right move is to wait, not to pay again. The switch and banks will settle what really happened.",
          facts: [["App shows", "Pending"], ["Advice", "Don’t pay again"], ["Shop sees", "Nothing yet"]],
          events: [
            send(L3.pspSw, "resp", "switch", "pspA", "amber", "RespPay", ["PENDING"], 31, 790, "RespPay (PAY) PENDING"),
            send(L3.app, "resp", "pspA", "phone", "amber", "PENDING", ["status unknown"], 31.1, 520, "Payment result to app"),
            note("phone", "⏳ PAYMENT PENDING", "amber"),
          ],
        },
        {
          title: "Check, then reverse",
          desc: "Status check finds no credit; ₹250 comes back",
          detail:
            "Later the switch asks the shop’s bank directly for the transaction’s status (a check-transaction request). The bank confirms the credit never happened, so the switch tells your bank to reverse the debit and the ₹250 returns. RBI rules require this auto-reversal by the next working day (T+1), with compensation if a bank is late.",
          facts: [["Status check", "ReqChkTxn → not credited"], ["Action", "Reversal to your bank"], ["Deadline", "T+1 day (RBI rules)"]],
          quiz: {
            q: "What if the status check had found the shop WAS credited?",
            options: ["Reverse anyway", "Mark the payment SUCCESS", "Charge you again", "Refund the shop"],
            answer: 1,
            why: "Pending only means unknown. If both debit and credit happened, the payment simply becomes a success.",
          },
          events: [
            send(L3.swPayee, "req", "switch", "payee", "blue", "ChkTxn", ["was it credited?"], 120, 520, "ReqChkTxn"),
            send(L3.swPayee, "resp", "payee", "switch", "violet", "RespChkTxn", ["NOT credited"], 120.2, 560, "RespChkTxn"),
            send(L3.swPayer, "req", "switch", "payer", "amber", "REVERSAL", ["+₹250 back"], 120.4, 980, "ReqPay (REVERSAL)"),
            send(L3.swPayer, "resp", "payer", "switch", "green", "RespPay", ["REVERSED"], 120.6, 640, "RespPay (REVERSAL)"),
            note("phone", "₹250 REFUNDED", "green"),
          ],
        },
      ],
      outro: {
        title: "Money back without asking",
        text: "Because debit and credit are separate steps, a timeout in between leaves a payment pending. The switch checks the real status and reverses the debit if the credit never happened, so waiting is safer than paying twice.",
        facts: [["Cause", "No credit reply in time"], ["Status", "Pending (deemed)"], ["Fix", "Status check + auto-reversal"], ["Rule", "Reversal by T+1"]],
      },
    },
    {
      id: "collect-scam",
      name: "Fake collect request scam",
      summary: "A “buyer” sends a collect request pretending it will send you money. Entering your PIN would pay them.",
      kind: "attack",
      devices: scamDevices,
      links: scamLinks,
      steps: [
        {
          title: "The bait",
          desc: "“I’ll send the money, just approve it”",
          detail:
            "You list an old phone for sale. A “buyer” agrees at once and says they’ll send ₹5,000 through UPI; you only need to “accept” it. Real UPI never needs your PIN to receive money. Pay requests from you need a PIN; money coming to you needs nothing.",
          facts: [["Story", "Eager buyer"], ["Ask", "Approve a request"], ["Truth", "Receiving needs no PIN"]],
          events: [note("attacker", "“APPROVE TO RECEIVE ₹5,000”", "red")],
        },
        {
          title: "A collect request arrives",
          desc: "A request for you to pay them",
          detail:
            "A collect request is a normal UPI feature: a payee asks a payer for money, like a shop billing you. The scammer’s PSP sends ReqPay type COLLECT for ₹5,000 through the switch to your PSP, and your app pops up “buyer99@pspx is requesting ₹5,000”. Scammers add notes like “Receive money” to confuse you.",
          facts: [["Type", "COLLECT (pull)"], ["From", "buyer99@pspx"], ["Amount", "₹5,000 from you"]],
          quiz: {
            q: "If you enter your UPI PIN on this screen, what happens?",
            options: ["You receive ₹5,000", "₹5,000 leaves your account to the scammer", "Nothing until the buyer confirms", "The bank checks if it is a scam and blocks it"],
            answer: 1,
            why: "Entering your PIN always authorises money going OUT of your account. On a collect request it approves paying the requester.",
          },
          events: [
            send(leg(N.scam, N.scamPsp, 51000, 0x11110000, 0x22220000), "req", "attacker", "scamPsp", "red", "COLLECT", ["ask victim for ₹5,000"], 0, 880, "Collect request from app"),
            send(leg(N.scamPsp, N.sw, 40500, 0x33330000, 0x44440000), "req", "scamPsp", "switch", "red", "ReqPay", ["type COLLECT", "₹5,000"], 0.15, 1150, "ReqPay (COLLECT)"),
            send(L4.pspSw, "resp", "switch", "pspA", "red", "ReqPay", ["COLLECT for you"], 0.35, 1100, "ReqPay (COLLECT) to payer PSP"),
            send(L4.app, "resp", "pspA", "phone", "red", "REQUEST", ["Pay ₹5,000?", "Enter PIN to PAY"], 0.5, 760, "Collect request push"),
            note("phone", "PAY ₹5,000? ENTER PIN", "red"),
          ],
        },
        {
          title: "Decline and report",
          desc: "No PIN, no money moves",
          detail:
            "You tap Decline. The app sends a response that rejects the collect, the switch tells the scammer’s PSP, and nothing touches your bank. You can also block and report the UPI ID in the app, and report fraud on the national cybercrime helpline 1930.",
          facts: [["Your action", "Decline"], ["Your bank", "Never contacted"], ["Report", "In-app + 1930 helpline"]],
          events: [
            send(L4.app, "req", "phone", "pspA", "green", "DECLINE", ["not approved"], 9, 610, "Collect decline from app"),
            send(L4.pspSw, "req", "pspA", "switch", "green", "RespPay", ["DECLINED"], 9.12, 790, "RespPay (COLLECT) DECLINED"),
            note("payer", "NO DEBIT", "green"),
            note("phone", "DECLINED · REPORTED", "green"),
          ],
        },
      ],
      outro: {
        title: "PIN means pay, always",
        text: "A collect request asks you to pay; it is never a way to receive. The UPI PIN is only ever needed to send money out, so any message that asks for your PIN to “receive” money is a scam.",
        facts: [["Rule", "PIN = money out"], ["Receiving", "Needs no PIN or approval"], ["Defence", "Decline, block, report"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Who is who",
      items: [["Payer PSP", "Bank behind your UPI app"], ["UPI switch", "Central hub that routes every payment"], ["Remitter bank", "Holds your account, checks your PIN"], ["Beneficiary bank", "Holds the shop’s account"], ["UPI ID", "name@handle; the handle picks the PSP"]],
    },
    {
      title: "Messages (simplified)",
      items: [["ReqPay / RespPay", "Pay, debit, credit, reversal and their results"], ["ReqAuthDetails", "Resolve a UPI ID to an account"], ["Ack", "“Received”, sent at once"], ["ReqChkTxn", "Ask for the real status"]],
    },
    {
      title: "Safety rules",
      items: [["PIN", "Only to send money, never to receive"], ["Collect request", "A request for YOU to pay"], ["Pending", "Wait; don’t pay twice"], ["Fraud", "Report in app and on 1930"]],
    },
  ],
});
