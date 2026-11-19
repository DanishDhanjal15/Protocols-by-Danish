"use client";

import { useState } from "react";
import { Search } from "lucide-react";

const TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "HTTPS"];
const TYPE_NAMES: Record<number, string> = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA", 46: "RRSIG", 65: "HTTPS" };
const RCODES = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"];

interface Answer { name: string; type: number; TTL: number; data: string }
interface Result { Status: number; AD: boolean; Answer?: Answer[]; Authority?: Answer[] }

/** Real lookups through a public DNS-over-HTTPS resolver, run from the visitor's browser. */
export function LiveDns() {
  const [name, setName] = useState("example.com");
  const [type, setType] = useState("A");
  const [res, setRes] = useState<Result | null>(null);
  const [ms, setMs] = useState(0);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const lookup = async () => {
    const q = name.trim().replace(/\.$/, "");
    if (!/^[a-z0-9.-]+$/i.test(q)) {
      setErr("Use a plain domain name such as example.com.");
      return;
    }
    setBusy(true);
    setErr("");
    const t = performance.now();
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(q)}&type=${type}&do=1`, { headers: { accept: "application/dns-json" } });
      if (!r.ok) throw new Error(String(r.status));
      setRes(await r.json());
      setMs(performance.now() - t);
    } catch {
      setErr("The resolver didn’t answer. Check your connection, or your network may block DNS over HTTPS.");
      setRes(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card p-5 flex flex-col gap-3">
      <div>
        <h2 className="text-[18px] font-bold">Live DNS lookup <span className="text-[13px] font-medium text-muted">· nslookup / dig in your browser</span></h2>
        <p className="text-[13px] text-muted">Does what <code className="mono">nslookup example.com</code> or <code className="mono">dig example.com A</code> does in a terminal: a real query, sent from your browser over DNS over HTTPS to Cloudflare’s public resolver (1.1.1.1). See the DoH lesson for what happens underneath.</p>
      </div>
      <form className="flex flex-wrap gap-2" onSubmit={(e) => { e.preventDefault(); lookup(); }}>
        <input id="dns-name" value={name} onChange={(e) => setName(e.target.value)} className="h-10 rounded-lg border border-line bg-panel px-3 text-[14px] mono flex-1 min-w-[160px]" aria-label="Domain name" />
        <select id="dns-type" value={type} onChange={(e) => setType(e.target.value)} className="h-10 rounded-lg border border-line bg-panel px-2 text-[14px]" aria-label="Record type">
          {TYPES.map((t) => <option key={t}>{t}</option>)}
        </select>
        <button className="btn btn-primary h-10" disabled={busy}><Search size={16} /> {busy ? "Looking up…" : "Look up"}</button>
      </form>
      {err && <p className="text-[13px]" style={{ color: "var(--c-red)" }}>{err}</p>}
      {res && (
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap gap-1.5">
            <span className="chip" style={{ color: res.Status === 0 ? "var(--c-green)" : "var(--c-red)" }}>{RCODES[res.Status] ?? res.Status}</span>
            <span className="chip">{ms.toFixed(0)} ms</span>
            <span className="chip">{res.AD ? "DNSSEC validated (AD)" : "not DNSSEC-signed"}</span>
          </div>
          <div className="overflow-x-auto scroll-thin">
            <table className="w-full text-[13px] mono">
              <thead className="text-muted text-left"><tr><th className="py-1 pr-3">Name</th><th className="pr-3">Type</th><th className="pr-3">TTL</th><th>Data</th></tr></thead>
              <tbody>
                {(res.Answer ?? res.Authority ?? []).map((a, i) => (
                  <tr key={i} className="border-t border-line">
                    <td className="py-1 pr-3 whitespace-nowrap">{a.name}</td>
                    <td className="pr-3">{TYPE_NAMES[a.type] ?? a.type}</td>
                    <td className="pr-3 tnum">{a.TTL}s</td>
                    <td className="break-all">{a.data}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!res.Answer?.length && !res.Authority?.length && <p className="text-[13px] text-muted pt-1">No records of that type.</p>}
          </div>
        </div>
      )}
    </div>
  );
}
