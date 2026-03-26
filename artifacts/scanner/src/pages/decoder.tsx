import { useState } from "react";
import { Layout } from "@/components/layout";
import { cn } from "@/lib/utils";
import { Copy, Check, ArrowRightLeft, Trash2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

type Codec = {
  id: string;
  label: string;
  encode: (v: string) => string;
  decode: (v: string) => string;
};

const CODECS: Codec[] = [
  {
    id: "base64",
    label: "BASE64",
    encode: (v) => btoa(unescape(encodeURIComponent(v))),
    decode: (v) => {
      try { return decodeURIComponent(escape(atob(v.trim()))); }
      catch { return "[Invalid Base64]"; }
    },
  },
  {
    id: "url",
    label: "URL ENCODE",
    encode: (v) => encodeURIComponent(v),
    decode: (v) => { try { return decodeURIComponent(v); } catch { return "[Invalid URL encoding]"; } },
  },
  {
    id: "url_full",
    label: "URL FULL",
    encode: (v) => v.split("").map(c => "%" + c.charCodeAt(0).toString(16).padStart(2, "0").toUpperCase()).join(""),
    decode: (v) => { try { return decodeURIComponent(v); } catch { return "[Invalid]"; } },
  },
  {
    id: "html",
    label: "HTML ENTITY",
    encode: (v) => v.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"),
    decode: (v) => v.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&#(\d+);/g, (_, n) => String.fromCharCode(n)),
  },
  {
    id: "hex",
    label: "HEX",
    encode: (v) => v.split("").map(c => c.charCodeAt(0).toString(16).padStart(2, "0")).join(""),
    decode: (v) => { try { return v.replace(/[0-9a-f]{2}/gi, (h) => String.fromCharCode(parseInt(h, 16))); } catch { return "[Invalid Hex]"; } },
  },
  {
    id: "hex_escaped",
    label: "HEX ESCAPED",
    encode: (v) => v.split("").map(c => "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0")).join(""),
    decode: (v) => { try { return v.replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))); } catch { return "[Invalid]"; } },
  },
  {
    id: "unicode",
    label: "UNICODE",
    encode: (v) => v.split("").map(c => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join(""),
    decode: (v) => { try { return v.replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))); } catch { return "[Invalid]"; } },
  },
  {
    id: "jwt",
    label: "JWT DECODE",
    encode: (v) => "[JWT encoding not applicable — paste a JWT token to decode]",
    decode: (v) => {
      try {
        const parts = v.trim().split(".");
        if (parts.length !== 3) return "[Not a valid JWT — must have 3 parts separated by .]";
        const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
        const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
        return JSON.stringify({ header, payload, signature: parts[2] }, null, 2);
      } catch { return "[Invalid JWT token]"; }
    },
  },
  {
    id: "binary",
    label: "BINARY",
    encode: (v) => v.split("").map(c => c.charCodeAt(0).toString(2).padStart(8, "0")).join(" "),
    decode: (v) => { try { return v.trim().split(/\s+/).map(b => String.fromCharCode(parseInt(b, 2))).join(""); } catch { return "[Invalid binary]"; } },
  },
];

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
      toast({ title: "COPIED", description: "Output copied to clipboard" });
    });
  };
  return (
    <button onClick={copy} className="p-1.5 text-muted-foreground hover:text-primary transition-colors">
      {copied ? <Check className="w-3.5 h-3.5 text-primary" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

export default function Decoder() {
  const [codec, setCodec] = useState("base64");
  const [input, setInput] = useState("");
  const [mode, setMode] = useState<"encode" | "decode">("encode");

  const selected = CODECS.find(c => c.id === codec)!;

  const output = (() => {
    if (!input.trim()) return "";
    try {
      return mode === "encode" ? selected.encode(input) : selected.decode(input);
    } catch (e: any) {
      return `[Error: ${e.message}]`;
    }
  })();

  const swap = () => {
    setInput(output);
    setMode(mode === "encode" ? "decode" : "encode");
  };

  return (
    <Layout>
      <div className="space-y-5 animate-in fade-in duration-500 max-w-5xl mx-auto">
        <header>
          <h1 className="text-2xl sm:text-3xl">ENCODER_DECODER</h1>
          <p className="text-muted-foreground font-mono text-xs sm:text-sm mt-1">
            // Base64, URL, HTML, Hex, Unicode, Binary, JWT — all in one place
          </p>
        </header>

        {/* Codec Selector */}
        <div className="cyber-box p-4">
          <label className="font-mono text-xs text-primary flex items-center gap-2 mb-3">
            <span className="w-2 h-2 bg-primary" /> SELECT_CODEC
          </label>
          <div className="flex flex-wrap gap-1.5">
            {CODECS.map(c => (
              <button
                key={c.id}
                onClick={() => setCodec(c.id)}
                className={cn(
                  "px-3 py-1.5 font-mono text-xs border transition-all",
                  codec === c.id
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border/50 text-muted-foreground hover:border-primary/40 hover:text-foreground"
                )}
              >
                {c.label}
              </button>
            ))}
          </div>
        </div>

        {/* Mode Toggle */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setMode("encode")}
            className={cn(
              "px-4 py-1.5 font-mono text-xs border transition-all",
              mode === "encode" ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:text-foreground"
            )}
          >
            ENCODE
          </button>
          <button
            onClick={() => setMode("decode")}
            className={cn(
              "px-4 py-1.5 font-mono text-xs border transition-all",
              mode === "decode" ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:text-foreground"
            )}
          >
            DECODE
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Input */}
          <div className="cyber-box p-0 flex flex-col">
            <div className="flex items-center justify-between px-3 py-2 border-b border-primary/20 bg-primary/5">
              <span className="font-mono text-xs text-primary">INPUT</span>
              <div className="flex gap-1">
                <CopyButton text={input} />
                <button onClick={() => setInput("")} className="p-1.5 text-muted-foreground hover:text-red-400 transition-colors">
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              className="flex-1 min-h-[280px] p-3 bg-transparent font-mono text-sm text-foreground resize-none focus:outline-none placeholder:text-muted-foreground/40"
              placeholder={`Paste your ${mode === "encode" ? "plain" : "encoded"} data here...`}
              spellCheck={false}
            />
          </div>

          {/* Output */}
          <div className="cyber-box p-0 flex flex-col">
            <div className="flex items-center justify-between px-3 py-2 border-b border-primary/20 bg-primary/5">
              <span className="font-mono text-xs text-primary">OUTPUT ({selected.label} {mode.toUpperCase()}D)</span>
              <div className="flex gap-1">
                <CopyButton text={output} />
                <button
                  onClick={swap}
                  title="Use output as new input"
                  className="p-1.5 text-muted-foreground hover:text-cyan-400 transition-colors"
                >
                  <ArrowRightLeft className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
            <pre className="flex-1 min-h-[280px] p-3 font-mono text-sm text-cyan-300 overflow-auto whitespace-pre-wrap break-all select-all">
              {output || <span className="text-muted-foreground/30 font-mono text-sm">Output will appear here...</span>}
            </pre>
          </div>
        </div>
      </div>
    </Layout>
  );
}
