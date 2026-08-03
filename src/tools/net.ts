import { connect as tlsConnect } from "node:tls";
import { connect as netConnect } from "node:net";
import { mapWithConcurrency } from "./shared";

function checkCertExpiry(hostname: string, port: number, timeoutMs = 8000): Promise<{
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  expired: boolean;
}> {
  return new Promise((resolve, reject) => {
    const socket = tlsConnect(
      { host: hostname, port, servername: hostname, timeout: timeoutMs },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          socket.end();
          if (!cert || !cert.valid_to) {
            reject(new Error("No certificate presented"));
            return;
          }
          const validTo = new Date(cert.valid_to);
          const daysRemaining = Math.ceil((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
          resolve({
            subject: cert.subject?.CN ?? hostname,
            issuer: cert.issuer?.CN ?? "unknown",
            validFrom: new Date(cert.valid_from).toISOString(),
            validTo: validTo.toISOString(),
            daysRemaining,
            expired: daysRemaining < 0,
          });
        } catch (e) {
          reject(e);
        }
      }
    );
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error(`Connection to ${hostname}:${port} timed out`));
    });
    socket.on("error", reject);
  });
}

const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 27017];

function checkPort(host: string, port: number, timeoutMs = 2500): Promise<{ port: number; state: "open" | "closed" | "filtered" }> {
  return new Promise((resolve) => {
    const socket = netConnect({ host, port, timeout: timeoutMs });
    const finish = (state: "open" | "closed" | "filtered") => {
      socket.destroy();
      resolve({ port, state });
    };
    socket.on("connect", () => finish("open"));
    socket.on("timeout", () => finish("filtered"));
    socket.on("error", (err: any) => finish(err?.code === "ECONNREFUSED" ? "closed" : "filtered"));
  });
}

async function scanPorts(host: string, ports: number[], timeoutMs = 2500) {
  const results = await mapWithConcurrency(ports, 20, (port) => checkPort(host, port, timeoutMs));
  results.sort((a, b) => a.port - b.port);
  return {
    host,
    portsScanned: results.length,
    open: results.filter((r) => r.state === "open").map((r) => r.port),
    closed: results.filter((r) => r.state === "closed").map((r) => r.port),
    filtered: results.filter((r) => r.state === "filtered").map((r) => r.port),
    results,
  };
}

export const tools = {
  ssl_cert_check: {
    price: "$0.0002",
    description: "Connect to a host over TLS and report its certificate's expiry date, days remaining, issuer, and subject.",
    inputSchema: {
      type: "object",
      properties: {
        hostname: { type: "string", description: "Hostname to check, e.g. papacasper.com (no scheme/path)" },
        port: { type: "number", description: "TLS port to connect to (default 443)" },
      },
      required: ["hostname"],
    },
    async run({ hostname, port }: { hostname: string; port?: number }) {
      const cleanHost = hostname.replace(/^https?:\/\//, "").split("/")[0];
      const result = await checkCertExpiry(cleanHost, port ?? 443);
      return { hostname: cleanHost, port: port ?? 443, ...result };
    },
  },

  check_open_ports: {
    price: "$0.0003",
    description:
      "TCP-connect scan a host for open ports. Defaults to a list of ~20 common service ports (SSH, HTTP/S, mail, DBs, etc.) if none are given. For checking your own infrastructure's exposure — capped at 100 ports per call.",
    inputSchema: {
      type: "object",
      properties: {
        host: { type: "string", description: "Hostname or IP to scan (no scheme)" },
        ports: {
          type: "array",
          items: { type: "number" },
          description: "Specific ports to check. Defaults to a common-ports list. Max 100 ports per call.",
        },
      },
      required: ["host"],
    },
    async run({ host, ports }: { host: string; ports?: number[] }) {
      const cleanHost = host.replace(/^https?:\/\//, "").split("/")[0];
      const list = (ports?.length ? ports : COMMON_PORTS)
        .filter((p) => Number.isInteger(p) && p > 0 && p <= 65535)
        .slice(0, 100);
      return scanPorts(cleanHost, list);
    },
  },
};

export type ToolName = keyof typeof tools;
