import { tools as httpTools } from "./http";
import { tools as seoTools } from "./seo";
import { tools as dnsTools } from "./dns";
import { tools as netTools } from "./net";
import { tools as bundleTools } from "./bundles";
import { tools as securityTools } from "./security";
import { tools as performanceTools } from "./performance";
import { tools as devTools } from "./dev";
import { tools as emailTools } from "./email";
import { tools as mcpTools } from "./mcp";
import { tools as renderTools } from "./render";
import { tools as validateTools } from "./validate";
import { tools as convertTools } from "./convert";
import { tools as archiveTools } from "./archive";
import { tools as siteCheckTools } from "./sitechecks";

export const tools = {
  ...httpTools,
  ...seoTools,
  ...dnsTools,
  ...netTools,
  ...bundleTools,
  ...securityTools,
  ...performanceTools,
  ...devTools,
  ...emailTools,
  ...mcpTools,
  ...renderTools,
  ...validateTools,
  ...convertTools,
  ...archiveTools,
  ...siteCheckTools,
};

export type ToolName = keyof typeof tools;
