import { tools as httpTools } from "./http";
import { tools as seoTools } from "./seo";
import { tools as dnsTools } from "./dns";
import { tools as netTools } from "./net";
import { tools as bundleTools } from "./bundles";
import { tools as securityTools } from "./security";
import { tools as performanceTools } from "./performance";
import { tools as devTools } from "./dev";
import { tools as emailTools } from "./email";

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
};

export type ToolName = keyof typeof tools;
