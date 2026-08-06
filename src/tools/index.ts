import { tools as httpTools } from "./http";
import { tools as seoTools } from "./seo";
import { tools as dnsTools } from "./dns";
import { tools as netTools } from "./net";
import { tools as bundleTools } from "./bundles";

export const tools = {
  ...httpTools,
  ...seoTools,
  ...dnsTools,
  ...netTools,
  ...bundleTools,
};

export type ToolName = keyof typeof tools;
