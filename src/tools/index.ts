import { tools as httpTools } from "./http";
import { tools as seoTools } from "./seo";
import { tools as dnsTools } from "./dns";
import { tools as netTools } from "./net";

export const tools = {
  ...httpTools,
  ...seoTools,
  ...dnsTools,
  ...netTools,
};

export type ToolName = keyof typeof tools;
