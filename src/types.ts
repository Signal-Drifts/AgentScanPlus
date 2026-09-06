export type Category = "Application Security" | "Dependencies" | "Agent Security" | "MCP Security";

export interface Finding {
  id: string;
  category: Category;
  critical: boolean;
  title: string;
  detail: string;
  location: string;
  recommendation: string;
}

export interface Report {
  id: string;
  label: string;
  project: string;
  branch?: string;
  path: string;
  filesScanned: number;
  findings: Finding[];
  agentDetected: boolean;
  mcpDetected: boolean;
  skippedFiles: number;
}

export interface ScanResult {
  sourceName: string;
  sourcePath: string;
  sourceKind: "folder" | "repository";
  reports: Report[];
  scannedAt: string;
}
