/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
*/

export type Paginated<T> = {
  items: T[];
  page: number;
  page_size: number;
  total: number;
};

export type ClientFinding = {
  id: number;
  title: string;
  severity?: string | null;
  status?: string;
  cvss_score?: number | null;
  mitre_id?: string | null;
  visibility_status: string;
  approval_status: string;
};

export type ClientFindingDetail = {
  id: number;
  title: string;
  description?: string | null;
  severity?: string | null;
  status: string;
  cvss_score?: number | null;
  mitre_id?: string | null;
  visibility_status: string;
  approval_status: string;
};

export type ClientEvidenceItem = {
  id: number;
  finding_id: number;
  artifact_type: string;
  description?: string | null;
  approval_status: string;
  download_url: string;
};

export type ClientReport = {
  id: number;
  title: string;
  status: string;
  download_url: string;
};

export type RiskSummary = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  score: number;
};

export type RemediationTask = {
  id: number;
  finding_id?: number | null;
  title: string;
  status: string;
  priority?: string | null;
  owner?: string | null;
  due_date?: string | null;
};

export type ClientTheme = {
  company_name: string;
  logo_url?: string | null;
  colors: {
    primary: string;
    accent: string;
    background: string;
    foreground: string;
    danger: string;
    success: string;
  };
  platform_brand_locked?: boolean;
  platform_attribution?: {
    line1: string;
    line2: string;
  };
};

export type ClientMLInsight = {
  score: number;
  confidence: number;
  explanation: string;
  model_version: string;
  generated_at: string;
};
