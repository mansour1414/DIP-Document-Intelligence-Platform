export type WorkflowBinding =
  | { source: "workflow"; input: string }
  | { source: "node"; nodeId: string; output?: number };

export type WorkflowNode = {
  id: string;
  toolId: string;
  toolVersion: string;
  dependsOn: string[];
  inputs: WorkflowBinding[];
  options?: Record<string, string | number | boolean>;
};

export type WorkflowDefinition = { schemaVersion: 1; nodes: WorkflowNode[] };

export type WorkflowValidationIssue = { code: string; path: string; message: string };
export type WorkflowValidationResult = { valid: boolean; issues: WorkflowValidationIssue[]; order: string[] };
