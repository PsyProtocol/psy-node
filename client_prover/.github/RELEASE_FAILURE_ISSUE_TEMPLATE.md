---
title: Release workflow failed
labels: ["bug", "release"]
assignees:
  - PsyProtocol/core-team
---

## Release Workflow Failure

The automated release workflow has failed. This requires immediate attention.

**Workflow Run:** ${{ env.WORKFLOW_URL }}

**Failure Details:**
- Branch: `${{ github.ref_name }}`
- Commit: `${{ github.sha }}`
- Actor: `${{ github.actor }}`
- Event: `${{ github.event_name }}`

Please investigate the failure and take appropriate action:

1. Check the workflow logs for specific error messages
2. Fix any issues in the codebase or workflow configuration
3. Re-run the workflow or create a new release as needed
4. Close this issue once resolved

**Priority:** High - Release process is blocked