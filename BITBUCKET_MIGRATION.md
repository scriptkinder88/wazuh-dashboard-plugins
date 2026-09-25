# Bitbucket migration

Target internal repository:

- Project: Wazuh Reporting & Compliance
- Project key: WRC
- Repository: wazuh-dashboard-plugins-4x

The 4.14.x customized reporting line is intended to move to the internal
Bitbucket repository. The public GitHub fork is reserved for the clean 5.x
upstream contribution and must not contain customer-specific references.

## Import baseline

Use the validated 4.14.7 customized source after the v11 CI gates pass.

## Separation rule

- Bitbucket: internal/custom 4.x reporting implementation.
- GitHub: clean Wazuh 5.x fork only, generic/upstream-ready.
