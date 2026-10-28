# Fully automatic public access

## Current state

The service is deployed, and a live read-only Google Play connection has passed. The Google OAuth app remains in Testing mode. Access is limited to explicitly approved test users.

Google's documented process manages test users through Google Auth Platform's Audience page. No supported public tester-enrollment API was found during implementation research. A website form, Gmail message, or application database record does not itself enroll an OAuth tester.

## Required path

1. Finalize the public application name, operator/support details, homepage, privacy policy, and terms where applicable.
2. Configure and verify domain ownership as required for the OAuth brand. The account owns a custom domain, but existing domain and DNS settings have been preserved. A public hostname must be selected and configured deliberately before changing production redirect URIs.
3. Review the exact requested Google scopes: `openid`, `email`, and `https://www.googleapis.com/auth/androidpublisher`. Explain the broad Google Play permission and the separate read/write scopes enforced for agents.
4. Finish Branding, Audience, and Data Access settings. Prepare any scope justification and demonstration video Google requests.
5. Submit for applicable Google OAuth verification and complete the production publishing steps. Google controls approval; setting the app to production alone is not a substitute for verification requirements, and unverified apps may still face warnings or limits.
6. After approval and readiness checks, let developers connect through the hosted MCP endpoint. Each developer signs in and consents using a Google account with its own Play Console permissions. A separate tester-list entry is then unnecessary for ordinary public users, subject to Google's policies and any Workspace administrator restrictions.

## Email automation

The requested applicant confirmation email can accompany a future public signup flow. It must describe the actual state accurately: an email receipt is not proof of OAuth access or Google approval.

A continuously hosted Gmail sender needs its own authorized Gmail send integration and secure refresh-token storage. The connected Gmail tool in a development chat is not a credential that can be embedded into the Worker. Until a sender is configured and deployed, the service must not claim that confirmation messages are being sent automatically.

No signup or enrollment automation is enabled in this change. The owner requested fully automatic access rather than a manual tester-approval queue, so the production OAuth prerequisite must be completed first.

## Google documentation

- [Manage app audience](https://support.google.com/cloud/answer/15549945?hl=en)
- [OAuth scope verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/sensitive-scope-verification)
- [Submitting an app for verification](https://support.google.com/cloud/answer/13461325?hl=en)
