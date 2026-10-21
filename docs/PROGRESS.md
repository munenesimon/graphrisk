# GraphRisk progress, 12 to 21 October 2026

This note covers the work from 12 to 21 October: what changed in GraphRisk, how it was validated against a live Wazuh deployment, and what is planned next.

## What changed

### Confirmed-only scoring

GraphRisk now shows or scores a fact only if the source tool can confirm it. If the tool cannot confirm it, GraphRisk marks it as unconfirmed and leaves it out of both the passed count and the total.

- **Microsoft Defender features:** Wazuh cannot read Defender's live feature state. GraphRisk now reports the features as unconfirmed instead of inferring them from CIS check names, and no longer raises a "fix Defender settings" action.
- **Antivirus coverage:** devices whose antivirus state cannot be read are reported as unconfirmed and are not scored. If no device can be confirmed, the check returns "no data", and the control's health is left unchanged rather than marked as failed.
- **Okta password policy:** only a minimum length that Okta actually reports is used, and 12 or more counts as strong. If no policy reports a length, the check returns "no data".

### Antivirus confirmed through Windows services

Wazuh's process inventory cannot see Windows protected processes, which is where most antivirus engines run. GraphRisk now also reads the device's service inventory from the Wazuh indexer and recognises the services of common protection products (Microsoft Defender Antivirus, Defender for Endpoint, CrowdStrike Falcon, SentinelOne, ESET and Malwarebytes).

- A running service counts as confirmed evidence that the product is running.
- A stopped service is reported as "installed, service not running" and is not counted as protection.
- If neither the processes nor the services can be read, the device stays unconfirmed, as before.

### Inventory cross-check for vulnerability findings

A vulnerability scanner can keep reporting a finding after the software has been updated or removed, until it rescans the device. GraphRisk now compares each finding with the device's own software inventory. When a finding names a package version the device no longer reports, GraphRisk holds it back as "Fixed on the device, awaiting rescan".

- Held-back findings are shown on the device page but are not counted as open, and they do not raise recommended actions.
- They are not counted as resolved either. They drop off for good only when the scanner stops reporting them.
- A safety rule turns the cross-check off for a device if it would hold back most of its vulnerable packages at once, since that usually means the inventory itself is incomplete.

### Graded control status and control health

- Checks now set a graded implementation status instead of pass or fail only: Implemented when the check passes, Partially Implemented when it fails with some effectiveness, and Not Implemented when effectiveness is zero.
- The dashboard's Controls card shows the average control health, and a new Control Health section lists each control with its health, its source and when it was last tested. Selecting a control opens its blast radius.

### CIS benchmark matched to the Windows edition

The CIS benchmark that Wazuh ships is written for Windows 10 Enterprise. On Pro and Home devices, settings for Enterprise and Education features (Credential Guard, Device Guard, AppLocker, Windows tips, Microsoft consumer experiences) are no longer counted. Optional features such as Application Guard are not counted on any edition.

The edition is read from the agent's OS name and is never assumed to be Enterprise. The device page explains how many settings were left out and why.

### Smaller fixes

- Framework adherence totals now update as soon as requirement fields are filled in.
- Package names on the device page and in recommended actions no longer repeat the version when it is already part of the name.

### README

The README was updated to cover risk appetite and adequacy, recommended actions, framework adherence with evidence status and attestations, ISO 27001 and SOC 2 readiness, the shared connector rules, and the edition rule. The license section now reads All Rights Reserved.

## Live validation

All three Wazuh checks ran against a live manager and indexer with one Windows 10 Pro agent: agent connectivity, SCA configuration compliance, and vulnerability patching.

### Antivirus

- When the agent had not yet reported its inventory, GraphRisk marked antivirus as unconfirmed and left the saved result unchanged.
- Once the service inventory was available, GraphRisk reported antivirus as running on 1 of 1 devices checked, confirmed through its Windows service.

### Inventory cross-check

Three packages were updated or removed on the test device.

- After the connector ran, GraphRisk held back the 227 findings for those packages as awaiting rescan, and kept every finding for software that is still installed.
- The device's recommended actions went from 10 to 7.
- Unpatched Vulnerability Risk fell from 9.33 to 5.29, against an appetite of 4. Vulnerability and patch management health is now 63%.

### Edition rule

The configuration score leaves out 7 Enterprise-only or optional-feature settings on the Pro device, and the action text explains why. The latest run shows 293 of 408 applicable checks failing.

## Finding: the source tool can lag behind the device

While validating the patches, the Wazuh agent inventory showed the new package versions, but Wazuh's vulnerability index still held records for the old ones. The change event had been lost on the Wazuh side, so the old records were never cleared, and removing them by hand did not last because the scanner restored them on its next sync.

GraphRisk relayed the stale data accurately, because it reports what the source holds. The inventory cross-check above is the product's answer: GraphRisk now spots the gap itself and shows those findings as awaiting rescan instead of open.

## Next steps

- **Protection products:** list only products whose service is running in the device's protection summary, so an installed but inactive product is not shown alongside the active one.
- **Risk acceptance:** record accepted risk, with a reason and a review date, for findings that cannot be fixed yet.
- **Combining rule:** when several checks feed the same control, combine their results instead of letting the latest one overwrite the others.
- **Attestation lifecycle:** add review dates and expiry to attestations.
- **Count mismatch:** look into why the configuration card and the action text sometimes disagree by one failed check.
- **Framework headline:** grey out the headline percentage when most requirements have no evidence yet.
- **Live validation beyond Wazuh:** run the device profiles against other connectors on live tenants.
