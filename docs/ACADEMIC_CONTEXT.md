# Academic Context

**Project:** *A Structured Triage Framework for IDS Alerts on Suspicious RMM Installers: A Case-Driven Approach*  
**Institution:** University of Ha'il — Department of Information Security  
**COOP training placement:** TAHAKOM  
**Supervisor:** Dr. Ehab AlNfrawy

## Objective

This project explores how a repeatable triage workflow can bridge manual SOC analysis and automated evidence processing. Suspicious RMM installer alerts are difficult to assess because legitimate remote-support software is also used by adversaries. Analysts need to establish file identity, inspect signature evidence, consult threat intelligence and internal authorization records, then document a defensible next step. Ruler Triage Framework automates those initial evidence-gathering and prioritization steps while keeping the result explainable and subject to analyst review.

## Methodology

The ManageEngine UEMS Agent investigation conducted during the Tahakom COOP placement serves as the ground-truth calibration case. Its recorded evidence includes an unsigned installer, an internal SMB2 transfer over port 445, a VirusTotal ratio of 1/69, and an unresolved authorization question. The SHA-256 is recorded in `vendor_hashes.json` as `pending_verification`, reflecting that IT Operations had not yet confirmed the deployment at the time of the investigation.

The scoring weights were selected so this evidence reproduces the manual disposition: unsigned (+30), any VT detections (+20), and a pending vendor database match (−30), yielding a total of 20. Scores below 30 map to **Low Confidence (Suspicious / Pending Verification)**. The `--validate-case` mode simulates these known inputs and compares key indicators and the verdict with the case record. This demonstrates calibration against one documented case; it is not a statistical validation across a representative dataset and does not establish general detection accuracy.

## Mapping to Industry Guidance

The mappings below describe how selected project capabilities support parts of the guidance. They do not imply certification or full compliance.

| Guidance | Relevant guidance theme | Project relationship |
|---|---|---|
| NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide* | Incident detection and analysis, including gathering and correlating information to characterize and prioritize an event. | The six-stage pipeline gathers hash, signature, reputation, and internal database evidence; the weighted score and structured report help an analyst organize an initial assessment. The tool does not perform the full incident-handling lifecycle, containment, eradication, recovery, or organizational coordination. |
| CISA AA23-025A, *Protecting Against Malicious Use of Remote Monitoring and Management Software* | RMM tools are legitimate dual-use software and can be abused by threat actors; defenders are advised to monitor and investigate suspicious RMM use and apply the advisory's mitigations. | The project focuses on suspicious RMM installer alerts and provides file identity, signature, VirusTotal, and organization-specific hash context to support triage. It does not implement network monitoring, endpoint policy enforcement, or every mitigation in the advisory. |

**Guidance currency:** This academic project explicitly maps to the requested Rev. 2 edition of NIST SP 800-61. NIST withdrew Rev. 2 on April 3, 2025 and superseded it with SP 800-61 Rev. 3; readers applying current guidance should consult Rev. 3. [NIST SP 800-61 Rev. 2 status and supersession notice](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-61r2.pdf) · [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final).

CISA AA23-025A describes the risks of malicious use of legitimate RMM software and recommends defenders review the advisory's indicators and mitigations. [CISA AA23-025A advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a).

## Limitations and Mitigations

- **VirusTotal coverage and free-tier limits:** Hash-only lookups depend on the file already being indexed and on API availability and quotas. The framework applies a proactive delay and retry back-off for rate limiting, never uploads the analyzed file, and reports when VirusTotal is unavailable so an analyst can treat the score as incomplete.
- **Certificate trust and revocation:** The full signature tier checks Authenticode digest integrity and extracts certificate details, but it does not build a complete trust chain or perform OCSP/CRL revocation checking. The report exposes the tier and verification status; analysts should corroborate certificate trust and revocation through an appropriate trusted endpoint or security workflow.
- **Hash database freshness:** A database miss can reflect an authorized but undocumented deployment, while a pending match does not establish authorization. Entries are status-aware, pending matches trigger an IT Operations warning, and approval should follow organizational confirmation.
- **Heuristic calibration scope:** The weights are calibrated against a single case, not a broad labeled dataset. The score is an explainable prioritization aid, not a probability or conclusive malware classification. Analysts should combine it with endpoint, network, and business context.
- **No detonation or behavioral analysis:** The framework does not execute files or provide sandbox analysis. It relies on static identity and reputation evidence and should be paired with approved analysis tooling when behavioral evidence is required.
