// Captured verbatim from the live Palo Alto PSIRT bulk endpoint on 2026-09-19
// (https://security.paloaltonetworks.com/api/v1/products/PAN-OS/advisories),
// trimmed to the fields lib/feeds/paloalto.js actually reads. Per CLAUDE.md:
// the captured records ARE the fixtures -- never hand-written approximations
// of what documentation says a vendor returns.
//
// The two informational records are COMPLETE.  is the
// positive control -- it exists only to prove the unaffected-skip is not
// passing because nothing ever yields a range -- and its versions[] is cut to
// the first 2 entries with 3 changes[] each, from a record carrying ~21 KB of
// per-hotfix-train history that adds nothing to this test.

module.exports = {
  "informationalUnaffected": {
    "cveMetadata": {
      "cveId": "CVE-2022-22963",
      "datePublished": "2022-03-31T00:00:00"
    },
    "containers": {
      "cna": {
        "title": "Informational: Impact of Spring Vulnerabilities CVE-2022-22963 and CVE-2022-22965",
        "metrics": [
          {
            "cvssV3_1": {
              "version": "3.1",
              "attackVector": "PHYSICAL",
              "attackComplexity": "HIGH",
              "privilegesRequired": "HIGH",
              "userInteraction": "REQUIRED",
              "scope": "UNCHANGED",
              "confidentialityImpact": "NONE",
              "integrityImpact": "NONE",
              "availabilityImpact": "NONE",
              "vectorString": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
              "baseScore": 0,
              "baseSeverity": "NONE"
            },
            "format": "CVSS",
            "scenarios": [
              {
                "lang": "en",
                "value": "GENERAL"
              }
            ]
          }
        ],
        "affected": [
          {
            "vendor": "Palo Alto Networks",
            "product": "PAN-OS",
            "versions": [
              {
                "version": "All",
                "status": "unaffected"
              }
            ]
          }
        ],
        "references": [
          {
            "tags": [
              "x_refsource_CONFIRM"
            ],
            "url": "https://security.paloaltonetworks.com/CVE-2022-22963"
          }
        ],
        "descriptions": [
          {
            "lang": "en",
            "value": "The Palo Alto Networks Product Security Assurance team has completed its evaluation of the Spring Cloud Function vulnerability CVE-2022-22963 and Spring Core vulnerability CVE-2022-22965 for all produ"
          }
        ],
        "problemTypes": [
          {
            "descriptions": [
              {
                "type": "CWE",
                "lang": "en",
                "description": "CWE-770 Allocation of Resources Without Limits or Throttling",
                "cweId": "CWE-770"
              }
            ]
          },
          {
            "descriptions": [
              {
                "type": "CWE",
                "lang": "en",
                "description": "CWE-497 Exposure of System Data to an Unauthorized Control Sphere",
                "cweId": "CWE-497"
              }
            ]
          }
        ]
      }
    }
  },
  "informationalImpactVector": {
    "cveMetadata": {
      "cveId": "CVE-2021-28041",
      "datePublished": "2021-03-24T00:00:00"
    },
    "containers": {
      "cna": {
        "title": "PAN-OS: Informational: Impact of the OpenSSH vulnerability CVE-2021-28041",
        "metrics": [
          {
            "cvssV4_0": {
              "version": "4.0",
              "attackVector": "PHYSICAL",
              "attackComplexity": "HIGH",
              "attackRequirements": "NONE",
              "privilegesRequired": "HIGH",
              "userInteraction": "ACTIVE",
              "vulnConfidentialityImpact": "HIGH",
              "subConfidentialityImpact": "HIGH",
              "vulnIntegrityImpact": "HIGH",
              "subIntegrityImpact": "HIGH",
              "vulnAvailabilityImpact": "HIGH",
              "subAvailabilityImpact": "HIGH",
              "Safety": "NOT_DEFINED",
              "Automatable": "NOT_DEFINED",
              "Recovery": "NOT_DEFINED",
              "valueDensity": "NOT_DEFINED",
              "vulnerabilityResponseEffort": "NOT_DEFINED",
              "providerUrgency": "NOT_DEFINED",
              "baseSeverity": "NONE",
              "baseScore": 0,
              "vectorString": "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
            },
            "format": "CVSS",
            "scenarios": [
              {
                "lang": "en",
                "value": "GENERAL"
              }
            ]
          }
        ],
        "affected": [
          {
            "vendor": "Palo Alto Networks",
            "product": "PAN-OS",
            "versions": [
              {
                "version": "All",
                "status": "unaffected"
              }
            ]
          }
        ],
        "references": [
          {
            "tags": [
              "x_refsource_CONFIRM"
            ],
            "url": "https://security.paloaltonetworks.com/CVE-2021-28041"
          }
        ],
        "descriptions": [
          {
            "lang": "en",
            "value": "The Palo Alto Networks Product Security Assurance team has evaluated the OpenSSH software CVE-2021-28041 vulnerability.\n\nPAN-OS software does not utilize the ssh-agent component or provide access to t"
          }
        ],
        "problemTypes": []
      }
    }
  },
  "genuinelyAffected": {
    "cveMetadata": {
      "cveId": "CVE-2026-0310",
      "datePublished": null
    },
    "containers": {
      "cna": {
        "title": "PAN-OS: Buffer Overflow Vulnerability via XML Processing ",
        "metrics": [
          {
            "format": "CVSS",
            "scenarios": [
              {
                "lang": "en",
                "value": "The risk is highest for PA-Series hardware firewalls as there is a risk of arbitrary code execution"
              }
            ],
            "cvssV4_0": {
              "version": "4.0",
              "attackVector": "NETWORK",
              "attackComplexity": "HIGH",
              "attackRequirements": "NONE",
              "privilegesRequired": "NONE",
              "userInteraction": "NONE",
              "vulnConfidentialityImpact": "HIGH",
              "subConfidentialityImpact": "LOW",
              "vulnIntegrityImpact": "HIGH",
              "subIntegrityImpact": "LOW",
              "vulnAvailabilityImpact": "HIGH",
              "subAvailabilityImpact": "NONE",
              "Safety": "NOT_DEFINED",
              "Automatable": "NO",
              "Recovery": "USER",
              "valueDensity": "DIFFUSE",
              "vulnerabilityResponseEffort": "MODERATE",
              "providerUrgency": "RED",
              "exploitMaturity": "UNREPORTED",
              "baseSeverity": "CRITICAL",
              "baseScore": 9.2,
              "threatSeverity": "HIGH",
              "threatScore": 7.2,
              "vectorString": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N/E:U/AU:N/R:U/V:D/RE:M/U:Red"
            }
          },
          {
            "format": "CVSS",
            "scenarios": [
              {
                "lang": "en",
                "value": "The risk is lower for VM-Series firewalls, as the impact is limited to a Denial of Service condition"
              }
            ],
            "cvssV4_0": {
              "version": "4.0",
              "attackVector": "NETWORK",
              "attackComplexity": "LOW",
              "attackRequirements": "NONE",
              "privilegesRequired": "NONE",
              "userInteraction": "NONE",
              "vulnConfidentialityImpact": "NONE",
              "subConfidentialityImpact": "NONE",
              "vulnIntegrityImpact": "NONE",
              "subIntegrityImpact": "NONE",
              "vulnAvailabilityImpact": "HIGH",
              "subAvailabilityImpact": "NONE",
              "Safety": "NOT_DEFINED",
              "Automatable": "NO",
              "Recovery": "USER",
              "valueDensity": "DIFFUSE",
              "vulnerabilityResponseEffort": "MODERATE",
              "providerUrgency": "AMBER",
              "exploitMaturity": "UNREPORTED",
              "baseSeverity": "HIGH",
              "baseScore": 8.7,
              "threatSeverity": "MEDIUM",
              "threatScore": 6.6,
              "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:U/AU:N/R:U/V:D/RE:M/U:Amber"
            }
          },
          {
            "format": "CVSS",
            "scenarios": [
              {
                "lang": "en",
                "value": "The risk of exploitation is lower for Prisma Access and Cloud NGFW as it requires an authenticated user and the external network access is restricted. "
              }
            ],
            "cvssV4_0": {
              "version": "4.0",
              "attackVector": "ADJACENT",
              "attackComplexity": "HIGH",
              "attackRequirements": "NONE",
              "privilegesRequired": "LOW",
              "userInteraction": "NONE",
              "vulnConfidentialityImpact": "HIGH",
              "subConfidentialityImpact": "LOW",
              "vulnIntegrityImpact": "HIGH",
              "subIntegrityImpact": "LOW",
              "vulnAvailabilityImpact": "HIGH",
              "subAvailabilityImpact": "NONE",
              "Safety": "NOT_DEFINED",
              "Automatable": "NO",
              "Recovery": "USER",
              "valueDensity": "DIFFUSE",
              "vulnerabilityResponseEffort": "MODERATE",
              "providerUrgency": "AMBER",
              "exploitMaturity": "UNREPORTED",
              "baseSeverity": "HIGH",
              "baseScore": 7.5,
              "threatSeverity": "MEDIUM",
              "threatScore": 4.8,
              "vectorString": "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N/E:U/AU:N/R:U/V:D/RE:M/U:Amber"
            }
          },
          {
            "format": "CVSS",
            "scenarios": [
              {
                "lang": "en",
                "value": "You can reduce the risk of exploitation on management interface by restricting access to a jump box that is the only system allowed to access the management interface."
              }
            ],
            "cvssV4_0": {
              "version": "4.0",
              "attackVector": "ADJACENT",
              "attackComplexity": "HIGH",
              "attackRequirements": "NONE",
              "privilegesRequired": "NONE",
              "userInteraction": "NONE",
              "vulnConfidentialityImpact": "HIGH",
              "subConfidentialityImpact": "LOW",
              "vulnIntegrityImpact": "HIGH",
              "subIntegrityImpact": "LOW",
              "vulnAvailabilityImpact": "HIGH",
              "subAvailabilityImpact": "NONE",
              "Safety": "NOT_DEFINED",
              "Automatable": "NO",
              "Recovery": "USER",
              "valueDensity": "DIFFUSE",
              "vulnerabilityResponseEffort": "MODERATE",
              "providerUrgency": "AMBER",
              "exploitMaturity": "UNREPORTED",
              "baseSeverity": "HIGH",
              "baseScore": 7.7,
              "threatSeverity": "MEDIUM",
              "threatScore": 5.2,
              "vectorString": "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N/E:U/AU:N/R:U/V:D/RE:M/U:Amber"
            }
          }
        ],
        "affected": [
          {
            "vendor": "Palo Alto Networks",
            "product": "PAN-OS",
            "versions": [
              {
                "version": "12.2.0",
                "status": "affected",
                "lessThan": "12.2.3",
                "versionType": "custom",
                "changes": [
                  {
                    "at": "12.2.3",
                    "status": "unaffected"
                  }
                ]
              },
              {
                "version": "12.1.0",
                "status": "affected",
                "lessThan": "12.1.4-h10",
                "versionType": "custom",
                "changes": [
                  {
                    "at": "12.1.10",
                    "status": "unaffected"
                  },
                  {
                    "at": "12.1.7-h5",
                    "status": "unaffected"
                  },
                  {
                    "at": "12.1.4-h10",
                    "status": "unaffected"
                  }
                ]
              }
            ],
            "defaultStatus": "unaffected"
          }
        ],
        "references": [
          {
            "url": "https://security.paloaltonetworks.com/CVE-2026-0310",
            "tags": [
              "vendor-advisory"
            ]
          }
        ],
        "descriptions": [
          {
            "lang": "en",
            "value": "A buffer overflow vulnerability in the XML processing functionality of Palo Alto Networks PAN-OS® software enables an unauthenticated attacker with network access to the management web or dataplane in"
          }
        ],
        "problemTypes": [
          {
            "descriptions": [
              {
                "lang": "en",
                "cweId": "CWE-787",
                "description": "CWE-787 Out-of-bounds Write",
                "type": "CWE"
              }
            ]
          }
        ]
      }
    }
  },
  "mixedStatuses": {
    "cveMetadata": {
      "cveId": "CVE-2026-0308",
      "datePublished": null
    },
    "containers": {
      "cna": {
        "title": "PAN-OS: Stored Cross-Site Scripting (XSS) Vulnerability in the Web Interface",
        "metrics": [
          {
            "format": "CVSS",
            "scenarios": [
              {
                "lang": "en",
                "value": "The risk is highest when you allow access to the management interface from external IP addresses on the internet. "
              }
            ],
            "cvssV4_0": {
              "version": "4.0",
              "attackVector": "NETWORK",
              "attackComplexity": "LOW",
              "attackRequirements": "NONE",
              "privilegesRequired": "HIGH",
              "userInteraction": "PASSIVE",
              "vulnConfidentialityImpact": "LOW",
              "subConfidentialityImpact": "NONE",
              "vulnIntegrityImpact": "LOW",
              "subIntegrityImpact": "NONE",
              "vulnAvailabilityImpact": "NONE",
              "subAvailabilityImpact": "NONE",
              "Safety": "NOT_DEFINED",
              "Automatable": "NO",
              "Recovery": "USER",
              "valueDensity": "DIFFUSE",
              "vulnerabilityResponseEffort": "MODERATE",
              "providerUrgency": "AMBER",
              "exploitMaturity": "UNREPORTED",
              "baseSeverity": "MEDIUM",
              "baseScore": 4.8,
              "threatSeverity": "LOW",
              "threatScore": 1.1,
              "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/AU:N/R:U/V:D/RE:M/U:Amber"
            }
          },
          {
            "format": "CVSS",
            "scenarios": [
              {
                "lang": "en",
                "value": "You can reduce the risk of exploitation by restricting access to a jump box that is the only system allowed to access the management interface. "
              }
            ],
            "cvssV4_0": {
              "version": "4.0",
              "attackVector": "ADJACENT",
              "attackComplexity": "LOW",
              "attackRequirements": "NONE",
              "privilegesRequired": "HIGH",
              "userInteraction": "PASSIVE",
              "vulnConfidentialityImpact": "LOW",
              "subConfidentialityImpact": "NONE",
              "vulnIntegrityImpact": "LOW",
              "subIntegrityImpact": "NONE",
              "vulnAvailabilityImpact": "NONE",
              "subAvailabilityImpact": "NONE",
              "Safety": "NOT_DEFINED",
              "Automatable": "NO",
              "Recovery": "USER",
              "valueDensity": "DIFFUSE",
              "vulnerabilityResponseEffort": "MODERATE",
              "providerUrgency": "AMBER",
              "exploitMaturity": "UNREPORTED",
              "baseSeverity": "LOW",
              "baseScore": 2.4,
              "threatSeverity": "LOW",
              "threatScore": 0.4,
              "vectorString": "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/AU:N/R:U/V:D/RE:M/U:Amber"
            }
          }
        ],
        "affected": [
          {
            "vendor": "Palo Alto Networks",
            "product": "PAN-OS",
            "versions": [
              {
                "version": "12.2.0",
                "status": "unaffected",
                "versionType": "custom"
              },
              {
                "version": "12.1.0",
                "status": "affected",
                "lessThan": "12.1.10",
                "versionType": "custom",
                "changes": [
                  {
                    "at": "12.1.10",
                    "status": "unaffected"
                  }
                ]
              },
              {
                "version": "11.2.0",
                "status": "affected",
                "lessThan": "11.2.13-h2",
                "versionType": "custom",
                "changes": [
                  {
                    "at": "11.2.13-h2",
                    "status": "unaffected"
                  }
                ]
              },
              {
                "version": "11.1.0",
                "status": "affected",
                "lessThan": "11.1.16-h2",
                "versionType": "custom",
                "changes": [
                  {
                    "at": "11.1.16-h2",
                    "status": "unaffected"
                  }
                ]
              }
            ],
            "defaultStatus": "unaffected"
          }
        ],
        "references": [
          {
            "url": "https://security.paloaltonetworks.com/CVE-2026-0308",
            "tags": [
              "vendor-advisory"
            ]
          }
        ],
        "descriptions": [
          {
            "lang": "en",
            "value": "A stored cross-site scripting (XSS) vulnerability in Palo Alto Networks PAN-OS® software enables a malicious authenticated administrator to store or execute a JavaScript payload using the web interfac"
          }
        ],
        "problemTypes": [
          {
            "descriptions": [
              {
                "lang": "en",
                "cweId": "CWE-79",
                "description": "CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                "type": "CWE"
              }
            ]
          }
        ]
      }
    }
  }
};
