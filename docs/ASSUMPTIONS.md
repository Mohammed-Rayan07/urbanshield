# Modelling assumptions

_Owner: A. One page; every number the model uses, and where it comes from._

| Item | Value | Source / rationale |
|---|---|---|
| Devices | 50 in four categories | Synthetic, placed on Mangaluru streets |
| CVE / CVSS / EPSS / KEV | ~40 real records | Pinned snapshot of NVD, FIRST EPSS, CISA KEV (`backend/data/feeds/`) |
| Exploit odds | 1 − Π(1 − EPSS) over a device's CVEs, × the control's `exploit_mult` | EPSS is the 30-day probability of exploitation in the wild; CVEs treated as independent ways in |
| Entry points | 1–3 exposed devices per scenario (uniform count, chosen without replacement); each must still pass its own exploit draw | Internet-exposed devices are the only external way in |
| Spread | Over REACH edges hop by hop; a reached device falls if its single draw beats its odds, once per scenario | A device that resists the attacker does not get re-rolled in the same attack |
| Campaign rate | 0.2 of scenarios | Mass exploitation of one CVE is common but not the norm; tunable per call (`campaign_rate`) |
| Campaign CVE | Chosen with weight EPSS × number of carriers; one draw at that CVE's EPSS decides if it fires | Attackers target widespread, likely-exploited CVEs; one exploit works on every carrier at once |
| Campaign carriers | If fired, each carrier falls when the same draw beats EPSS × its `exploit_mult`; spread continues from them over REACH (normal entry points are not used) | No controls → all carriers fall together; whether it fires never depends on controls, so plans face the same campaigns |
| Damage and cascade | Lost device costs its criticality, plus its `spread_mult` × the criticality of every device that depends on it (directly or transitively over DEPENDS) | Attributed to the lost device so the MILP's additive loss works; a dependent that is also lost directly is counted twice (see below) |
| Common random numbers | All uniforms drawn from the seed before controls are applied | Plans are compared on identical attacks; adding a control can only shrink the set of lost devices |
| Red-Team: entry points | Only the listed devices can be entry points | Models a known foothold |
| Red-Team: target category | Devices that can reach that category over REACH are 4× more likely to be picked as entry | Attacker with a goal picks footholds near it, without ignoring the rest |
| Red-Team: shared-firmware pivot | One lost member of a firmware family (`family/version` prefix) takes every member whose draw beats its `exploit_mult` (certain without a control) | Same firmware means same credentials and exploit; controls can still stop it |
| Red-Team: forced campaign CVE | Campaign scenarios all use that CVE; the share still follows `campaign_rate` | Lets the Red-Team test one specific CVE wave |
| Control costs / downtime / multipliers | _to fill_ | |

## Known simplifications

- The optimiser's loss is additive over devices and double-counts overlapping cascades; every plan is
  re-checked in the full simulator and the gap is reported (`linear_gap`).
- External attacker exploiting known vulnerabilities only; zero-days, insiders and physical attacks are out of scope.
- Probabilities are estimates for ranking decisions, not predictions.
