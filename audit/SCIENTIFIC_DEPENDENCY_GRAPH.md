# Graphe des dÃ©pendances scientifiques â€” TracePolicy

**Date de travail :** 2026-11-28  
**PÃ©rimÃ¨tre :** revendications C01â€“C13 de `claim_evidence_matrix.csv`, version de manuscrit et dÃ©pÃ´t examinÃ©s lors de lâ€™audit de rÃ©vision.  
**Ã‰tat :** graphe initial Ã©tabli; audit indÃ©pendant de chaque nÅ“ud amont et fermeture de G11 restent ouverts.

## Graphe de synthÃ¨se

```mermaid
flowchart TD
  A[HypothÃ¨ses A1â€“A4 et pÃ©rimÃ¨tre des interventions] --> D[DÃ©finitions trace, Ã©tat, politique versionnÃ©e, classe]
  D --> T[Garanties finies : suffisance, minimalitÃ© par inclusion, tÃ©moins]
  D --> I[Ã‰valuateur de rÃ©fÃ©rence]
  I --> X[Ã‰valuateur indexÃ©]
  I --> N[Ã‰valuateur incrÃ©mental]
  T --> E[Extracteur exhaustif, domaine limitÃ© Ã  18 unitÃ©s]
  I --> E
  E --> V[VÃ©rificateur et tests indÃ©pendants, portÃ©e finie]
  V --> R1[C01â€“C04 : sÃ©mantique, garanties, Ã©quivalence testÃ©e, Docker]
  E --> R2[C05 : ablation conjointe et unions sÃ©parÃ©es]
  D --> P[Ã‰ditions/versionnement et dÃ©cision avant-aprÃ¨s]
  P --> R3[C06, C09 : pilotes temporels et sÃ©quentiels]
  D --> L[Protocoles et granularitÃ©s des donnÃ©es externes]
  L --> R4[C07â€“C08 : LID-DS et THEIA]
  I --> R5[C10 : rejeu distribuÃ© bornÃ©]
  R1 --> C[Conclusions de validitÃ© et de calcul dans le pÃ©rimÃ¨tre mesurÃ©]
  R2 --> C
  R3 --> C
  R4 --> C
  R5 --> C
  S[SOTA, textes intÃ©graux, comparateurs Ã©quitables] --> R6[C13 : originalitÃ©]
  R6 --> C
  H[Ã‰chantillons indÃ©pendants et protocole gelÃ©] -. manquant .-> R7[C11 : gÃ©nÃ©ralisation]
  U[Ã‰tude dâ€™utilisateurs prÃ©spÃ©cifiÃ©e] -. manquante .-> R8[C12 : utilitÃ© analyste]
  V --> G[G11 : cohÃ©rence revendications/preuves]
  S --> G
  H --> G
  U --> G
  C --> G
```

## DÃ©pendances par revendication

| Revendication | DÃ©pendances nÃ©cessaires | Ã‰lÃ©ments prÃ©sents | Ã‰tat de la chaÃ®ne et limite |
|---|---|---|---|
| C01 â€” sÃ©mantique dÃ©terministe versionnÃ©e | A1â€“A4; schÃ©mas Ã©vÃ©nement/rÃ¨gle; prioritÃ©, classification, horizon; implÃ©mentation de rÃ©fÃ©rence | Manuscrit Â§Â§5â€“8; `formal/TracePolicy_Formal_Specification.tex`; `src/trace_policy_engine.py`; modÃ¨le-check fini | Soutenue dans le pÃ©rimÃ¨tre dÃ©clarÃ©. Le replay explicatif utilise lâ€™Ã©tat initial vide; transitions et interfaces gÃ©nÃ©rales ne sont pas toutes Ã©tablies. |
| C02 â€” suffisance et minimalitÃ© par inclusion | Domaine dâ€™intervention fixÃ©; oracle exact; monotonicitÃ© de la suffisance; test de chaque suppression; validitÃ© des tÃ©moins | DÃ©finitions et preuves finies dans la spÃ©cification; `min_explain_bruteforce`; vÃ©rifications de masques et tÃ©moins | Les preuves ensemblistes Ã©lÃ©mentaires sont cohÃ©rentes. La preuve exhaustive code/API est incomplÃ¨te; aucun rÃ©sultat ne signifie minimum global de cardinalitÃ© ou causalitÃ© physique. |
| C03 â€” Ã©quivalence des Ã©valuateurs | SÃ©mantique de rÃ©fÃ©rence; hypothÃ¨ses dâ€™indexation; hypothÃ¨ses dâ€™historique/transition; suites de tests et modÃ¨le indÃ©pendant | `reference_eval`, `StaticIndex`, `IncrementalEvaluator`; rapport formel; `scripts/independent_semantics_modelcheck.py` | VÃ©rifiÃ© pour les tests et domaine fini gÃ©nÃ©rÃ©. Couverture arbitraire de sÃ©lecteurs, mises Ã  jour adversariales et interfaces dâ€™Ã©tat personnalisÃ©es ouverte. |
| C04 â€” procÃ©dures dâ€™explication sur Docker | Cas sÃ©lectionnÃ©s et hachÃ©s; version de politique; cinq procÃ©dures; oracle exact; certificats de suffisance/minimalitÃ© | `results/revision/local_lab_proofmatched/`; tests; manuscript results | 120 alertes sÃ©lectionnÃ©es satisfont les contrÃ´les indiquÃ©s. DÃ©pendance aux fenÃªtres/alertes sÃ©lectionnÃ©es; aucune validation de dÃ©ploiement indÃ©pendant. |
| C05 â€” ablation Ã©vÃ©nements/rÃ¨gles/joint | Familles complÃ¨tes de noyaux sÃ©parÃ©s; unions cartÃ©siennes; Ã©valuation dans le domaine conjoint; cas non sÃ©lectionnÃ©s et contre-exemple | `experiments/revision_joint_ablation_expanded_sample.py`; `results/revision/joint_ablation_expanded_sample_v1/`; `audit/COMPOSABILITY_ANALYSIS.md` | 335/335 unions de 239 alertes et 11/11 unions de neuf fixtures suffisantes; contre-exemple construit rÃ©fute lâ€™universalitÃ©. FrÃ©quence rÃ©aliste et utilitÃ© non Ã©tablies. |
| C06 â€” explication de paire avant/aprÃ¨s | Correspondance des versions; fonction Ã  sortie paire; unitÃ©s Ã©vÃ©nement/Ã©dition; minimalitÃ©; oracle indÃ©pendant et baseline native | `experiments/revision_policy_differential.py`; rÃ©sultat appariÃ©; `audit/GENERIC_AXP_BASELINE_REPORT.md` | Trois fenÃªtres vÃ©rifiÃ©es exhaustivement; un Ã©numÃ©rateur gÃ©nÃ©rique AXp reproduit les familles. MÃªme sÃ©mantique et cas sÃ©lectionnÃ©s; preuve de mÃ©canisme seulement. |
| C07 â€” rÃ©sultat LID-DS | DonnÃ©es/scÃ©nario; protocole; split; unitÃ© dâ€™analyse recording; labels; politique action seule | `results/lidds_cve_2020_23839/label_metrics.json`; protocole de donnÃ©es | RÃ©sultat descriptif sur un scÃ©nario et un split (120/120 enregistrements avec attaque alertÃ©s). Pas dâ€™alignement Ã  lâ€™instant dâ€™exploitation ni de portÃ©e gÃ©nÃ©rale. |
| C08 â€” rÃ©sultat THEIA | DÃ©rivÃ© chronologique; labels proxy; politique de rÃ©fÃ©rence et variante; unitÃ© event-proxy; mÃ©triques recalculÃ©es | `temporal_external/results/detection_metrics.json`; rapport externe | La variante temporelle ajoute des positifs et faux positifs et prÃ©sente un F1 proxy plus faible dans cette campagne. RÃ©sultat dÃ©favorable descriptif, une campagne familiÃ¨re. |
| C09 â€” sÃ©quence BETH | RÃ¨gle/sÃ©quence; hÃ´te; labels disponibles; provenance train/validation; sÃ©lection des alertes | `results/beth_p2_trainval_2026-11-04/`; rapport BETH | Sept explications exploratoires sÃ©lectionnÃ©es avec informations train/validation; tous les Ã©vÃ©nements ont `evil=0`. Ne valide pas la dÃ©tection dâ€™attaque. |
| C10 â€” rejeu distribuÃ© | Ordonnancement, identifiants, checkpoints, synchronisation, scÃ©narios de perturbation et oracle | `audit/two_source_replay.json`; campagnes WSL2/VPS indiquÃ©es dans le gap register | Soutient seulement les scÃ©narios de laboratoire documentÃ©s. Les perturbations et conditions de dÃ©ploiement gÃ©nÃ©rales ne sont pas couvertes. |
| C11 â€” gÃ©nÃ©ralisation | Holdout indÃ©pendant, unitÃ©s dâ€™Ã©chantillonnage prÃ©spÃ©cifiÃ©es, campagnes/hÃ´tes/politiques distincts, protocole sans fuite | Jeux hÃ©tÃ©rogÃ¨nes nommÃ©s dans lâ€™article | DÃ©pendance manquante : aucun Ã©chantillon reprÃ©sentatif indÃ©pendant. Le graphe nâ€™autorise que Â« Ã©valuÃ© sur ces reprÃ©sentations Â», pas Â« gÃ©nÃ©ralise Â». |
| C12 â€” utilitÃ© analyste | Ã‰tude utilisateur prÃ©spÃ©cifiÃ©e, tÃ¢ches, critÃ¨res, population, comparaison et analyse | Aucun artefact dâ€™Ã©tude identifiÃ© | DÃ©pendance absente; ne pas revendiquer amÃ©lioration de comprÃ©hension, forensic ou performance analyste. |
| C13 â€” originalitÃ© | SOTA texte intÃ©gral; correspondance sÃ©mantique; baseline directe mÃªme tÃ¢che; propriÃ©tÃ© nouvelle ou utilitÃ© mesurÃ©e | `audit/SOTA_SYSTEMATIC_REVIEW.md`; matrice; collisions AXp/Margrave | DÃ©pendances partiellement prÃ©sentes, mais preuve dâ€™une diffÃ©rence scientifique significative absente. Reste un risque Ã©ditorial ouvert. |

## ConsÃ©quences pour le manuscrit et le statut

1. Les rÃ©sultats C01â€“C10 sont des conclusions subordonnÃ©es Ã  leurs pÃ©rimÃ¨tres de donnÃ©es, dâ€™interventions et dâ€™implÃ©mentation; ils ne permettent pas dâ€™infÃ©rer C11 ou C12.
2. Le passage de C02 Ã  une revendication dâ€™originalitÃ© C13 ne dÃ©coule pas de la validitÃ© formelle. La minimalitÃ© et lâ€™Ã©numÃ©ration exhaustive relÃ¨vent dâ€™un cadre gÃ©nÃ©rique; une propriÃ©tÃ© propre Ã  la classe de politiques doit encore Ãªtre dÃ©montrÃ©e.
3. C05 montre quâ€™une composition naÃ¯ve peut Ã©chouer dans un tÃ©moin construit, tandis quâ€™elle rÃ©ussit dans les Ã©chantillons mesurÃ©s. Ces deux dÃ©pendances doivent Ãªtre conservÃ©es ensemble dans toute conclusion.
4. C06 est logiquement distinct de lâ€™explication dâ€™une classe unique, mais son Ã©numÃ©ration est reproduite par un AXp gÃ©nÃ©rique sur la sortie paire. La distinction des unitÃ©s reste une hypothÃ¨se de contribution, pas une preuve dâ€™avantage.
5. G11 reste **NOT VERIFIED** jusquâ€™Ã  la revue par un second passage de chaque dÃ©pendance amont et jusquâ€™Ã  la synchronisation exacte de ce graphe avec le snapshot et les revendications du manuscrit.

## VÃ©rification suivante requise

Reprendre chaque arÃªte Ã  partir du code, des donnÃ©es/rÃ©sultats bruts et du texte du manuscrit sur un commit unique; consigner les divergences comme corrections ou restrictions de revendication. En particulier, vÃ©rifier les sources primaires de C03â€“C10 et les correspondances dÃ©taillÃ©es de C13. Ce graphe est un registre dâ€™audit, pas une preuve que ses dÃ©pendances sont toutes satisfaites.

