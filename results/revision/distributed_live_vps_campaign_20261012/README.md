# Campagne live distribuée — 12 octobre 2026

## Résultat vérifié

Le run `COSE-LIVE-DIST-20261012-07` a exécuté un scénario ordonné entre trois instances distinctes : le poste Windows comme source A, le VPS Ubuntu `157.173.116.245` comme source B et le VPS Ubuntu `194.163.169.17` comme contrôleur. Le contrôleur était lié à `127.0.0.1`; les sources l’ont rejoint par tunnels SSH. Aucun port de campagne n’a été ouvert publiquement et aucun paquet ni service n’a été installé.

Les opérations réellement exécutées étaient une lecture d’un fichier de fixture, l’exécution d’un processus Python enfant et une connexion TCP au contrôleur. Elles étaient bénignes et ordonnées pour exercer la règle temporelle déclarée. Les trois événements ont été reçus et validés : 3 observés, 3 engagés, 0 en attente, 0 doublon, 0 lacune, 0 erreur. Le retard maximal réception/événement est de 1,112 s, pour une limite configurée de 1,5 s. Le replay canonique indépendant et la restauration du checkpoint reproduisent les trois décisions; la dernière est la violation attendue `DENY_READ_EXEC_CONNECT`.

Ce résultat prouve une intégration distribuée de bout en bout pour un scénario fixe. Il ne mesure pas l’efficacité de détection d’attaques, ne crée aucun TP/FP/F1 et ne transforme pas le résultat négatif P1. Le processus Python enfant et la règle de test ne sont pas un capteur IDS ni un déploiement opérationnel. La validation d’horloge locale est un échantillonnage avant l’essai; la dérive n’a pas été bornée en continu. L’ingestion suppose des identités et des horodatages fiables; le tunnel SSH protège le transport mais le protocole applicatif ne signe pas les identités de source.

Les deux VPS sont des instances séparées, mais elles sont hébergées chez le même fournisseur Contabo et leur placement sur hyperviseurs/zones différents n’a pas été vérifié. Le compte OVH fourni est un hébergement mutualisé sans privilège root et n’a pas été retenu comme nœud.

## Prévol des machines

| Nœud | État vérifié | Ressources observées | Usage |
|---|---|---|---|
| Poste local | Windows 10, Python 3.11.9; NTP mesuré avant le run | — | Source A |
| `157.173.116.245` | Ubuntu 24.04.3; compte `administrator` avec sudo; NTP actif | 6 vCPU, 11 Go RAM, 7,2 Go disponibles, 75 Go libres | Source B |
| `194.163.169.17` | Ubuntu 24.04.4; accès root; NTP actif | 4 vCPU, 7,8 Go RAM, 6,4 Go disponibles, 82 Go libres | Contrôleur |
| OVH `ssh.cluster100.hosting.ovh.net` | Authentification réussie; UID non privilégié, hébergement mutualisé | Pas un VPS administrable | Exclu |

Écarts NTP mesurés sur le poste Windows avant le run : `+0.0391403`, `−0.0769099`, `+0.0443218`, `+0.0388764`, `+0.0490728` seconde. Les deux VPS indiquaient `NTPSynchronized=yes`. Cette mesure préalable ne remplace pas une mesure continue pendant une campagne longue.

## Tentatives écartées

Les tentatives `02` à `06` restent archivées dans leurs sous-répertoires comme diagnostics d’infrastructure. Elles ont été incomplètes à cause d’un collecteur détaché tué par la session SSH, d’un watermark terminal initial trop court, d’un tunnel inactif ou d’un démarrage distant après la cible. Le contrôleur a laissé les enregistrements non couverts en attente. Elles sont exclues des résultats présentés; le run 07 seul passe toutes les vérifications.

Le changement de watermark terminal dans `revision_COSE_2026/code/experiments/revision_distributed_lab.py` a été testé par les six profils locaux : statuts attendus 6/6 et rejeu de checkpoint 6/6. La campagne live a ensuite utilisé ce lanceur mis à jour.

## Artefacts du run 07

- `run07/config.json` : configuration figée et cible UTC.
- `run07/source_A.json`, `run07/source_B.json` : journaux de source et accusés de réception.
- `run07/controller_result.json`, `run07/checkpoint.json` : journal consolidé et état restaurable.
- `run07/canonical_replay.json` : replay des décisions par l’évaluateur de référence.
- `run07/campaign_manifest.json` : vérifications et SHA-256.
- `run07/verify_campaign.py` : vérificateur reproductible (tous les contrôles doivent passer).

## Suite nécessaire pour traiter P1

Le run réel d’intégration n’est pas la campagne d’évaluation indépendante demandée pour P1. Il reste à concevoir P3 sur entraînement/validation uniquement, arrêter à l’avance le budget d’alertes et les coûts d’erreur, instrumenter des capteurs appropriés, établir une vérité terrain complète pour les scénarios bénins et d’attaque isolés, puis comparer P0/P1/P3 sur plusieurs périodes indépendantes aux niveaux événement, processus et incident. Il faut geler les règles, seuils, code et empreintes avant le test final; aucune métrique d’efficacité ne doit être tirée du run 07.

Les identifiants SSH ont été transmis en clair dans la conversation. L’auteur doit les faire tourner maintenant que l’accès de campagne est terminé et remplacer ensuite les mots de passe par des clés dédiées.
