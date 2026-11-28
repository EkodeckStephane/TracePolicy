# Rapport final d’audit scientifique Q1 — 28 novembre 2026

## Décision

**NO-GO pour une nouvelle soumission à Computers & Security dans l’état scientifique actuel.** Les sources et PDFs de soumission sont à présent synchronisés, et les nouveaux résultats ont été ajoutés au paquet auteur. Les preuves disponibles ne lèvent toujours pas le risque central de nouveauté et de portée scientifique soulevé par le rejet du 9 octobre 2026. Ce rapport évalue la maturité scientifique documentée; il ne prédit pas la décision éditoriale.

Le registre structuré des portes figure dans `audit/FINAL_SCIENTIFIC_GATE_STATUS.json`. Le statut `PASS` est limité aux exigences effectivement vérifiées dans leur périmètre. Les statuts `NOT VERIFIED` signalent l’absence de preuve suffisante pour le périmètre revendiqué.

## Éléments vérifiés dans cette continuation

- Le modèle sémantique indépendant avait contrôlé 94 160 paires politique/trace, 1 401 136 masques et 71 752 explications avec témoins, sans divergence dans son domaine généré. Ce contrôle est fini et borné; il ne prouve pas les propriétés pour toute politique ni pour tout état initial.
- L’ablation E-only/R-only/Union/E+R a été étendue à 239 alertes provenant de 120 strates non vides sur 30 workloads figés. Les 335 unions séparées étaient suffisantes dans le domaine conjoint; chaque cas possédait au moins une union égale à un noyau conjoint minimal. Les neuf fixtures contrôlées fournissent 11 unions suffisantes. Le contre-exemple sémantique construit montre toujours deux unions croisées insuffisantes sur quatre. Le corpus observé n’établit pas une défaillance fréquente; le contre-exemple ne mesure pas sa fréquence opérationnelle.
- Trois modifications de politique préspécifiées ont été rejouées sur toutes les fenêtres consécutives de cinq événements des 30 flux Docker figés, sans filtrage par étiquette d’attaque. Les décisions changent sur 604 fenêtres pour le seuil de brute force 4→3, 693 pour 4→5 et 179 après suppression de `D_ADMIN`. Les explications ordinaires de chaque version ont été vérifiées sur un cas représentatif par modification. Un nouveau pilote exhaustif définit une explication appariée des classes avant/après sur ces trois cas représentatifs; la suppression de `D_ADMIN` est alors expliquée par `{e:4, d:D_ADMIN.presence}`, même si le noyau ordinaire de la classe `Gap` est vide. Le pilote reste un AXp pair-valué exploratoire sur trois fenêtres, sans preuve de nouveauté ni d’utilité.
- Le manuscrit rapporte l’échantillon étendu et le replay. La réponse aux reviewers et la cover letter sont alignées. Le contrôle PDF relève zéro texte hors page, zéro citation/référence non résolue, 18 points de réponse et les longueurs finales 25/6/1 pages. La boîte verticale bibliographique de 20,998 pt reste signalée par LaTeX, sans rognage visuel observé.
- L’archive auteur mise à jour compte 1 991 membres; 1 986 empreintes sont vérifiées, avec trois références soumises vérifiées, zéro erreur CRC et zéro divergence de manifeste. Le snapshot scientifique testé est le commit `c6fb027fba1102768015a5dda1bf322bd6cefc34`; CI `46142868690` réussie.

Les fichiers `audit/COMPOSABILITY_ANALYSIS.md`, `audit/POLICY_VERSION_DIFFERENTIAL_ANALYSIS.md`, `audit/FORMAL_VERIFICATION_REPORT.md`, `audit/SOTA_SYSTEMATIC_REVIEW.md`, `audit/SCIENTIFIC_GAP_REGISTER.csv` et `audit/REVISION_ROADMAP.md` contiennent les détails et limites par sujet.

## Motifs du NO-GO

La vérification directe des textes intégraux précise le risque de nouveauté : le diagramme de changement de Margrave représente déjà les paires ordonnées de résultats de politiques et les régions de requêtes correspondantes; le pilote TracePolicy se ramène en outre à un AXp contraint sur une fonction à sortie paire. La différence candidate réside dans les interventions locales conjointes sur événements temporels et éditions explicites, sans résultat nouveau de classe de politiques ni avantage diagnostique mesuré à ce jour. Le rapport de correspondance et le protocole de comparaison figurent dans `audit/DIRECT_BASELINE_MAPPING_MARGRAVE_AXP_2026-11-28.md`.

1. **Nouveauté et importance.** La littérature établit déjà les explications de politiques, l’abduction conjointe de faits et règles pour d’autres objectifs, les AXp/CXp, le rejeu et le différentiel sémantique de politiques, ainsi que la comparaison d’explications entre modèles adaptés. Le pilote apparié de TracePolicy se ramène lui-même à un AXp sur une sortie paire; il distingue une intervention d’événements/édition, mais n’établit ni une propriété théorique nouvelle ni une utilité supérieure. La contribution centrale reste une instanciation possible, dont l’importance et la portée ne sont pas démontrées.
2. **Valeur empirique du joint.** Dans l’échantillon Docker étendu, la composition de noyaux séparés a préservé la décision pour toutes les unions observées. L’étude soutient l’exactitude du domaine conjoint et établit un contre-exemple de non-composabilité universelle, mais n’établit ni un gain empirique fréquent ni une amélioration d’utilité.
3. **Versionnement.** Le replay confirme que les trois mises à jour changent des décisions observées. Un pilote définit et vérifie une explication minimale de la paire ordonnée avant/après pour trois fenêtres sélectionnées; cet objet se ramène à un AXp pair-valué et reste sans comparaison directe à Margrave, sans holdout indépendant ni mesure d’utilité.
4. **Validation externe et reproductibilité.** Les expériences étendues utilisent le même corpus local figé et un échantillonnage conditionnel aux alertes pour l’ablation. Il manque une confirmation indépendante, non conditionnée aux alertes, sur des politiques opérationnelles réalistes. Le verrouillage transitif des dépendances et une reproduction complète depuis un clone propre ne sont pas achevés.
5. **Adéquation éditoriale.** Le moratoire public de la revue sur les soumissions où l’AI/ML constitue une composante significative pourrait concerner le cadrage XAI du manuscrit. L’application de cette politique à TracePolicy reste incertaine; le Guide for Authors détaillé n’a pas pu être consulté lors de l’audit.

## Portes de décision

| Porte | Statut | Conclusion vérifiable |
|---|---|---|
| G0 — critiques des reviewers | NOT VERIFIED | Les 18 réponses sont présentes et les documents sont cohérents; plusieurs objections scientifiques restent non résolues par des preuves. |
| G1 — originalité centrale | NOT VERIFIED | Artelt et al. expliquent déjà les changements de systèmes par comparaison d’explications; le nouvel objet événement/édition est un AXp pair-valué dont la distinction et l’utilité restent à établir. |
| G2 — preuves et hypothèses | NOT VERIFIED | Des preuves et un vérificateur fini existent; l’audit indépendant exhaustif des théorèmes et des cas limites n’est pas terminé. |
| G3 — valeur de l’explication conjointe | NOT VERIFIED | Le corpus étendu ne montre pas d’échec de composition; le témoin construit ne donne pas une fréquence opérationnelle. |
| G4 — composabilité | NOT VERIFIED | Le critère exact se ramène à la présence d’un noyau conjoint minimal; aucune caractérisation structurelle utile de classe de politiques n’est établie. |
| G5 — comparaison équitable au SOTA | NOT VERIFIED | Plusieurs comparateurs sont évalués, mais la cartographie native/adaptée/certifiée et l’équité ne sont pas auditées pour tous les travaux pertinents. |
| G6 — ablation essentielle | PASS | Les quatre configurations et familles de noyaux ont été évaluées dans le périmètre Docker/fixtures, avec vérification de toutes les unions échantillonnées et intégration au manuscrit. |
| G7 — passage à l’échelle | PASS | Le prototype borne l’énumération à 18 unités et rapporte une campagne contrôlée de 126 exécutions sur 5–18 unités; les revendications restent bornées à ce périmètre. |
| G8 — validation externe | NOT VERIFIED | Aucun jeu de confirmation indépendant adapté à l’estimand revendiqué n’est établi. |
| G9 — valeur du versionnement | NOT VERIFIED | Un pilote apparié vérifié sur trois fenêtres identifie les événements et l’édition nécessaires à la paire exacte de décisions; sa nouveauté, sa généralisation, ses comparateurs directs et son utilité restent ouverts. |
| G10 — pertinence opérationnelle/distribuée | NOT VERIFIED | Les preuves système sont bornées; perturbations distribuées complètes et bénéfice analyste mesuré manquent. |
| G11 — cohérence revendications/preuves | NOT VERIFIED | Les documents récents et résultats ajoutés sont alignés; la matrice complète C01–C13 et toutes les dépendances ne sont pas clôturées. |
| G12 — snapshot reproductible | NOT VERIFIED | Commit, CI et manifeste de paquet sont vérifiés; la reproduction complète depuis un clone propre avec environnement transitif verrouillé reste incomplète. |
| G13 — références vérifiées | NOT VERIFIED | Les références proches ont été contrôlées à partir de textes intégraux; une vérification documentée exhaustive de toute la bibliographie reste à achever. |
| G14 — limites et résultats défavorables | NOT VERIFIED | Le résultat de composabilité défavorable à un avantage pratique et les limites de versionnement sont rapportés; le registre complet des résultats négatifs reste à vérifier. |
| G15 — exigences de la revue | NOT VERIFIED | Le statut du moratoire AI/ML et les instructions éditoriales actuelles ne sont pas confirmés. |

Deux portes vérifiées sur leur périmètre limité ne compensent pas les portes scientifiques encore ouvertes. **La décision demeure NO-GO.**

## Travaux qui peuvent modifier la décision

1. Établir une contribution théorique ou empirique qui se distingue des AXp, du replay versionné et de l’analyse sémantique de changements de politiques, au-delà de l’objet défini.
2. Comparer le pilote apparié à Margrave et aux méthodes AXp génériques; caractériser ses garanties au-delà de la définition générique et évaluer des mises à jour réalistes sur des politiques indépendantes.
3. Exécuter un protocole gelé sur un holdout indépendant avec politiques réalistes et comparaison équitable; conserver les résultats défavorables.
4. Terminer l’audit des preuves, de C01–C13, des références, des dépendances transitives et de la reproduction en clone propre.
5. Confirmer auprès de la revue que le cadrage actuel relève bien de son périmètre éditorial avant dépôt.

## Mise à jour du contrôle éditorial et du paquet final

La page officielle Elsevier confirme le moratoire de la revue sur les soumissions où l'IA/ML constitue une composante significative. TracePolicy décrit un détecteur déterministe à règles explicites, mais la contribution centrale reste l'explicabilité en détection d'intrusion. Faute de précision publique sur ce cas limite, G15 demeure NOT VERIFIED; l'audit détaillé et la source sont dans `audit/JOURNAL_SCOPE_GATE_2026-11-27.md`. Le Guide for Authors ScienceDirect a renvoyé HTTP 403 et l'équipe éditoriale n'a pas été contactée.

## Résultat exploratoire ajouté après la décision

Un prototype réversible modélise explicitement les unités d’édition et conserve la paire exacte de classes alertes calculées avant/après neutralisation commune des événements. Les 64 affectations de chacun des trois cas ont été explorées; une procédure de vérification par réénumération a retrouvé les trois familles minimales et validé tous les témoins de suppression. La CI inclut ces commandes. Cette vérification partage encore l’évaluateur de référence et le constructeur de mises à jour; elle valide l’énumération finie et les certificats, pas une seconde sémantique.

Le pilote apporte un objet concret à comparer aux travaux antérieurs et explique l’édition `D_ADMIN` que le noyau `Gap` n’identifie pas. Comme l’objet est un AXp sur une fonction à sortie paire, ce résultat ne démontre pas encore une contribution originale distincte. Il n’est pas intégré au manuscrit ni à la réponse/cover letter. Les portes G1, G3, G5 et G9 restent NOT VERIFIED et le verdict ne change pas.

Le commit `f5f09345bcd66b90bc77af043c67d540543588d3` identifie le snapshot scientifique des campagnes expérimentales. Le commit `c6fb027fba1102768015a5dda1bf322bd6cefc34` intègre le rapprochement Margrave/AXp, et sa CI `46142868690` réussit les vérifications disponibles.

Après synchronisation des sources, PDFs et audits, le paquet auteur contient 1 991 membres, dont 1 986 empreintes couvertes par le manifeste; vérification : zéro erreur CRC et zéro divergence de manifeste. Le SHA-256 courant est enregistré dans `bundle_verification.json`.
