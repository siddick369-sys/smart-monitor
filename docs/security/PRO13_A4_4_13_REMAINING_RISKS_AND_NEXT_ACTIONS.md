# PRO13-A.4.4 — REMAINING RISKS & NEXT ACTIONS

**Mission ID :** `SSM-PRO13-A4-4-CONTROLLED-REMEDIATION-AND-SECURITY-CLOSURE-01`  
**Date / Horodatage :** 2026-11-27T08:28:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. CONDITIONS CONCRÈTES POUR LA QUALIFICATION EGRESS RÉELLE (MISSION DISTINCTE)

1. Audit final des scripts durcis (`setup_ffmpeg_egress_firewall.ps1`, `check_ffmpeg_egress_firewall.ps1`, `setup_docker_egress_host.sh`).
2. Sauvegarde et validation du plan de retour arrière (`teardown_ffmpeg_egress_firewall.ps1`).
3. Préparation d'un hôte de qualification dédié (Windows Server/Workstation dédié ou hôte Linux Docker).
4. Autorisation humaine explicite préalable.
5. Intervention administrateur contrôlée pour appliquer les règles pare-feu.
6. Tests TCP positifs et négatifs sur destinations autorisées et interdites.
7. Tests explicites IPv4 et IPv6.
8. Vérification des règles effectivement appliquées via `check_ffmpeg_egress_firewall.ps1` (`WINDOWS_EGRESS_ENFORCED`).
9. Vérification des chemins alternatifs et processus secondaires.
10. Rapport de qualification indépendant.

---

## 2. AUTRES ACTIONS DIFFÉRÉES

- Migration vers une ancre de confiance cryptographique externe (KMS / HSM / TSA RFC 3161) pour les futurs manifestes.
- Compilation locale de Tailwind CSS et externalisation des scripts inline pour supprimer `'unsafe-inline'` de la CSP.
- **Lot B PRO-13 :** Demeure strictement bloqué (`BLOCKED_PENDING_EXPLICIT_HUMAN_APPROVAL`).
