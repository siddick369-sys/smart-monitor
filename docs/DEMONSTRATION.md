# Scénario de Démonstration en Classe (5 à 7 minutes)

Guide minuté pour présenter avec succès le projet **SMART SECURITY MONITOR** devant un jury universitaire.

---

## 1. Déroulement Chronométré de la Soutenance

| Temps | Étape | Manipulation Étudiant | Ce qui s'affiche & Effet sonore | Argument Technique à Présenter |
|---|---|---|---|---|
| **00:00 - 01:30** | **1. Présentation de l'Architecture** | Projeter le tableau de bord (`http://127.0.0.1:5000`). Montrer les téléphones posés sur la table. | Statut **OPÉRATIONNEL** en vert. Compteur de smartphones et capteurs actifs. | Expliquer le découpage : PC centralisé en Monitoring Host (Flask + OpenCV) et téléphones Android en nœuds IoT distribués. |
| **01:30 - 03:00** | **2. Surveillance & Télémétrie en Direct** | Montrer la fluidité des flux vidéo MJPEG et les cartes de télémétrie. | Les valeurs de proximité, son et accéléromètre évoluent en direct avec sparklines. | Mettre en avant la tolérance aux pannes : si un capteur manque, il est marqué `CAPTEUR NON DISPONIBLE` sans inventer de valeur ni faire crasher le système. |
| **03:00 - 04:30** | **3. Démonstration d'Intrusion Réelle** | Vérifier que le système est **ARMÉ**.<br>1. Déplacer la main devant l'objectif pour tester le **Mouvement OpenCV**.<br>2. Taper dans les mains pour tester l'**Alerte Acoustique**. | **Effet saisissant :**<br>- Sirène sonore du PC retentit via `winsound`.<br>- Bandeau rouge clignotant en haut.<br>- La torche du smartphone s'allume (si compatible). | Expliquer le rôle du moteur de détection : soustraction différentielle de fond OpenCV, seuillage, et anti-rebond (8s) évitant le mitraillage d'alertes. |
| **04:30 - 05:30** | **4. Arrêt de la Sirène & Preuves** | Cliquer sur **« ARRÊTER LA SIRÈNE »**. Descendre au Centre des Incidents. | La sirène se coupe instantanément sans couper la vidéo. L'alerte apparaît en tête de liste avec sévérité `CRITIQUE`. | Démontrer l'efficacité du **tampon circulaire en mémoire** : ouvrir la vidéo MP4 et montrer qu'on voit les 3 secondes **avant** l'intrusion et les 5 secondes après. |
| **05:30 - 06:30** | **5. Mode Simulation & Filtrage** | Cliquer sur le menu **« SIMULER »** et injecter un choc accéléromètre. Montrer les filtres du tableau. | L'incident porte le badge violet `ÉVÉNEMENT SIMULÉ` (distinction nette des mesures physiques). | Souligner la rigueur méthodologique : séparation stricte entre données physiques réelles et injections logicielles. Télécharger l'export CSV. |
| **06:30 - 07:00** | **6. Conclusion & Questions** | Montrer la section des seuils configurables en direct. | Les seuils sont modifiables sans redémarrer le serveur. | Conclure sur la robustesse du système (multithreading, anti-SSRF, isolation des caméras). |

---

## 2. Plan de Secours en Cas d'Imprévu Réseau

> [!WARNING]
> **Scénario de secours (Wi-Fi défaillant ou pas de smartphone disponible) :**
> Si le réseau universitaire refuse la communication entre le PC et les téléphones (*AP Client Isolation*) :
> 1. Cliquez sur le bouton violet **« Ajouter Simulateur Mock »** en haut de la console.
> 2. Le simulateur local (`http://127.0.0.1:8081`) est immédiatement intégré.
> 3. Il produit un flux vidéo animé avec une cible en mouvement, des capteurs réalistes et une torche virtuelle.
> 4. Vous pouvez exécuter 100% de la démonstration avec le jury en toute sérénité !
