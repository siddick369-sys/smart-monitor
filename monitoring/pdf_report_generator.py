import os
import io
import time
from typing import List, Optional, Dict
from xml.sax.saxutils import escape as xml_escape
import config

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, HRFlowable, KeepTogether

class PDFReportGenerator:
    """Générateur professionnel de rapports de sécurité d'incidents et de synthèses d'activité en PDF."""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        # Styles personnalisés professionnels
        self.title_style = ParagraphStyle(
            'ReportTitle',
            parent=self.styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=4
        )
        self.subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569"),
            spaceAfter=12
        )
        self.section_title = ParagraphStyle(
            'SectionTitle',
            parent=self.styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=12,
            spaceAfter=6
        )
        self.body_style = ParagraphStyle(
            'ReportBody',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#1e293b")
        )
        self.body_bold = ParagraphStyle(
            'ReportBodyBold',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#0f172a")
        )
        self.footer_style = ParagraphStyle(
            'ReportFooter',
            parent=self.styles['Normal'],
            fontName='Helvetica-Oblique',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#64748b")
        )

    def generate_incident_report(self, incident: dict) -> bytes:
        """Génère un rapport PDF complet d'un incident de sécurité avec sa preuve photo intégrée."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )
        story = []

        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        alert_id = xml_escape(str(incident.get("id", "N/A")))
        device_name = xml_escape(str(incident.get("device_name", "Inconnu")))
        device_ip = xml_escape(str(incident.get("device_ip", "127.0.0.1")))
        severity = xml_escape(str(incident.get("severity", "INFO")))
        event_code = str(incident.get("event_code", "SIMULATED_EVENT"))
        raw_cat = incident.get("category", config.EVENT_CODES.get(event_code, "ÉVÉNEMENT"))
        category = xml_escape(str(raw_cat))
        raw_date = incident.get("datetime") or time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(incident.get("timestamp", time.time())))
        date_str = xml_escape(str(raw_date))
        details = xml_escape(str(incident.get("details", "Aucun détail complémentaire.")))
        type_str = xml_escape(str(incident.get("type", "N/A")))
        status_str = xml_escape(str(incident.get("status", "TERMINÉ")))

        is_simulated = (event_code == "SIMULATED_EVENT" or "SIMULÉ" in category.upper())

        # 1. En-tête officiel
        story.append(Paragraph("SMART SECURITY MONITOR // RAPPORT D'INCIDENT", self.title_style))
        story.append(Paragraph(f"Dossier de preuve officiel — Réf. <b>{alert_id}</b> — Édité le {now_str}", self.subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=14))

        # 2. Badge de qualification Réel vs Simulé
        if is_simulated:
            badge_html = "<font color='#b45309'><b>[SIMULATION ACADÉMIQUE / TEST CONTRÔLÉ]</b></font> Cet événement a été injecté à des fins de test ou de démonstration."
            badge_bg = colors.HexColor("#fef3c7")
            badge_border = colors.HexColor("#f59e0b")
        else:
            badge_html = "<font color='#991b1b'><b>[INTRUSION / ÉVÉNEMENT PHYSIQUE RÉEL]</b></font> Cet événement provient d'une détection matérielle réelle sur smartphone."
            badge_bg = colors.HexColor("#fee2e2")
            badge_border = colors.HexColor("#ef4444")

        badge_table = Table([[Paragraph(badge_html, self.body_style)]], colWidths=[520])
        badge_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), badge_bg),
            ('BOX', (0,0), (-1,-1), 1, badge_border),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ]))
        story.append(badge_table)
        story.append(Spacer(1, 14))

        # 3. Tableau Récapitulatif des Métadonnées
        meta_data = [
            [Paragraph("<b>Identifiant Incident</b>", self.body_style), Paragraph(alert_id, self.body_style),
             Paragraph("<b>Date & Heure</b>", self.body_style), Paragraph(date_str, self.body_style)],
            [Paragraph("<b>Smartphone Source</b>", self.body_style), Paragraph(device_name, self.body_style),
             Paragraph("<b>Adresse IP Hôte</b>", self.body_style), Paragraph(device_ip, self.body_style)],
            [Paragraph("<b>Type Détection</b>", self.body_style), Paragraph(type_str, self.body_style),
             Paragraph("<b>Niveau Gravité</b>", self.body_style), Paragraph(f"<b>{severity}</b>", self.body_style)],
            [Paragraph("<b>Classification</b>", self.body_style), Paragraph(category, self.body_style),
             Paragraph("<b>Statut Traitement</b>", self.body_style), Paragraph(status_str, self.body_style)],
        ]
        meta_table = Table(meta_data, colWidths=[110, 150, 110, 150])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 14))

        # 4. Description et Données de Capteurs
        story.append(Paragraph("Détails Techniques et Télémétrie Mesurée", self.section_title))
        desc_p = Paragraph(f"<b>Circonstances :</b> {details}", self.body_style)
        
        meas_val = incident.get("measured_value")
        thresh_val = incident.get("threshold")
        val_str = xml_escape(f"{meas_val}") if meas_val is not None else "Non disponible"
        thresh_str = xml_escape(f"{thresh_val}") if thresh_val is not None else "Standard"

        telemetry_rows = [
            [Paragraph("<b>Paramètre Mesuré</b>", self.body_bold), Paragraph("<b>Valeur Enregistrée</b>", self.body_bold), Paragraph("<b>Seuil d'Alerte</b>", self.body_bold)],
            [Paragraph(type_str, self.body_style), Paragraph(val_str, self.body_style), Paragraph(thresh_str, self.body_style)]
        ]
        telemetry_table = Table(telemetry_rows, colWidths=[180, 170, 170])
        telemetry_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))

        story.append(desc_p)
        story.append(Spacer(1, 6))
        story.append(telemetry_table)
        story.append(Spacer(1, 14))

        # 5. Preuve Visuelle (Photo instantanée JPEG)
        story.append(Paragraph("Preuve Visuelle Instantanée (JPEG HD)", self.section_title))
        scr_path = incident.get("screenshot_path")
        embedded_img = False
        img_box = None

        if scr_path:
            full_scr = os.path.join(config.BASE_DIR, scr_path)
            if os.path.exists(full_scr) and os.path.getsize(full_scr) > 0:
                try:
                    # Intégration de l'image (format largeur 460 x hauteur 280)
                    img = Image(full_scr, width=460, height=280)
                    img_box = Table([[img]], colWidths=[520])
                    img_box.setStyle(TableStyle([
                        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#000000")),
                        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#334155")),
                        ('PADDING', (0,0), (-1,-1), 4),
                    ]))
                    story.append(img_box)
                    embedded_img = True
                except Exception as e:
                    print(f"[PDF] Erreur intégration image : {e}")

        if not embedded_img:
            no_img_box = Table([[Paragraph("<i>Aucune capture d'image archivée ou flux vidéo non disponible pour cet incident.</i>", self.body_style)]], colWidths=[520])
            no_img_box.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
                ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#94a3b8")),
                ('PADDING', (0,0), (-1,-1), 12),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ]))
            story.append(no_img_box)

        # 6. Clip Vidéo associé et Rétention
        story.append(Spacer(1, 10))
        rec_path = incident.get("recording_path")
        rec_info = f"<b>Enregistrement vidéo associé :</b> {xml_escape(str(rec_path or 'Aucun fichier vidéo archivé'))}"
        story.append(Paragraph(rec_info, self.body_style))

        # 6.1 Intégrité Cryptographique SHA-256
        sha256_hash = incident.get("sha256_hash")
        if sha256_hash:
            story.append(Spacer(1, 6))
            sha_p = Paragraph(f"<b>Empreinte SHA-256 certifiée de la preuve :</b> <font face='Courier' size='7'>{xml_escape(str(sha256_hash))}</font>", self.body_style)
            sha_box = Table([[sha_p]], colWidths=[520])
            sha_box.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f0fdf4")),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#22c55e")),
                ('PADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(sha_box)

        # 7. Pied de page légal et universitaire
        story.append(Spacer(1, 18))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=6))
        story.append(Paragraph("Smart Security Monitor — Plateforme Universitaire TP4 — Conforme aux exigences d'audit et d'intégrité des preuves.", self.footer_style))

        try:
            doc.build(story)
        except Exception as e:
            print(f"[PDF] Exception doc.build incident report : {e}, tentative sans média...")
            buffer = io.BytesIO()
            doc_fallback = SimpleDocTemplate(
                buffer, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
            )
            fallback_story = []
            for item in story:
                if img_box is not None and item is img_box:
                    fallback_story.append(Table([[Paragraph("<i>[Preuve visuelle non restituable : format d'image non valide]</i>", self.body_style)]], colWidths=[520]))
                else:
                    fallback_story.append(item)
            try:
                doc_fallback.build(fallback_story)
            except Exception as e2:
                print(f"[PDF] Exception critique doc_fallback : {e2}")
                buffer = io.BytesIO()
                doc_min = SimpleDocTemplate(buffer, pagesize=A4)
                doc_min.build([
                    Paragraph("SMART SECURITY MONITOR // RAPPORT D'INCIDENT", self.title_style),
                    Paragraph(f"Réf. {alert_id} - Gravité : {severity}", self.body_bold),
                    Paragraph(f"Détails : {details}", self.body_style)
                ])

        return buffer.getvalue()

    def generate_summary_report(self, alerts: List[dict], period_label: str = "Période complète", stats: Optional[dict] = None) -> bytes:
        """Génère un rapport de synthèse journalier ou périodique des alertes avec statistiques."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )
        story = []

        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        total_count = len(alerts)

        # Calcul des statistiques si non fournies
        crit_count = sum(1 for a in alerts if a.get("severity") == "CRITIQUE")
        warn_count = sum(1 for a in alerts if a.get("severity") == "AVERTISSEMENT")
        info_count = sum(1 for a in alerts if a.get("severity") == "INFO")

        real_count = sum(1 for a in alerts if a.get("event_code") == "REAL_SENSOR_EVENT")
        video_count = sum(1 for a in alerts if a.get("event_code") == "VIDEO_MOTION_EVENT")
        sim_count = sum(1 for a in alerts if a.get("event_code") == "SIMULATED_EVENT" or "SIMULÉ" in a.get("category", "").upper())

        devices_set = set(a.get("device_name", "Inconnu") for a in alerts)
        devices_str = xml_escape(", ".join(sorted(devices_set)) if devices_set else "Aucun appareil")
        period_label_esc = xml_escape(str(period_label))

        # 1. En-tête de Synthèse
        story.append(Paragraph("SMART SECURITY MONITOR // SYNTHÈSE DES ALERTES", self.title_style))
        story.append(Paragraph(f"Rapport d'activité consolidé — Filtre : <b>{period_label_esc}</b> — Édité le {now_str}", self.subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=14))

        # 2. Tableau KPI Récapitulatif
        kpi_data = [
            [Paragraph("<b>Total Incidents</b>", self.body_bold), Paragraph(str(total_count), self.body_style),
             Paragraph("<b>Alertes Critiques</b>", self.body_bold), Paragraph(f"<font color='#dc2626'><b>{crit_count}</b></font>", self.body_style)],
            [Paragraph("<b>Avertissements</b>", self.body_bold), Paragraph(str(warn_count), self.body_style),
             Paragraph("<b>Informations / Syst.</b>", self.body_bold), Paragraph(str(info_count), self.body_style)],
            [Paragraph("<b>Capteurs Réels</b>", self.body_bold), Paragraph(str(real_count), self.body_style),
             Paragraph("<b>Détections Vidéo</b>", self.body_bold), Paragraph(str(video_count), self.body_style)],
            [Paragraph("<b>Simulations TP</b>", self.body_bold), Paragraph(str(sim_count), self.body_style),
             Paragraph("<b>Smartphones Impliqués</b>", self.body_bold), Paragraph(str(len(devices_set)), self.body_style)],
        ]
        kpi_table = Table(kpi_data, colWidths=[120, 140, 130, 130])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 10))
        story.append(Paragraph(f"<b>Périmètre des appareils :</b> {devices_str}", self.body_style))
        story.append(Spacer(1, 14))

        # 3. Tableau Détaillé des Incidents
        story.append(Paragraph(f"Journal Chronologique des Événements ({min(total_count, 35)} derniers)", self.section_title))

        table_header = [
            Paragraph("<b>Date / Heure</b>", self.body_bold),
            Paragraph("<b>Smartphone</b>", self.body_bold),
            Paragraph("<b>Type / Motif</b>", self.body_bold),
            Paragraph("<b>Gravité</b>", self.body_bold),
            Paragraph("<b>Nature</b>", self.body_bold)
        ]
        table_rows = [table_header]

        for a in alerts[:35]: # Limiter à 35 pour garder le PDF concis et lisible
            d_time = xml_escape(str(a.get("datetime", "N/A")))
            d_name = xml_escape(str(a.get("device_name", "Inconnu")))
            d_type = xml_escape(str(a.get("type", "INCIDENT")))
            d_sev = xml_escape(str(a.get("severity", "INFO")))
            is_sim = (a.get("event_code") == "SIMULATED_EVENT" or "SIMULÉ" in str(a.get("category", "")).upper())
            nature_lbl = "<font color='#b45309'>Simulé</font>" if is_sim else "<font color='#16a34a'><b>Réel</b></font>"

            table_rows.append([
                Paragraph(d_time, self.body_style),
                Paragraph(d_name, self.body_style),
                Paragraph(d_type, self.body_style),
                Paragraph(d_sev, self.body_style),
                Paragraph(nature_lbl, self.body_style)
            ])

        if len(table_rows) == 1:
            table_rows.append([Paragraph("<i>Aucun incident enregistré sur cette période.</i>", self.body_style), "", "", "", ""])

        events_table = Table(table_rows, colWidths=[110, 110, 140, 80, 80])
        events_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0,0), (-1,-1), 4),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story.append(events_table)

        # 4. Pied de page
        story.append(Spacer(1, 16))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=6))
        story.append(Paragraph("Smart Security Monitor — Synthèse officielle certifiée conforme aux journaux d'événements du serveur hôte.", self.footer_style))

        try:
            doc.build(story)
        except Exception as e:
            print(f"[PDF] Exception build summary report : {e}")
            buffer = io.BytesIO()
            doc_min = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
            doc_min.build([
                Paragraph("SMART SECURITY MONITOR // SYNTHÈSE DES ALERTES", self.title_style),
                Paragraph(f"Période : {period_label_esc} — Total incidents : {total_count}", self.body_bold),
                Paragraph("Rapport généré en mode de sécurité simplifié suite à une anomalie de composition.", self.body_style)
            ])

        return buffer.getvalue()
