import time
import pytest
from app import create_app
import config
from monitoring.system_coordinator import SystemCoordinator
from database import get_db_session
from monitoring.models import User

def test_admin_creation_and_authentication():
    """Vérifie l'authentification de l'administrateur et la gestion de session."""
    app, coordinator = create_app()
    app.config["TESTING"] = True

    admin_pwd = config.ADMIN_DEFAULT_PASSWORD or "AdminSecurity2026!"

    with app.test_client() as client:
        # 1. Échec avec mot de passe erroné
        res_fail = client.post('/api/auth/login', json={
            "username": config.ADMIN_DEFAULT_USERNAME,
            "password": "wrong_password_123"
        })
        assert res_fail.status_code == 401
        assert "invalides" in res_fail.get_json()["message"]

        # 2. Succès avec mot de passe correct
        res_ok = client.post('/api/auth/login', json={
            "username": config.ADMIN_DEFAULT_USERNAME,
            "password": admin_pwd
        })
        assert res_ok.status_code == 200
        user_info = res_ok.get_json()["user"]
        assert user_info["username"] == config.ADMIN_DEFAULT_USERNAME
        assert user_info["role"] == "ADMIN"

        # 3. Vérification session courante
        res_me = client.get('/api/auth/me')
        assert res_me.status_code == 200
        assert res_me.get_json()["user"]["role"] == "ADMIN"

        # 4. Déconnexion
        res_logout = client.post('/api/auth/logout')
        assert res_logout.status_code == 200

    coordinator.stop()

def test_brute_force_rate_limiting():
    """Vérifie le blocage après 5 tentatives infructueuses consécutives."""
    app, coordinator = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        # 5 tentatives erronées
        for _ in range(5):
            client.post('/api/auth/login', json={"username": "attacker", "password": "bad"})

        # 6e tentative : doit être rejetée par rate-limiting
        res_blocked = client.post('/api/auth/login', json={"username": "attacker", "password": "bad"})
        assert res_blocked.status_code == 401
        assert "trop de tentatives" in res_blocked.get_json()["message"].lower()

    coordinator.stop()

def test_rbac_roles_permissions():
    """Vérifie strictement la hiérarchie des permissions (ADMIN, OPERATOR, AUDITOR)."""
    app, coordinator = create_app()
    app.config["TESTING"] = True
    auth_mgr = coordinator.auth_manager

    # Création des comptes de test
    auth_mgr.create_user("test_operator", "OperatorPass2026!", "OPERATOR")
    auth_mgr.create_user("test_auditor", "AuditorPass2026!", "AUDITOR")

    with app.test_client() as client:
        # -------------------------------------------------------------
        # 1. TEST AUDITEUR : Lecture seule, aucun contrôle opérationnel
        # -------------------------------------------------------------
        client.post('/api/auth/login', json={"username": "test_auditor", "password": "AuditorPass2026!"})
        
        # Auditeur peut consulter les alertes
        res_aud_alerts = client.get('/api/alerts')
        assert res_aud_alerts.status_code == 200

        # Auditeur NE PEUT PAS armer le système -> 403 Forbidden
        res_aud_arm = client.post('/api/alarm/arm')
        assert res_aud_arm.status_code == 403

        # Auditeur NE PEUT PAS ajouter d'appareil -> 403 Forbidden
        res_aud_dev = client.post('/api/devices', json={"name": "Dev Aud", "ip": "127.0.0.1", "port": 8080})
        assert res_aud_dev.status_code == 403

        client.post('/api/auth/logout')

        # -------------------------------------------------------------
        # 2. TEST OPÉRATEUR : Contrôle alarme, mais pas de gestion système
        # -------------------------------------------------------------
        client.post('/api/auth/login', json={"username": "test_operator", "password": "OperatorPass2026!"})

        # Opérateur PEUT armer et désarmer le système
        res_op_arm = client.post('/api/alarm/arm')
        assert res_op_arm.status_code == 200

        # Opérateur NE PEUT PAS ajouter ou supprimer un appareil -> 403 Forbidden
        res_op_dev = client.post('/api/devices', json={"name": "Dev Op", "ip": "127.0.0.1", "port": 8080})
        assert res_op_dev.status_code == 403

        # Opérateur NE PEUT PAS purger le stockage -> 403 Forbidden
        res_op_purge = client.post('/api/storage/clean', json={"days": 1})
        assert res_op_purge.status_code == 403

        client.post('/api/auth/logout')

        # -------------------------------------------------------------
        # 3. TEST ADMIN : Accès total
        # -------------------------------------------------------------
        admin_pwd = config.ADMIN_DEFAULT_PASSWORD or "AdminSecurity2026!"
        client.post('/api/auth/login', json={"username": config.ADMIN_DEFAULT_USERNAME, "password": admin_pwd})

        # Admin PEUT créer un appareil
        res_adm_dev = client.post('/api/devices', json={"name": "Dev Admin", "ip": "127.0.0.1", "port": 8080})
        assert res_adm_dev.status_code == 201
        dev_id = res_adm_dev.get_json()["device"]["id"]

        # Admin PEUT supprimer l'appareil
        res_del = client.delete(f'/api/devices/{dev_id}')
        assert res_del.status_code == 200

    coordinator.stop()

def test_bootstrap_security_and_lifecycle():
    """Vérifie le cycle de vie du bootstrap sécurisé et les protections associées."""
    app, coordinator = create_app()
    app.config["TESTING"] = True
    auth_mgr = coordinator.auth_manager

    with app.test_client() as client:
        # 1. Vérification du statut de bootstrap quand un admin existe
        res_status = client.get('/api/auth/bootstrap/status')
        assert res_status.status_code == 200
        # Puisqu'un admin existe déjà dans la base
        assert res_status.get_json()["bootstrap_required"] is False

        # 2. Tentative de bootstrap frauduleux alors qu'un admin existe -> REJET 403
        res_boot_fail = client.post('/api/auth/bootstrap', json={
            "username": "hacker_admin",
            "password": "PasswordHacker123!",
            "confirm_password": "PasswordHacker123!"
        })
        assert res_boot_fail.status_code == 403
        assert "refusée" in res_boot_fail.get_json()["message"].lower()

        # 3. Vérification de la politique de mot de passe (< 8 caractères)
        valid, msg = auth_mgr.validate_password_policy("short")
        assert valid is False
        assert "8 caractères" in msg

        # Sans chiffres
        valid, msg = auth_mgr.validate_password_policy("lettersOnlyHere")
        assert valid is False
        assert "chiffre" in msg

        # Mot de passe robuste
        valid, msg = auth_mgr.validate_password_policy("RobustPass2026!")
        assert valid is True

    coordinator.stop()
