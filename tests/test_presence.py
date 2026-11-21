import os
import time
import pytest
from unittest.mock import MagicMock, patch

from monitoring.presence_manager import PresenceManager

def test_device_crud_and_persistence(tmp_path):
    """Vérifie l'ajout, la persistance et la suppression d'appareils autorisés."""
    dev_file = str(tmp_path / "presence_devices.json")
    mgr = PresenceManager(enabled=False, devices_file=dev_file)
    
    # 1. Ajout d'appareils
    d1 = mgr.add_trusted_device(name="Smartphone Alice", ip="192.168.1.50", mac="AA:BB:CC:DD:EE:01")
    d2 = mgr.add_trusted_device(name="iPhone Bob", ip="192.168.1.51", mac="AA:BB:CC:DD:EE:02")
    
    assert len(mgr.get_trusted_devices()) == 2
    assert d1["name"] == "Smartphone Alice"
    assert os.path.exists(dev_file)
    
    # 2. Rechargement depuis le fichier
    mgr2 = PresenceManager(enabled=False, devices_file=dev_file)
    assert len(mgr2.get_trusted_devices()) == 2
    
    # 3. Suppression
    ok = mgr2.remove_trusted_device(d1["id"])
    assert ok is True
    assert len(mgr2.get_trusted_devices()) == 1

def test_absence_tolerance_and_flapping_protection(tmp_path):
    """Vérifie qu'un simple échec de ping ne déclare pas immédiatement l'appareil ABSENT."""
    dev_file = str(tmp_path / "devices.json")
    mgr = PresenceManager(enabled=False, devices_file=dev_file)
    dev = mgr.add_trusted_device("Pixel 8", "192.168.1.100")
    
    with patch.object(mgr, "ping_check", return_value=False):
        # 1er échec -> pas encore absent
        st1 = mgr.check_device_presence(dev)
        assert st1 != PresenceManager.PRESENCE_ABSENT
        
        # 2e échec -> toujours pas absent (seuil = 3)
        st2 = mgr.check_device_presence(dev)
        assert st2 != PresenceManager.PRESENCE_ABSENT
        
        # 3e échec -> bascule à ABSENT confirmée
        st3 = mgr.check_device_presence(dev)
        assert st3 == PresenceManager.PRESENCE_ABSENT
        
    with patch.object(mgr, "ping_check", return_value=True):
        # Retour immédiat
        st4 = mgr.check_device_presence(dev)
        assert st4 == PresenceManager.PRESENCE_PRESENT
        assert mgr._consecutive_misses[dev["id"]] == 0

def test_state_machine_away_pending_and_grace_period(tmp_path):
    """Vérifie le passage en AWAY_PENDING et l'armement après expiration du délai de grâce."""
    dev_file = str(tmp_path / "devices.json")
    mock_alarm = MagicMock()
    mock_alarm.is_armed.return_value = False
    
    mgr = PresenceManager(
        alarm_manager=mock_alarm,
        enabled=True,
        auto_arm=True,
        grace_period_seconds=2,
        devices_file=dev_file
    )
    dev = mgr.add_trusted_device("iPad", "192.168.1.10")
    
    # Appareil présent -> HOME
    with patch.object(mgr, "check_device_presence", return_value=PresenceManager.PRESENCE_PRESENT):
        st, _ = mgr.evaluate_state_machine()
        assert st == PresenceManager.STATE_HOME
        
    # Appareil devient absent -> AWAY_PENDING
    with patch.object(mgr, "check_device_presence", return_value=PresenceManager.PRESENCE_ABSENT):
        st, _ = mgr.evaluate_state_machine()
        assert st == PresenceManager.STATE_AWAY_PENDING
        mock_alarm.arm.assert_not_called()  # Pas encore armé pendant la période de grâce
        
        # Simulation de l'écoulement du délai de grâce
        mgr.state_entered_time = time.time() - 3.0
        st, _ = mgr.evaluate_state_machine()
        assert st == PresenceManager.STATE_ARMED_AWAY
        mock_alarm.arm.assert_called_once()

def test_return_during_grace_cancels_arming(tmp_path):
    """Vérifie que le retour d'un appareil pendant le délai de grâce annule l'armement."""
    dev_file = str(tmp_path / "devices.json")
    mock_alarm = MagicMock()
    
    mgr = PresenceManager(
        alarm_manager=mock_alarm,
        enabled=True,
        auto_arm=True,
        grace_period_seconds=10,
        devices_file=dev_file
    )
    dev = mgr.add_trusted_device("Phone", "192.168.1.20")
    
    with patch.object(mgr, "check_device_presence", return_value=PresenceManager.PRESENCE_ABSENT):
        mgr.evaluate_state_machine()
        assert mgr.current_state == PresenceManager.STATE_AWAY_PENDING
        
    # L'appareil revient avant l'expiration du délai
    with patch.object(mgr, "check_device_presence", return_value=PresenceManager.PRESENCE_PRESENT):
        mgr.evaluate_state_machine()
        assert mgr.current_state == PresenceManager.STATE_HOME
        mock_alarm.arm.assert_not_called()

def test_silent_disarm_protection_and_manual_override(tmp_path):
    """Vérifie la règle de sécurité interdisant le désarmement silencieux sans politique explicite."""
    dev_file = str(tmp_path / "devices.json")
    mock_alarm = MagicMock()
    mock_alarm.is_armed.return_value = True
    
    # auto_disarm_on_return = False (sécurisé par défaut)
    mgr = PresenceManager(
        alarm_manager=mock_alarm,
        enabled=True,
        auto_arm=True,
        auto_disarm_on_return=False,
        devices_file=dev_file
    )
    dev = mgr.add_trusted_device("Laptop", "192.168.1.30")
    mgr.current_state = PresenceManager.STATE_ARMED_AWAY
    
    with patch.object(mgr, "check_device_presence", return_value=PresenceManager.PRESENCE_PRESENT):
        mgr.evaluate_state_machine()
        # Ne doit PAS désarmer automatiquement : passe en RETURN_PENDING
        assert mgr.current_state == PresenceManager.STATE_RETURN_PENDING
        mock_alarm.disarm.assert_not_called()
        
    # Dérogation manuelle prioritaire
    ok = mgr.manual_override(PresenceManager.STATE_MANUAL, "Opérateur présent")
    assert ok is True
    assert mgr.current_state == PresenceManager.STATE_MANUAL
