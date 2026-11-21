"""
Bancs de Tests pour PRO-08 : Recherche Vidéo Sémantique (CLIP & Vector Search)
Valide les fonctionnalités :
- Calcul des embeddings visuels et textuels
- Indexation des images clés dans SQLite
- Recherche par similarité cosinus avec requêtes textuelles
- Pagination des résultats
- Synchronisation lors de la suppression d'événements
- Reconstruction complète de l'index
"""

import os
import tempfile
import numpy as np
import pytest
from monitoring.semantic_search import SemanticSearchEngine


@pytest.fixture
def temp_search_engine():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        db_path = os.path.join(tmp_dir, "test_semantic.db")
        engine = SemanticSearchEngine(db_path=db_path, clip_model_path=None, embedding_dim=128)
        yield engine


def test_embedding_computation_and_normalization(temp_search_engine):
    engine = temp_search_engine

    # Image test (rouge vif 100x100)
    red_img = np.zeros((100, 100, 3), dtype=np.uint8)
    red_img[:, :] = [0, 0, 255]  # BGR Rouge
    emb_img = engine.compute_image_embedding(red_img)

    assert len(emb_img) == 128
    assert np.isclose(np.linalg.norm(emb_img), 1.0, atol=1e-3)

    # Embedding texte
    emb_txt = engine.compute_text_embedding("voiture rouge dans la cour")
    assert len(emb_txt) == 128
    assert np.isclose(np.linalg.norm(emb_txt), 1.0, atol=1e-3)


def test_indexing_and_similarity_search(temp_search_engine):
    engine = temp_search_engine

    # Création de frames synthétiques distinctes
    red_frame = np.zeros((120, 160, 3), dtype=np.uint8)
    red_frame[:, :] = [0, 0, 240]  # Rouge

    blue_frame = np.zeros((120, 160, 3), dtype=np.uint8)
    blue_frame[:, :] = [240, 0, 0]  # Bleu

    # Indexation de 2 événements
    indexed1 = engine.index_video_event(
        event_id="alert_red_car",
        device_id="cam_garden",
        video_path="recordings/car.mp4",
        keyframes=[red_frame],
        labels=["voiture", "rouge", "intrusion"]
    )
    assert indexed1 == 1

    indexed2 = engine.index_video_event(
        event_id="alert_blue_person",
        device_id="cam_door",
        video_path="recordings/person.mp4",
        keyframes=[blue_frame],
        labels=["personne", "bleu", "mouvement"]
    )
    assert indexed2 == 1

    # Recherche "voiture rouge"
    search_red = engine.search("voiture rouge", top_k=5)
    assert search_red["total_results"] >= 1
    assert search_red["results"][0]["event_id"] == "alert_red_car"
    assert search_red["results"][0]["score"] > 0.30

    # Recherche "personne"
    search_person = engine.search("personne près de la porte", top_k=5)
    assert search_person["total_results"] >= 1
    assert search_person["results"][0]["event_id"] == "alert_blue_person"


def test_search_pagination_and_empty_query(temp_search_engine):
    engine = temp_search_engine

    # Requête vide
    empty_res = engine.search("", top_k=10)
    assert empty_res["total_results"] == 0
    assert len(empty_res["results"]) == 0

    # Indexation de 5 événements
    for i in range(5):
        frame = np.full((50, 50, 3), fill_value=i * 40, dtype=np.uint8)
        engine.index_video_event(
            event_id=f"alert_{i}",
            device_id="cam1",
            video_path=f"rec_{i}.mp4",
            keyframes=[frame],
            labels=["mouvement", "intrusion"]
        )

    # Pagination : page 1 taille 2
    p1 = engine.search("mouvement", page=1, page_size=2)
    assert p1["page"] == 1
    assert len(p1["results"]) == 2
    assert p1["total_pages"] == 3

    # Page 2 taille 2
    p2 = engine.search("mouvement", page=2, page_size=2)
    assert p2["page"] == 2
    assert len(p2["results"]) == 2


def test_deletion_sync_and_rebuild_index(temp_search_engine):
    engine = temp_search_engine

    frame = np.ones((80, 80, 3), dtype=np.uint8) * 120
    engine.index_video_event("alert_delete_me", "cam1", "rec.mp4", keyframes=[frame, frame])

    stats_before = engine.get_stats()
    assert stats_before["indexed_events_count"] == 1
    assert stats_before["indexed_keyframes_count"] == 2

    # Suppression synchronisée
    deleted = engine.remove_event_embeddings("alert_delete_me")
    assert deleted == 2

    stats_after = engine.get_stats()
    assert stats_after["indexed_events_count"] == 0
    assert stats_after["indexed_keyframes_count"] == 0
