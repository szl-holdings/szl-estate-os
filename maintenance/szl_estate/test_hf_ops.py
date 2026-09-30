from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from szl_estate.hf_ops import insert_note, update_card, rename_model, verify_move, recognize_successor, digest, LEGACY_NOTE, OLD_ID, NEW_ID, inventory


def hub():
    obj = Mock()
    obj.info.return_value = SimpleNamespace(sha="a" * 40, id=OLD_ID)
    obj.card.return_value = "---\nlicense: mit\n---\n# Existing body\n"
    return obj


def test_note_preserves_frontmatter_and_existing_body():
    before = "---\r\nlicense: mit\r\ntags: [reference]\r\n---\r\n# Body\r\n"
    after = insert_note(before, "> Note", "> Note")
    assert after.startswith("---\r\nlicense: mit\r\ntags: [reference]\r\n---\r\n")
    assert after.endswith("# Body\r\n")
    assert insert_note(after, "> Note", "> Note") == after


def test_bad_frontmatter_is_not_written():
    obj = hub()
    obj.card.return_value = "---\nlicense: mit\n"
    assert update_card(obj, OLD_ID, "Note", "Note", True)["status"] == "BLOCKED"
    obj.upload.assert_not_called()


def test_parent_revision_drift_prevents_write():
    obj = hub()
    obj.info.side_effect = [SimpleNamespace(sha="a"*40), SimpleNamespace(sha="b"*40)]
    assert update_card(obj, OLD_ID, "Note", "Note", True)["status"] == "BLOCKED"
    obj.upload.assert_not_called()


def test_timeout_requires_readback_and_never_retries_mutation():
    obj = hub()
    before = obj.card.return_value
    obj.card.side_effect = [before, insert_note(before, "Note", "Note")]
    obj.upload.side_effect = TimeoutError()
    assert update_card(obj, OLD_ID, "Note", "Note", True)["status"] == "VERIFIED_APPLIED"
    obj.upload.assert_called_once()


def test_wrong_readback_cannot_pass():
    obj = hub()
    assert update_card(obj, OLD_ID, "Note", "Note", True)["status"] == "READBACK_FAILED"


def test_matching_existing_card_is_idempotent():
    obj = hub()
    obj.card.return_value = "Note\n\nExisting body"
    assert update_card(obj, OLD_ID, "Note", "Note", True)["status"] == "VERIFIED_NO_CHANGE"
    obj.upload.assert_not_called()


def test_rename_requires_resolved_current_consumers():
    obj = hub()
    missing = RuntimeError()
    missing.response = SimpleNamespace(status_code=404)
    obj.info.side_effect = [SimpleNamespace(sha="a"*40, id=OLD_ID), missing]
    assert rename_model(obj, True)["status"] == "BLOCKED"
    obj.api.move_repo.assert_not_called()


def test_rename_never_overwrites_existing_destination():
    obj = hub()
    obj.info.side_effect = [SimpleNamespace(sha="a"*40, id=OLD_ID), SimpleNamespace(sha="b"*40, id=NEW_ID)]
    assert rename_model(obj, True)["status"] == "BLOCKED"
    obj.api.move_repo.assert_not_called()


def test_inventory_failure_does_not_become_complete_zero():
    obj = hub()
    obj.api.list_models.side_effect = TimeoutError()
    obj.api.list_datasets.return_value = []
    obj.api.list_spaces.return_value = []
    result = inventory(obj)
    assert result["complete"] is False
    assert result["counts"]["model"] is None
    assert result["failures"][0]["target"] == "model"


@pytest.mark.parametrize("content", ["> **Scope note:** Clinically validated", "```markdown\n> Correct note\n```"])
def test_marker_or_note_in_code_is_not_success(content):
    obj = hub()
    obj.card.return_value = content
    note, marker = ("> Correct note", "Correct note") if "```" in content else ("> **Scope note:** Synthetic", "**Scope note:**")
    assert update_card(obj, OLD_ID, note, marker, True)["status"] == "BLOCKED"
    obj.upload.assert_not_called()


@pytest.mark.parametrize("write_error", [None, TimeoutError()])
def test_card_readback_failure_keeps_unknown_write_state(write_error):
    obj = hub()
    obj.info.side_effect = [SimpleNamespace(sha="a"*40), SimpleNamespace(sha="a"*40), TimeoutError()]
    obj.upload.side_effect = write_error
    assert update_card(obj, OLD_ID, "Note", "Note", True)["status"] == "UNKNOWN_AFTER_ATTEMPT"
    obj.upload.assert_called_once()


def test_rename_readback_failure_keeps_unknown_write_state():
    from datetime import datetime, timezone
    obj = hub()
    missing = RuntimeError()
    missing.response = SimpleNamespace(status_code=404)
    obj.info.side_effect = [SimpleNamespace(sha="a"*40, id=OLD_ID), missing,
                            SimpleNamespace(sha="a"*40), TimeoutError()]
    migration = {"from_id": OLD_ID, "to_id": NEW_ID, "source_revision": "a"*40,
                 "unresolved_consumers": [], "canonical_publisher_ready": True,
                 "checked_at": datetime.now(timezone.utc).isoformat()}
    assert rename_model(obj, True, migration)["status"] == "UNKNOWN_AFTER_ATTEMPT"
    obj.api.move_repo.assert_called_once()


def test_identical_source_and_destination_do_not_prove_move():
    obj = hub()
    obj.info.side_effect = [SimpleNamespace(sha="a"*40, id=NEW_ID), SimpleNamespace(sha="a"*40, id=OLD_ID)]
    assert verify_move(obj, "a"*40) is None


def test_destination_alias_is_not_canonical_move():
    obj = hub()
    obj.info.return_value = SimpleNamespace(sha="a"*40, id=OLD_ID)
    assert verify_move(obj, "a"*40) is None


def test_canonical_move_with_old_redirect_is_verified():
    obj = hub()
    obj.info.return_value = SimpleNamespace(sha="a"*40, id=NEW_ID)
    assert verify_move(obj, "a"*40).id == NEW_ID


def test_successor_is_distinct_from_rename_and_never_deletes_or_moves():
    obj = hub()
    legacy = '---\nlicense: apache-2.0\n---\n\n' + LEGACY_NOTE + '\n\n# Historical model\n'
    canonical = '---\nlicense: apache-2.0\n---\n# System Health\n'
    obj.card.side_effect = [legacy, canonical]
    migration = {"from_id": OLD_ID, "to_id": NEW_ID, "source_revision": "a"*40,
                 "destination_revision": "b"*40, "canonical_publisher_ready": True,
                 "publisher_commit": "c"*40, "legacy_card_sha256": digest(legacy),
                 "canonical_card_sha256": digest(canonical)}
    result = recognize_successor(obj, SimpleNamespace(id=OLD_ID,sha="a"*40), SimpleNamespace(id=NEW_ID,sha="b"*40), migration)
    assert result['status'] == 'VERIFIED_SUCCESSOR'
    assert result['literal_repository_move'] is False
    obj.api.move_repo.assert_not_called()
    obj.upload.assert_not_called()


def test_successor_revision_change_blocks_reviewed_policy():
    obj = hub()
    result = recognize_successor(obj, SimpleNamespace(id=OLD_ID,sha="a"*40), SimpleNamespace(id=NEW_ID,sha="b"*40), {})
    assert result['status'] == 'BLOCKED'
    obj.card.assert_not_called()


def test_exact_replacement_preserves_other_card_content():
    obj = hub()
    old = '---\nlicense: mit\n---\n\n> Misleading note\n\n# Body\n'
    new = old.replace('> Misleading note\n\n', '')
    obj.card.side_effect = [old, new]
    assert update_card(obj, NEW_ID, '', '', True, replacement_from='> Misleading note\n\n')['status'] == 'VERIFIED_APPLIED'
    assert obj.upload.call_args.args[2] == new


@pytest.mark.parametrize('content', [
    '````\n```\n> Correct note\n````',
    '    > Correct note',
    '<!--\n> Correct note\n-->',
    '---\ndescription: |\n  > Correct note\n---\n# Body',
])
def test_examples_and_metadata_are_not_an_active_note(content):
    obj = hub()
    obj.card.return_value = content
    assert update_card(obj, OLD_ID, '> Correct note', 'Correct note', True)['status'] == 'BLOCKED'
    obj.upload.assert_not_called()


def test_dataset_card_targets_dataset_namespace():
    from szl_estate.hf_ops import Hub
    api = Mock()
    dataset_hub = Hub(api=api, repo_type='dataset')
    dataset_hub.info('SZLHOLDINGS/example')
    api.dataset_info.assert_called_once()
    api.model_info.assert_not_called()
    dataset_hub.upload('SZLHOLDINGS/example', 'a'*40, '# Dataset\n')
    assert api.upload_file.call_args.kwargs['repo_type'] == 'dataset'
    assert api.upload_file.call_args.kwargs['parent_commit'] == 'a'*40
    assert api.upload_file.call_args.kwargs['path_in_repo'] == 'README.md'
