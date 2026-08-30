from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from gawsl.parser import (
    WorkflowDocument,
    extract_action_ref,
    is_full_commit_sha,
    permission_has_write,
)


class ParserTests(unittest.TestCase):
    def test_on_key_is_not_boolean(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "w.yml"
            path.write_text("on: push\njobs: {}\n", encoding="utf-8")
            doc = WorkflowDocument.load(path)
            self.assertEqual({"push"}, doc.triggers())

    def test_trigger_list(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "w.yml"
            path.write_text("on: [push, pull_request]\njobs: {}\n", encoding="utf-8")
            doc = WorkflowDocument.load(path)
            self.assertEqual({"push", "pull_request"}, doc.triggers())

    def test_trigger_mapping(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "w.yml"
            path.write_text("on:\n  pull_request:\n    types: [opened]\njobs: {}\n", encoding="utf-8")
            doc = WorkflowDocument.load(path)
            self.assertEqual({"pull_request"}, doc.triggers())

    def test_full_sha(self) -> None:
        self.assertTrue(is_full_commit_sha("a" * 40))

    def test_tag_is_not_full_sha(self) -> None:
        self.assertFalse(is_full_commit_sha("v4"))

    def test_local_action_has_no_remote_ref(self) -> None:
        action, ref = extract_action_ref("./.github/actions/local")
        self.assertEqual("./.github/actions/local", action)
        self.assertIsNone(ref)

    def test_write_all_permission(self) -> None:
        self.assertTrue(permission_has_write("write-all"))

    def test_explicit_write_scope(self) -> None:
        self.assertTrue(permission_has_write({"contents": "write"}))

    def test_read_permissions_not_write(self) -> None:
        self.assertFalse(permission_has_write({"contents": "read"}))
