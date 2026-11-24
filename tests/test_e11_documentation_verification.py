"""Phase 11 and 12 — "authored and verified" as a claim that can be checked.

Phase 11 reports nine production documents as *authored and verified*, and PROGRESS.md
records the outcome of Phase 12 as though it were finished. Reading the documents is what
turned up the defects below, and they are the kind a reader cannot spot: a diagram with a
module that does not exist, links that only work on the author's Windows machine, table
counts that were true two migrations ago.

"Verified" is therefore defined here as five checks that a machine can make:

  1. every relative link resolves inside the repository;
  2. every repository path named in backticks exists;
  3. no document leaks a local filesystem path (the author's home directory);
  4. the table counts in the documents equal what the code defines;
  5. the module map in the architecture diagram names real modules.

The tests are deliberately about the documents, not about the code: the code has its own
suites, and the gap this closes is that nothing was checking the prose.
"""

from __future__ import annotations

import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: The Phase 11 deliverable: nine topics, one or more files each.
PHASE_11_DOCS = (
    "docs/architecture/SYSTEM_ARCHITECTURE.md",
    "docs/architecture/TASK_QUEUE.md",
    "docs/security/SECURITY_MODEL.md",
    "docs/security/SECURITY_IMPLEMENTATION.md",
    "docs/deployment/PRODUCTION_DEPLOYMENT.md",
    "docs/deployment/STAGING_DEPLOYMENT.md",
    "docs/operations/BACKUP_RESTORE.md",
    "docs/operations/DISASTER_RECOVERY.md",
    "docs/operations/INCIDENT_RESPONSE.md",
    "docs/operations/DEPLOYMENT.md",
    "docs/testing/TEST_STRATEGY.md",
    "docs/database/MIGRATION_GUIDE.md",
    "docs/database/POSTGRESQL_MIGRATION.md",
    "docs/ai/AI_RELIABILITY_AND_SECURITY.md",
    "docs/ci/CI_CD_AND_TESTING.md",
)


def _read(rel: str) -> str:
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


# ------------------------------------------------------------------- the documents exist


@pytest.mark.parametrize("rel", PHASE_11_DOCS)
def test_the_document_exists_and_is_not_a_stub(rel: str) -> None:
    path = os.path.join(REPO_ROOT, rel)
    assert os.path.exists(path), f"{rel} is claimed by Phase 11 and does not exist"
    body = _read(rel)
    assert len(body) > 1500, f"{rel} is too short to be a production document ({len(body)} chars)"
    assert body.lstrip().startswith("#"), f"{rel} does not start with a title"


# ------------------------------------------------------------------------- links resolve


@pytest.mark.parametrize("rel", PHASE_11_DOCS)
def test_every_relative_link_resolves(rel: str) -> None:
    """A link that points at a path outside the repo is dead for every reader but one.

    Measured before the fix: 22 links across three documents pointed at
    `file:///c:/Users/<author>/Documents/...`, which resolves only on the machine that
    wrote them - and publishes that machine's layout to everyone who reads the document.
    """
    body = _read(rel)
    broken = []
    for match in re.finditer(r"\]\((?!https?:|#|mailto:)([^)#]+)", body):
        target = match.group(1).strip()
        resolved = os.path.normpath(os.path.join(os.path.dirname(rel), target))
        if not os.path.exists(os.path.join(REPO_ROOT, resolved)):
            broken.append(target)
    assert not broken, f"{rel}: link(s) that resolve to nothing: {broken[:5]}"


@pytest.mark.parametrize("rel", PHASE_11_DOCS)
def test_no_document_leaks_a_local_filesystem_path(rel: str) -> None:
    """`file:///c:/Users/...` is both a broken link and a disclosure of the author's disk."""
    body = _read(rel)
    leaked = re.findall(r"file:///[A-Za-z]:/[^\s)\]]+", body)
    assert not leaked, f"{rel} contains an absolute local path: {leaked[:3]}"


@pytest.mark.parametrize("rel", PHASE_11_DOCS)
def test_every_repository_path_named_in_backticks_exists(rel: str) -> None:
    """A document that names a module can be checked against the module."""
    body = _read(rel)
    missing = []
    for match in re.finditer(
        r"`((?:app|core|tests|scripts|docs|migrations)/[\w./-]+\.(?:py|md|yml|yaml|json|env))`",
        body,
    ):
        named = match.group(1)
        if not os.path.exists(os.path.join(REPO_ROOT, named)):
            missing.append(named)
    assert not missing, f"{rel} names path(s) that do not exist: {sorted(set(missing))[:5]}"


# ------------------------------------------------------------------ the numbers are true


class TestTheDocumentedTableCountsMatchTheCode:
    """`15 tables` was true before migrations 0005-0007 and was never revisited."""

    @staticmethod
    def _models_table_count() -> int:
        from core.models import Base

        return len(Base.metadata.tables)

    @staticmethod
    def _migrated_table_count() -> int:
        import sys

        sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
        import migrate_sqlite_to_postgres as migration

        return len(migration.MIGRATION_TABLES)

    def test_the_architecture_document_states_the_model_count(self):
        count = self._models_table_count()
        body = _read("docs/architecture/SYSTEM_ARCHITECTURE.md")
        assert f"all {count} tables" in body, (
            f"the architecture document does not state the {count} tables models.py defines"
        )

    def test_the_migration_documents_state_the_migrated_count(self):
        """Every table count in the migration documents must be 17 or the explained 18.

        An `or` over two spellings is how the first version of this test passed while the
        document said 15 in three places: one surviving `17 tables` satisfied the assertion.
        Each number is checked where it appears instead, so a stale count cannot hide behind
        a correct one elsewhere.
        """
        count = self._migrated_table_count()
        for rel in ("docs/database/MIGRATION_GUIDE.md", "docs/database/POSTGRESQL_MIGRATION.md"):
            body = _read(rel)
            stated = re.findall(r"(\d+) tables", body)
            assert stated, f"{rel} states no table count at all"
            wrong = [number for number in stated if number not in (str(count), str(self._models_table_count()))]
            assert not wrong, (
                f"{rel} states {sorted(set(wrong))} tables; the migration tool copies {count} "
                f"and models.py defines {self._models_table_count()}"
            )

    def test_the_two_counts_are_explained_where_they_differ(self):
        """18 models, 17 migrated. A reader who counts will notice; say why."""
        models, migrated = self._models_table_count(), self._migrated_table_count()
        assert models != migrated, "if the counts converged this explanation is obsolete"
        body = _read("docs/database/POSTGRESQL_MIGRATION.md")
        assert "page_login_namespace" in body, (
            "the documents state one count for models and another for the migration tool "
            "without naming the table that differs"
        )


class TestTheArchitectureDiagramNamesRealModules:
    """A diagram is a claim about the code. `core/repositories.py` was not in the code."""

    def test_the_repositories_layer_it_used_to_name_is_gone(self):
        body = _read("docs/architecture/SYSTEM_ARCHITECTURE.md")
        assert "core/repositories.py" not in body, (
            "the architecture diagram names core/repositories.py, which does not exist; "
            "data access goes through database.py and the *_service.py modules"
        )

    def test_the_diagram_names_the_actual_data_access_layer(self):
        body = _read("docs/architecture/SYSTEM_ARCHITECTURE.md")
        assert "database.py" in body
        assert "_service.py" in body

    def test_a_reader_can_find_every_module_the_diagram_names(self):
        """Whatever the diagram names must exist, so this stays true as the code moves."""
        body = _read("docs/architecture/SYSTEM_ARCHITECTURE.md")
        named = set(re.findall(r"`((?:core|app)/[\w./-]+\.py|[\w-]+_service\.py|main\.py|worker\.py|agent\.py|database\.py)`", body))
        assert named, "the diagram names no modules at all"
        missing = [name for name in sorted(named) if not os.path.exists(os.path.join(REPO_ROOT, name))]
        assert not missing, f"the architecture diagram names modules that do not exist: {missing}"


# -------------------------------------------------------------- Phase 10's scenario count


class TestPhase10ActuallyRunsItsTwentyScenarios:
    """Phase 10 is recorded COMPLETED on 20 scenarios with no gate behind the claim."""

    def test_the_file_holds_twenty_scenarios(self):
        body = _read("tests/test_failure_scenarios.py")
        assert len(re.findall(r"^def test_", body, flags=re.MULTILINE)) == 20

    def test_the_ci_step_asserts_twenty_passed_rather_than_running_pytest_bare(self):
        """Bare `pytest ...` reports failures but never noticed a SKIP.

        That is how the Phase 22/23/24 step spent months passing while 23 cases skipped:
        a skip is not a failure, so the exit status was clean. The same shape was here.
        """
        body = _read(".github/workflows/ci.yml")
        step = body[body.index("Run Failure Scenarios Suite") :]
        step = step[: step.index("Build Production Docker Image")]
        assert "check_pytest_log.py" in step, (
            "the failure-scenario step runs pytest with no log guard, so a skipped scenario "
            "reports exactly what a passing one does"
        )
        assert "--min-passed 20" in step, "the step does not assert that all twenty ran"
