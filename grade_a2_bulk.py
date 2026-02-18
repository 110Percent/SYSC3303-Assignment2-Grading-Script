#!/usr/bin/env python3
"""
Bulk evaluator for SYSC3303 A2 Brightspace-style export folders.

Expected folder structure:
  <bulk_root>/
    <submission-id> - <student name> <student number>- <date>/
      <anything>.zip
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import html
import io
import pathlib
import re
import shutil
import sys
import zipfile
from dataclasses import dataclass

import grade_a2
FOLDER_RE = re.compile(r"^(?P<submission_id>\d+-\d+)\s*-\s*(?P<student>.+)$")


@dataclass
class SubmissionResult:
    folder_name: str
    submission_id: str
    student_label: str
    zip_name: str
    status: str
    return_code: int
    passed_checks: int | None
    total_checks: int | None
    started_at: str
    finished_at: str
    output: str
    sections: grade_a2.SectionResults | None = None
    extracted_dir: str | None = None
    notes: str = ""


def discover_submission_folders(bulk_root: pathlib.Path) -> list[pathlib.Path]:
    candidates = []
    for child in sorted(p for p in bulk_root.iterdir() if p.is_dir()):
        if FOLDER_RE.match(child.name):
            candidates.append(child)
    return candidates


def find_zip_file(submission_folder: pathlib.Path) -> tuple[pathlib.Path | None, str]:
    zips = sorted(p for p in submission_folder.glob("*.zip") if p.is_file())
    if not zips:
        return None, "No .zip file found in submission folder."
    if len(zips) > 1:
        return zips[0], f"Multiple zip files found; used '{zips[0].name}'."
    return zips[0], ""


def safe_extract_zip(zip_path: pathlib.Path, out_dir: pathlib.Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            target = (out_dir / info.filename).resolve()
            if not str(target).startswith(str(out_dir.resolve())):
                raise RuntimeError(f"Unsafe zip entry detected: {info.filename}")
        zf.extractall(out_dir)


def _collect_artifact_paths(
    extracted_dir: str | None,
) -> tuple[list[pathlib.Path], list[pathlib.Path]]:
    if not extracted_dir:
        return [], []
    root = pathlib.Path(extracted_dir)
    if not root.exists() or not root.is_dir():
        return [], []

    diagrams = sorted(
        p
        for p in root.rglob("*")
        if p.is_file()
        and p.suffix.lower() in grade_a2.DIAGRAM_EXTS
        and "__MACOSX" not in p.parts
    )
    java_files = [
        p for p in root.rglob("*.java") if p.is_file() and "__MACOSX" not in p.parts
    ]

    class_paths: dict[str, list[pathlib.Path]] = {
        "Client": [],
        "IntermediateHost": [],
        "Host": [],
        "Server": [],
    }
    for p in java_files:
        class_name = grade_a2.JavaFileStats(p).class_name
        if class_name in class_paths:
            class_paths[class_name].append(p)

    class_files: list[pathlib.Path] = []
    seen: set[pathlib.Path] = set()
    for class_name in ("Client", "IntermediateHost", "Host", "Server"):
        for p in sorted(class_paths[class_name]):
            if p not in seen:
                seen.add(p)
                class_files.append(p)

    return diagrams, class_files


def render_report(
    report_path: pathlib.Path,
    bulk_root: pathlib.Path,
    completed: int,
    total: int,
    results: list[SubmissionResult],
) -> None:
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cards = []
    for r in results:
        passed = r.passed_checks or 0
        summary = (
            f"{passed} checks passed (of {r.total_checks})"
            if r.total_checks is not None
            else f"{passed} checks passed"
        )
        if r.total_checks in (None, 0):
            chip_class = "summary-chip-blue"
        elif passed >= r.total_checks:
            chip_class = "summary-chip-blue"
        else:
            pass_ratio = passed / r.total_checks
            if pass_ratio >= 0.8:
                chip_class = "summary-chip-green"
            elif pass_ratio >= 0.5:
                chip_class = "summary-chip-yellow"
            else:
                chip_class = "summary-chip-red"

        diagrams, class_files = _collect_artifact_paths(r.extracted_dir)
        checks_html = ""
        compilation_has_failures = False
        if r.sections:
            section_chunks = []
            for section_name, items in r.sections.items():
                section_passed = sum(1 for passed, _, _ in items if passed)
                section_total = len(items)
                if section_name.lower() in ["compilation", "e2e"]:
                    compilation_has_failures = any(not check_passed for check_passed, _, _ in items)
                row_items = []
                for passed, label, detail in items:
                    item_class = "check-pass" if passed else "check-fail"
                    detail_html = (
                        f'<div class="check-detail">{html.escape(detail)}</div>'
                        if detail
                        else ""
                    )
                    row_items.append(
                        f'<li class="{item_class}">'
                        f'<div class="check-label">{html.escape(label)}</div>'
                        f"{detail_html}"
                        "</li>"
                    )
    
                if section_name == "Diagrams" and diagrams:
                    for diagram in diagrams:
                        for i, row in enumerate(row_items):
                            if diagram.name in row:
                                filename = re.search(r'<div class="check-detail">([^<]+)</div>', row)
                                if filename is not None:
                                    row_items[i] = row.replace(filename.group(1), f'<a href="{html.escape(diagram.as_uri())}" target="_blank" rel="noopener noreferrer">{filename.group(1)}</a>')
                elif section_name == "Code Quality" and class_files:
                    for class_file in class_files:
                        for i, row in enumerate(row_items):
                            if class_file.name in row:
                                filename = re.search(r'<div class="check-detail">([^<]+)</div>', row)
                                if filename is not None:
                                    row_items[i] = row.replace(filename.group(1), f'<a href="{html.escape(class_file.as_uri())}" target="_blank" rel="noopener noreferrer">📄 {filename.group(1)}</a>')

                section_chunks.append(
                    '<div class="check-section">'
                    f"<h3>{html.escape(section_name)} "
                    f"<span>{section_passed}/{section_total}</span></h3>"
                    f"<ul>{''.join(row_items)}</ul>"
                    "</div>"
                )
            checks_html = "".join(section_chunks)
        elif r.output:
            checks_html = (
                "<details><summary>Raw Output</summary>"
                f"<pre>{html.escape(r.output)}</pre>"
                "</details>"
            )
        else:
            checks_html = '<div class="no-checks">No checks available.</div>'

        notes_html = (
            f'<div class="notes"><strong>Notes:</strong> {html.escape(r.notes)}</div>'
            if r.notes
            else ""
        )

        cards.append(
            '<details class="submission-card">'
            "<summary>"
            f"<strong>{html.escape(r.submission_id)} - {html.escape(r.student_label)}</strong>"
            '<span class="summary-right">'
            f'<span class="summary-warning{" visible" if compilation_has_failures else ""}" aria-hidden="true">⚠</span>'
            f'<span class="summary-chip {chip_class}">{html.escape(summary)}</span>'
            "</span>"
            "</summary>"
            '<div class="submission-content">'
            '<div class="meta-grid">'
            f"<div><strong>Zip:</strong> {html.escape(r.zip_name or 'n/a')}</div>"
            f"<div><strong>Started:</strong> {html.escape(r.started_at)}</div>"
            f"<div><strong>Finished:</strong> {html.escape(r.finished_at)}</div>"
            "</div>"
            f"{f'<div><strong>Folder:</strong> <a href=\"{html.escape(r.extracted_dir)}\" target=\"_blank\" rel=\"noopener noreferrer\">{html.escape(r.folder_name)}</a></div>' if r.extracted_dir else ''}"
            '<div class="checks-block">'
            "<h3>Checks</h3>"
            f"{checks_html}"
            "</div>"
            '<details><summary>Captured Output</summary>'
            f"<pre>{html.escape(r.output)}</pre>"
            "</details>"
            "</div>"
            "</details>"
        )

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>A2 Bulk Evaluation Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; color: #1a1a1a; }}
    .meta {{ margin-bottom: 12px; }}
    .submission-card {{ border: 1px solid #ddd; border-radius: 10px; margin: 20px 0; background: #fff; }}
    .submission-card > summary {{ cursor: pointer; list-style: none; padding: 16px 18px; display: flex; justify-content: space-between; gap: 12px; align-items: center; }}
    .submission-card > summary::-webkit-details-marker {{ display: none; }}
    .submission-content {{ padding: 0 18px 18px 18px; }}
    .summary-right {{ display: inline-flex; align-items: center; gap: 8px; }}
    .summary-warning {{ display: none; color: #9f1212; font-size: 14px; font-weight: 700; line-height: 1; }}
    .summary-warning.visible {{ display: inline-block; }}
    .summary-chip {{ border-radius: 999px; padding: 4px 10px; font-size: 13px; font-weight: 600; white-space: nowrap; }}
    .summary-chip-blue {{ background: #e0ebff; color: #1e3a8a; }}
    .summary-chip-green {{ background: #dcfce7; color: #166534; }}
    .summary-chip-yellow {{ background: #fef3c7; color: #92400e; }}
    .summary-chip-red {{ background: #fee2e2; color: #991b1b; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px 16px; margin: 10px 0 14px 0; }}
    .notes {{ margin-bottom: 14px; color: #444; }}
    .checks-block h3 {{ margin: 0 0 10px; }}
    .check-section {{ margin-bottom: 14px; }}
    .check-section h3 {{ margin: 0 0 6px; font-size: 15px; }}
    .check-section h3 span {{ font-weight: normal; color: #555; }}
    .check-section ul {{ margin: 0; padding-left: 18px; }}
    .check-section li {{ margin: 5px 0; }}
    .check-pass .check-label {{ color: #0a6f2a; }}
    .check-fail .check-label {{ color: #9f1212; font-weight: 600; }}
    .check-detail {{ color: #555; font-size: 13px; }}
    .section-artifacts {{ margin: 10px 0 0 0; }}
    .section-artifacts h4 {{ margin: 0 0 6px; font-size: 14px; }}
    .section-artifacts ul {{ margin: 0; padding-left: 18px; }}
    .section-artifacts li {{ margin: 4px 0; }}
    pre {{ white-space: pre-wrap; max-width: 100%; background: #fafafa; border: 1px solid #eee; padding: 8px; border-radius: 6px; }}
  </style>
</head>
<body>
  <h1>A2 Bulk Evaluation Report</h1>
  <div class="meta">Bulk root: <code>{html.escape(str(bulk_root))}</code></div>
  <div class="meta">Progress: <strong>{completed}/{total}</strong></div>
  <div class="meta">Last updated: {html.escape(now)}</div>
  {''.join(cards)}
</body>
</html>
"""
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(document, encoding="utf-8")


def evaluate_submission(
    extracted_root: pathlib.Path,
) -> tuple[int, str, int | None, int | None, grade_a2.SectionResults]:
    output_capture = io.StringIO()
    with contextlib.redirect_stdout(output_capture), contextlib.redirect_stderr(
        output_capture
    ):
        result = grade_a2.grade_submission(
            root=extracted_root,
            keep_logs=True,
            no_open_diagrams=True,
        )

    return (
        result.return_code,
        output_capture.getvalue(),
        result.passed_checks,
        result.total_checks,
        result.all_results,
    )


def sanitize_folder_name(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())
    return safe or "submission"


def main() -> int:
    ap = argparse.ArgumentParser(description="Bulk evaluate SYSC3303 A2 submissions.")
    ap.add_argument("--bulk-root", required=True, help="Folder containing submission folders.")
    ap.add_argument(
        "--report",
        default="bulk_evaluation_report.html",
        help="Output HTML report path.",
    )
    ap.add_argument(
        "--work-dir",
        default=".a2_bulk_work",
        help="Working directory for extracted zip contents.",
    )
    ap.add_argument(
        "--keep-extracted",
        action="store_true",
        help="Keep extracted submission folders after evaluation.",
    )
    ap.add_argument(
        "--python",
        default=sys.executable,
        help="Unused (kept for backward compatibility).",
    )
    args = ap.parse_args()

    bulk_root = pathlib.Path(args.bulk_root).resolve()
    report_path = pathlib.Path(args.report).resolve()
    work_dir = pathlib.Path(args.work_dir).resolve()
    if not bulk_root.exists() or not bulk_root.is_dir():
        raise RuntimeError(f"Bulk root does not exist or is not a directory: {bulk_root}")

    submissions = discover_submission_folders(bulk_root)
    results: list[SubmissionResult] = []

    print(f"Discovered {len(submissions)} candidate submission folder(s) in: {bulk_root}")
    render_report(report_path, bulk_root, 0, len(submissions), results)

    for idx, folder in enumerate(submissions, start=1):
        m = FOLDER_RE.match(folder.name)
        if not m:
            continue
        submission_id = m.group("submission_id")
        student_label = m.group("student")

        started = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        zip_path, zip_note = find_zip_file(folder)
        if zip_path is None:
            finished = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            results.append(
                SubmissionResult(
                    folder_name=folder.name,
                    submission_id=submission_id,
                    student_label=student_label,
                    zip_name="",
                    status="SKIPPED",
                    return_code=1,
                    passed_checks=None,
                    total_checks=None,
                    started_at=started,
                    finished_at=finished,
                    output="",
                    sections=None,
                    extracted_dir=None,
                    notes=zip_note,
                )
            )
            render_report(report_path, bulk_root, idx, len(submissions), results)
            print(f"[{idx}/{len(submissions)}] SKIPPED {folder.name}: {zip_note}")
            continue

        extract_dir = work_dir / f"{idx:03d}_{sanitize_folder_name(folder.name)}"
        if extract_dir.exists():
            shutil.rmtree(extract_dir, ignore_errors=True)

        status = "FAILED"
        return_code = 1
        output = ""
        passed_checks: int | None = None
        total_checks: int | None = None
        sections: grade_a2.SectionResults | None = None
        note = zip_note

        try:
            safe_extract_zip(zip_path, extract_dir)
            return_code, output, passed_checks, total_checks, sections = evaluate_submission(
                extract_dir
            )
            status = "FINISHED"
        except Exception as exc:
            output = f"{type(exc).__name__}: {exc}"
            status = "ERROR"
            return_code = 1

        finished = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        results.append(
            SubmissionResult(
                folder_name=folder.name,
                submission_id=submission_id,
                student_label=student_label,
                zip_name=zip_path.name,
                status=status,
                return_code=return_code,
                passed_checks=passed_checks,
                total_checks=total_checks,
                started_at=started,
                finished_at=finished,
                output=output,
                sections=sections,
                extracted_dir=str(extract_dir) if args.keep_extracted else None,
                notes=note,
            )
        )
        render_report(report_path, bulk_root, idx, len(submissions), results)
        print(f"[{idx}/{len(submissions)}] {status} {folder.name} -> {report_path}")

        if not args.keep_extracted:
            shutil.rmtree(extract_dir, ignore_errors=True)

    passed_count = sum(1 for r in results if r.status == "PASSED")
    print(f"Done. {passed_count}/{len(results)} submissions passed. Report: {report_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
