import json
import logging
import tempfile
import multiprocessing
from tabulate import tabulate
from pathlib import Path
from semgrep import run_scan
from semgrep.state import get_state
from semgrep.constants import OutputFormat
from semgrep.output import OutputHandler, OutputSettings
from semgrep.target_manager import write_pipes_to_disk


class Scanner:
    def __init__(self):
        self.findings = {
            'matches': {},
            'errors': [],
        }
        self.scan_rules = str(Path(__file__).parents[0] / 'rules')


    @staticmethod
    def get_scan_files(paths):
        if not isinstance(paths, list):
            raise InvalidPathError('Path should be a list')
        all_files = set()
        for path in paths:
            pobj = Path(path)
            if pobj.is_dir():
                for pfile in pobj.rglob('*'):
                    all_files.add(pfile)
            else:
                all_files.add(pobj)
        return all_files


    def format_output(self, results):
        errs = self.findings.get('errors')
        if errs:
            self.findings['errors'] = errs
        smatches = self.findings['matches']
        for find in results['results']:
            file_details = {
                'file_path': find['path'],
                'match_position': (find['start']['col'], find['end']['col']),
                'match_lines': (find['start']['line'], find['end']['line']),
                'match_string': find['extra']['lines'],
            }
            rule_id = find['check_id'].split('.', 3)[-1]
            if rule_id in smatches:
                smatches[rule_id]['files'].append(file_details)
            else:
                metadata = find['extra']['metadata']
                metadata['description'] = find['extra']['message']
                metadata['severity'] = find['extra']['severity']
                smatches[rule_id] = {
                    'files': [file_details],
                    'metadata': metadata,
                }


    def scan(self, paths):

        with tempfile.TemporaryDirectory() as pipes_dir:

            targets = write_pipes_to_disk(paths, Path(pipes_dir))

            try:
                cpu_count = multiprocessing.cpu_count()
            except NotImplementedError:
                    cpu_count = 1

            state = get_state()
            state.terminal.configure(
                verbose=False,
                debug=False,
                quiet=True,
                force_color=False,
            )
            logging.getLogger('semgrep').propagate = False
            output_settings = OutputSettings(
                output_format=OutputFormat.JSON,
                output_destination=None,
                output_per_finding_max_lines_limit=None,
                output_per_line_max_chars_limit=None,
                error_on_findings=False,
                verbose_errors=False,
                strict=False,
                timeout_threshold=3,
            )
            output_handler = OutputHandler(output_settings)
            (
                filtered_matches_by_rule,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,) = run_scan.run_scan(
                output_handler=output_handler,
                target=targets,
                jobs=cpu_count,
                pattern=None,
                lang=None,
                configs=[self.scan_rules],
                timeout=5,
                timeout_threshold=3,
                no_git_ignore=True,
            )
            output_handler.rule_matches = [
                m for ms in filtered_matches_by_rule.values() for m in ms
            ]
            outputs = tuple(output_handler._build_outputs())
            self.format_output(json.loads(outputs[0][1]))
            for rule_id in self.findings['matches']:
                for finding in self.findings['matches'][rule_id]['files']:
                    finding.pop('metavars', None)
            return self.findings['matches']
