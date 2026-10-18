"""Exercise release publishing against a local fake GitHub CLI."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_ci import BASH, ROOT


# Keep remote files separate so tests can verify publication and preservation.
FAKE_GH = r'''
gh() {
    printf '%s\0' "$@" >> gh_calls
    printf '\n' >> gh_calls
    local action=$2
    [[ $1 != api ]] || action=lookup
    if [[ $action == "$FAIL_STAGE" ]]; then
        echo "Simulated $action failure" >&2
        return 1
    fi
    case "$action" in
        lookup)
            if [[ -f remote_release ]]; then echo 123; fi
            ;;
        view)
            for file in remote/*; do
                if [[ -f $file ]]; then printf '%s\n' "${file##*/}"; fi
            done
            ;;
        create)
            [[ ! -f remote_release ]] || return 1
            printf '%s\n' "$3" > remote_release
            shift 3
            while (( $# > 0 )); do
                case "$1" in
                    --verify-tag|--generate-notes|--prerelease) shift ;;
                    --title) shift 2 ;;
                    *) cp "$1" "remote/${1##*/}"; shift ;;
                esac
            done
            ;;
        download)
            shift 3
            [[ $# == 4 && $1 == --pattern && $3 == --dir ]] || return 2
            cp "remote/$2" "$4/$2"
            ;;
        upload)
            [[ -f remote_release ]] || return 1
            shift 3
            for file in "$@"; do
                [[ ! -e remote/${file##*/} ]] || return 1
                cp "$file" "remote/${file##*/}"
            done
            ;;
        *) echo "Unexpected gh command" >&2; return 2 ;;
    esac
}
source scripts/ci/publish_release.sh 'release files'
'''


@unittest.skipUnless(BASH, 'Requires Bash')
class ReleasePublishingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'scripts/ci').mkdir(parents=True)
        shutil.copyfile(ROOT / 'scripts/ci/publish_release.sh', self.root / 'scripts/ci/publish_release.sh')
        self.assets = self.root / 'release files'
        self.remote = self.root / 'remote'
        self.release = self.root / 'remote_release'
        self.assets.mkdir()
        self.remote.mkdir()
        for name in ('hypc-static-linux', 'hypc-macos', 'hypc-windows.exe', 'hypjson.js', 'SHA256SUMS'):
            (self.assets / name).write_bytes(b'build content: ' + name.encode())

    def publish(self, tag='v0.2.0', failure=''):
        # Export only test settings; gh is a shell function and never contacts GitHub.
        return subprocess.run(
            [BASH, '-c', 'export GH_REPO=example/hyperion RELEASE_TAG="$1" FAIL_STAGE="$2"\n' + FAKE_GH,
             'release-test', tag, failure],
            cwd=self.root, capture_output=True, text=True,
        )

    def calls(self, command):
        path = self.root / 'gh_calls'
        calls = [line.rstrip('\0').split('\0') for line in path.read_text().splitlines()] if path.exists() else []
        return [call for call in calls if call[:2] == ['release', command]]

    def assert_assets_published(self):
        for asset in self.assets.iterdir():
            self.assertEqual((self.remote / asset.name).read_bytes(), asset.read_bytes())

    def check_creation(self, tag, prerelease):
        result = self.publish(tag)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.release.read_text().strip(), tag)
        self.assert_assets_published()
        create, = self.calls('create')
        self.assertIn('--verify-tag', create)
        self.assertIn('--generate-notes', create)
        self.assertEqual('--prerelease' in create, prerelease)

    def test_create_stable_release(self):
        self.check_creation('v0.2.0', False)

    def test_create_prerelease(self):
        self.check_creation('v0.2.0-rc.1', True)

    def test_existing_release_gets_assets_and_preserves_metadata(self):
        self.release.write_text('user title, notes and release status')
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_assets_published()
        self.assertEqual(self.release.read_text(), 'user title, notes and release status')
        self.assertFalse(self.calls('create'))
        self.assertEqual(len(self.calls('upload')), 1)

    def test_partial_upload_and_completed_rerun(self):
        self.release.touch()
        shutil.copyfile(self.assets / 'hypc-static-linux', self.remote / 'hypc-static-linux')
        (self.remote / 'user-attachment.txt').write_text('keep this attachment')
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_assets_published()
        upload, = self.calls('upload')
        self.assertNotIn('release files/hypc-static-linux', upload)
        self.assertEqual(len(upload[3:]), 4)
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.calls('upload')), 1, 'Completed reruns must not upload again')
        self.assertEqual((self.remote / 'user-attachment.txt').read_text(), 'keep this attachment')

    def test_conflicting_asset_blocks_all_uploads(self):
        self.release.touch()
        (self.remote / 'SHA256SUMS').write_text('different build')
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('refusing to overwrite', result.stderr)
        self.assertFalse(self.calls('upload'))
        self.assertFalse(self.calls('create'))
        self.assertEqual(list(self.remote.iterdir()), [self.remote / 'SHA256SUMS'])
        self.assertEqual((self.remote / 'SHA256SUMS').read_text(), 'different build')

    def test_cli_failures_are_not_treated_as_success_or_absent_releases(self):
        for stage in ('lookup', 'view', 'download', 'create', 'upload'):
            with self.subTest(stage=stage):
                self.release.unlink(missing_ok=True)
                (self.root / 'gh_calls').write_text('')
                for asset in self.remote.iterdir():
                    asset.unlink()
                if stage != 'create':
                    self.release.touch()
                if stage == 'download':
                    shutil.copyfile(self.assets / 'hypc-static-linux', self.remote / 'hypc-static-linux')
                before = {asset.name: asset.read_bytes() for asset in self.remote.iterdir()}
                result = self.publish(failure=stage)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'Simulated {stage} failure', result.stderr)
                self.assertEqual({asset.name: asset.read_bytes() for asset in self.remote.iterdir()}, before)
                if stage in ('lookup', 'view', 'download'):
                    self.assertFalse(self.calls('create'))
                    self.assertFalse(self.calls('upload'))

    def test_invalid_tag_or_missing_asset_fails_before_api_calls(self):
        result = self.publish(tag='v0.2.0"invalid')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Invalid release tag', result.stderr)
        (self.assets / 'hypjson.js').unlink()
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing or empty release asset', result.stderr)
        self.assertFalse((self.root / 'gh_calls').exists())
